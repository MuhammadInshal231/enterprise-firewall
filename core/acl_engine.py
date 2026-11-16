import datetime
import ipaddress
import json
import os
import sqlite3
import threading

class DatabaseManager:
    def __init__(self, db_path=None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.normpath(os.path.join(base_dir, "firewall.db"))
        else:
            self.db_path = os.path.normpath(os.path.abspath(db_path))
        self.lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS rules ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "priority INTEGER UNIQUE NOT NULL, "
                    "action TEXT CHECK(action IN ('ALLOW', 'DROP', 'REJECT')) NOT NULL, "
                    "direction TEXT CHECK(direction IN ('INBOUND', 'OUTBOUND')) NOT NULL, "
                    "protocol TEXT CHECK(protocol IN ('TCP', 'UDP', 'ICMP', 'ANY')) NOT NULL, "
                    "source_cidr TEXT NOT NULL, "
                    "dest_cidr TEXT NOT NULL, "
                    "dest_port INTEGER, "
                    "interface TEXT DEFAULT 'ANY', "
                    "is_enabled INTEGER DEFAULT 1"
                    ");"
                )
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS security_events ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, "
                    "source_ip TEXT NOT NULL, "
                    "dest_ip TEXT NOT NULL, "
                    "dest_port INTEGER, "
                    "threat_type TEXT NOT NULL, "
                    "action_taken TEXT NOT NULL, "
                    "payload_sample TEXT"
                    ");"
                )
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS auto_bans ("
                    "ip_address TEXT PRIMARY KEY, "
                    "banned_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
                    "expires_at DATETIME NOT NULL, "
                    "reason TEXT NOT NULL"
                    ");"
                )
                conn.commit()
                self._seed_default_rules(cursor, conn)
            finally:
                conn.close()

    def _seed_default_rules(self, cursor, conn):
        cursor.execute("SELECT COUNT(*) AS count FROM rules;")
        if cursor.fetchone()["count"] == 0:
            default_rules = [
                (100, "ALLOW", "INBOUND", "TCP", "0.0.0.0/0", "0.0.0.0/0", 22, "ANY", 1),
                (200, "ALLOW", "INBOUND", "TCP", "0.0.0.0/0", "0.0.0.0/0", 8081, "ANY", 1),
                (250, "ALLOW", "INBOUND", "ANY", "127.0.0.0/8", "0.0.0.0/0", None, "ANY", 1),
                (300, "ALLOW", "INBOUND", "ANY", "192.168.1.0/24", "0.0.0.0/0", None, "ANY", 1),
                (400, "ALLOW", "INBOUND", "TCP", "0.0.0.0/0", "0.0.0.0/0", 80, "ANY", 1),
                (500, "ALLOW", "INBOUND", "TCP", "0.0.0.0/0", "0.0.0.0/0", 443, "ANY", 1),
                (999, "DROP", "INBOUND", "ANY", "0.0.0.0/0", "0.0.0.0/0", None, "ANY", 1)
            ]
            cursor.executemany(
                "INSERT INTO rules (priority, action, direction, protocol, source_cidr, dest_cidr, dest_port, interface, is_enabled) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", default_rules
            )
            conn.commit()

    def get_rules(self):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM rules ORDER BY priority ASC;")
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def add_rule(self, priority, action, direction, protocol, source_cidr, dest_cidr, dest_port=None, interface="ANY", is_enabled=1):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO rules (priority, action, direction, protocol, source_cidr, dest_cidr, dest_port, interface, is_enabled) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
                    (priority, action, direction, protocol, source_cidr, dest_cidr, dest_port, interface, is_enabled)
                )
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def delete_rule(self, rule_id):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM rules WHERE id = ?;", (rule_id,))
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def log_security_event(self, source_ip, dest_ip, dest_port, threat_type, action_taken, payload_sample=None):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO security_events (source_ip, dest_ip, dest_port, threat_type, action_taken, payload_sample) "
                    "VALUES (?, ?, ?, ?, ?, ?);",
                    (source_ip, dest_ip, dest_port, threat_type, action_taken, (payload_sample or "")[:250])
                )
                conn.commit()
            finally:
                conn.close()

    def get_recent_events(self, limit=50):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?;", (limit,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def get_all_events(self):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM security_events ORDER BY id DESC;")
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def is_ip_banned(self, ip_address):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT expires_at, reason FROM auto_bans WHERE ip_address = ?;", (ip_address,))
                row = cursor.fetchone()
                if not row:
                    return False, None, None
                expires_str = row["expires_at"]
                try:
                    exp_dt = datetime.datetime.fromisoformat(expires_str)
                    if exp_dt > datetime.datetime.now():
                        return True, row["reason"], exp_dt.timestamp()
                    else:
                        cursor.execute("DELETE FROM auto_bans WHERE ip_address = ?;", (ip_address,))
                        conn.commit()
                        return False, None, None
                except Exception:
                    return False, None, None
            finally:
                conn.close()

    def add_auto_ban(self, ip_address, duration=300, reason="IDS Threshold Exceeded"):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                exp_dt = datetime.datetime.now() + datetime.timedelta(seconds=duration)
                cursor.execute(
                    "INSERT OR REPLACE INTO auto_bans (ip_address, expires_at, reason) VALUES (?, ?, ?);",
                    (ip_address, exp_dt.isoformat(), reason)
                )
                conn.commit()
            finally:
                conn.close()

    def remove_auto_ban(self, ip_address):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM auto_bans WHERE ip_address = ?;", (ip_address,))
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def get_active_bans(self):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                now_str = datetime.datetime.now().isoformat()
                cursor.execute("SELECT * FROM auto_bans WHERE expires_at > ?;", (now_str,))
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

class AclEngine:
    SAFE_PORTS = {22, 8081}

    def __init__(self, database_manager=None, rules_file_path=None):
        self.db = database_manager
        if rules_file_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.rules_file_path = os.path.normpath(os.path.join(base_dir, "config", "rules.json"))
        else:
            self.rules_file_path = os.path.normpath(os.path.abspath(rules_file_path))
        if not os.path.exists(self.rules_file_path) and os.path.exists(self.rules_file_path + ".example"):
            try:
                with open(self.rules_file_path + ".example", "r", encoding="utf-8") as rf:
                    ex_data = rf.read()
                os.makedirs(os.path.dirname(self.rules_file_path), exist_ok=True)
                with open(self.rules_file_path, "w", encoding="utf-8") as wf:
                    wf.write(ex_data)
            except Exception:
                pass
        self.rules_cache = []
        self.lock = threading.Lock()
        self.reload_rules()

    def reload_rules(self):
        with self.lock:
            if self.db:
                self.rules_cache = self.db.get_rules()

    def validate_inputs(self, source_cidr, dest_cidr, dest_port=None):
        try:
            if source_cidr and source_cidr != "ANY":
                ipaddress.ip_network(source_cidr, strict=False)
            if dest_cidr and dest_cidr != "ANY":
                ipaddress.ip_network(dest_cidr, strict=False)
            if dest_port is not None and dest_port != "ANY":
                p = int(dest_port)
                if not (1 <= p <= 65535):
                    return False, "Port out of range (1-65535)"
        except ValueError as e:
            return False, f"Invalid CIDR or IP: {str(e)}"
        return True, "Valid"

    def add_rule(self, priority, action, protocol="TCP", source_cidr="0.0.0.0/0", dest_cidr="0.0.0.0/0", dest_port=None, direction="INBOUND", interface="ANY", is_enabled=1):
        valid, msg = self.validate_inputs(source_cidr, dest_cidr, dest_port)
        if not valid:
            raise ValueError(msg)

        if self.db:
            rule_id = self.db.add_rule(priority, action, direction, protocol, source_cidr, dest_cidr, dest_port, interface, is_enabled)
            self.reload_rules()
            self._sync_rules_to_file()
            return rule_id
        else:
            with self.lock:
                self.rules_cache.append({
                    "id": len(self.rules_cache) + 1,
                    "priority": priority,
                    "action": action,
                    "direction": direction,
                    "protocol": protocol,
                    "source_cidr": source_cidr,
                    "dest_cidr": dest_cidr,
                    "dest_port": dest_port,
                    "interface": interface,
                    "is_enabled": is_enabled
                })
                self.rules_cache.sort(key=lambda r: r["priority"])
                return len(self.rules_cache)

    def delete_rule(self, rule_id):
        if self.db:
            res = self.db.delete_rule(rule_id)
            self.reload_rules()
            self._sync_rules_to_file()
            return res
        else:
            with self.lock:
                self.rules_cache = [r for r in self.rules_cache if r.get("id") != rule_id]
                return True

    def _sync_rules_to_file(self):
        if not os.path.exists(self.rules_file_path):
            return
        try:
            with open(self.rules_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["acl_rules"] = self.rules_cache
            with open(self.rules_file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _match_cidr(self, ip_str, cidr_str):
        if not cidr_str or cidr_str == "ANY" or cidr_str == "0.0.0.0/0":
            return True
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            addr = ipaddress.ip_address(ip_str)
            return addr in net
        except ValueError:
            return ip_str == cidr_str

    def _match_port(self, packet_port, rule_port):
        if rule_port is None or rule_port == "ANY":
            return True
        try:
            return int(packet_port) == int(rule_port)
        except (ValueError, TypeError):
            return False

    def _match_protocol(self, packet_proto, rule_proto):
        if not rule_proto or rule_proto == "ANY":
            return True
        p_str = str(packet_proto).upper()
        r_str = str(rule_proto).upper()
        if p_str == r_str:
            return True
        proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
        return proto_map.get(p_str, p_str) == r_str

    def evaluate(self, packet_info):
        src_ip = None
        dst_ip = None
        dport = None
        protocol = "TCP"
        interface = "ANY"
        direction = "INBOUND"

        if hasattr(packet_info, "haslayer"):
            if packet_info.haslayer("IP"):
                src_ip = packet_info["IP"].src
                dst_ip = packet_info["IP"].dst
                proto_num = packet_info["IP"].proto
                protocol = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else str(proto_num)))
            if packet_info.haslayer("TCP"):
                dport = packet_info["TCP"].dport
            elif packet_info.haslayer("UDP"):
                dport = packet_info["UDP"].dport
        elif isinstance(packet_info, dict):
            src_ip = packet_info.get("src") or packet_info.get("src_ip")
            dst_ip = packet_info.get("dst") or packet_info.get("dst_ip")
            dport = packet_info.get("dport") or packet_info.get("dest_port")
            protocol = packet_info.get("protocol") or packet_info.get("proto") or "TCP"
            interface = packet_info.get("interface", "ANY")
            direction = packet_info.get("direction", "INBOUND")

        if dport is not None:
            try:
                if int(dport) in self.SAFE_PORTS:
                    return "ALLOW"
            except (ValueError, TypeError):
                pass

        if not src_ip or not dst_ip:
            return "ALLOW"

        if self.db:
            is_banned, _, _ = self.db.is_ip_banned(src_ip)
            if is_banned:
                return "DROP"

        with self.lock:
            rules = list(self.rules_cache)

        for rule in rules:
            if not rule.get("is_enabled", 1):
                continue
            if rule.get("direction") != "ANY" and rule.get("direction") != direction:
                continue
            if rule.get("interface") != "ANY" and rule.get("interface") != interface:
                continue
            if not self._match_protocol(protocol, rule.get("protocol")):
                continue
            if not self._match_cidr(src_ip, rule.get("source_cidr")):
                continue
            if not self._match_cidr(dst_ip, rule.get("dest_cidr")):
                continue
            if not self._match_port(dport, rule.get("dest_port")):
                continue

            return rule.get("action", "ALLOW")

        return "ALLOW"

RuleEvaluator = AclEngine

