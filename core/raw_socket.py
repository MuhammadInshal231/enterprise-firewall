import datetime
import os
import queue
import select
import socket
import threading
import time
import urllib.parse

from core.acl_engine import AclEngine, DatabaseManager
from core.dpi_engine import DeepPacketInspector
from core.ids_engine import IntrusionPreventionSystem, TCPFlagAnalyzer
from core.packet_parser import parse_http_request
from core.spi_state import StateTable
from core.telemetry import TelemetryCollector, append_csv_audit, setup_logger
from core.tls_sni import TLSInspector

def generate_403_html(client_ip, host, url, threat_category, rule_name):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        "<!DOCTYPE html>"
        "<html><head><meta charset='utf-8'><title>403 Forbidden</title>"
        "<style>"
        "body{background:rgb(15,23,42);color:rgb(241,245,249);font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}"
        ".card{background:rgb(30,41,59);border:1px solid rgb(239,68,68);border-radius:12px;padding:32px;max-width:600px;width:90%;box-shadow:0 10px 25px rgba(0,0,0,0.5);}"
        ".header{color:rgb(239,68,68);font-size:24px;font-weight:bold;margin-bottom:16px;display:flex;align-items:center;gap:12px;}"
        ".table{width:100%;margin-top:20px;border-collapse:collapse;}"
        ".table td{padding:10px;border-bottom:1px solid rgb(51,65,85);font-size:14px;}"
        ".table td.label{color:rgb(148,163,184);font-weight:600;width:35%;}"
        ".badge{background:rgba(239,68,68,0.2);color:rgb(248,113,113);padding:4px 8px;border-radius:4px;font-weight:bold;font-size:12px;}"
        ".footer{margin-top:24px;text-align:center;font-size:12px;color:rgb(100,116,139);}"
        "</style></head><body>"
        "<div class='card'>"
        "<div class='header'><span>[!]</span> 403 Access Denied</div>"
        "<p>Request blocked by Layer-7 Enterprise Application Proxy Firewall.</p>"
        "<table class='table'>"
        f"<tr><td class='label'>Client IP</td><td>{client_ip}</td></tr>"
        f"<tr><td class='label'>Target Host</td><td>{host}</td></tr>"
        f"<tr><td class='label'>Requested URL</td><td>{url}</td></tr>"
        f"<tr><td class='label'>Threat Category</td><td><span class='badge'>{threat_category}</span></td></tr>"
        f"<tr><td class='label'>Rule Triggered</td><td>{rule_name}</td></tr>"
        f"<tr><td class='label'>Timestamp</td><td>{timestamp}</td></tr>"
        "</table>"
        "<div class='footer'>Enterprise Firewall Security Subsystem v2.1</div>"
        "</div></body></html>"
    )

class CoreFirewallEngine:
    def __init__(self, proxy_host="127.0.0.1", proxy_port=8080, db_path=None, interface="eth0"):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.interface = interface
        self.db = DatabaseManager(db_path)
        self.state_table = StateTable()
        self.dpi = DeepPacketInspector()
        self.ids = IntrusionPreventionSystem(self.db)
        self.acl = AclEngine(self.db)
        self.rules = self.acl
        self.tls = TLSInspector()
        self.telemetry = TelemetryCollector()
        self.logger = setup_logger()

        self.running = False
        self.proxy_socket = None

    def start(self):
        self.running = True
        self._start_proxy_listener()
        t_purge = threading.Thread(target=self._state_table_purger, daemon=True)
        t_purge.start()

    def stop(self):
        self.running = False
        if self.proxy_socket:
            try:
                self.proxy_socket.close()
            except OSError:
                pass

    def _start_proxy_listener(self):
        try:
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            self.proxy_socket.bind((self.proxy_host, self.proxy_port))
            self.proxy_socket.listen(128)
            t = threading.Thread(target=self._proxy_accept_loop, daemon=True)
            t.start()
        except OSError:
            pass

    def _state_table_purger(self):
        while self.running:
            time.sleep(5.0)
            self.state_table.purge_expired()
            self.telemetry.set_active_sessions(self.state_table.get_active_count())

    def _proxy_accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self.proxy_socket.accept()
                client_sock.settimeout(15.0)
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except OSError:
                break

    def _handle_client(self, client_sock, client_addr):
        client_ip = client_addr[0]
        client_port = client_addr[1]

        allowed, reason = self.ids.check_packet(client_ip)
        if not allowed:
            self.telemetry.record_packet(0, dropped=True)
            self._send_block_response(client_sock, client_ip, "BLOCKED_IP", "IDS Mitigation", reason)
            try:
                client_sock.close()
            except OSError:
                pass
            return

        raw_buffer = bytearray()
        try:
            chunk = client_sock.recv(8192)
            if not chunk:
                client_sock.close()
                return
            raw_buffer.extend(chunk)
            while b"\r\n\r\n" not in raw_buffer and b"\n\n" not in raw_buffer and len(raw_buffer) < 32768:
                try:
                    client_sock.settimeout(0.5)
                    c = client_sock.recv(4096)
                    if not c:
                        break
                    raw_buffer.extend(c)
                except socket.timeout:
                    break
        except Exception:
            try:
                client_sock.close()
            except OSError:
                pass
            return

        self.telemetry.record_packet(len(raw_buffer), dropped=False)
        parsed = parse_http_request(bytes(raw_buffer))
        if not parsed:
            try:
                client_sock.close()
            except OSError:
                pass
            return

        target_host = parsed["host"]
        target_port = parsed["port"]
        method = parsed["method"]

        flow_key = (client_ip, target_host or "0.0.0.0", client_port, target_port, "TCP")
        self.state_table.update_state(flow_key, flags="SYN", packet_bytes=len(raw_buffer))

        acl_packet = {
            "src_ip": client_ip,
            "dst_ip": target_host,
            "dest_port": target_port,
            "protocol": "TCP",
            "direction": "INBOUND"
        }
        acl_verdict = self.acl.evaluate(acl_packet)
        if acl_verdict in ("DROP", "REJECT"):
            self.telemetry.record_packet(0, dropped=True)
            self._log_and_block(client_ip, target_host, target_port, parsed.get("raw_url", ""), "ACL Firewall Policy", f"Rule matched {acl_verdict}", client_sock)
            return

        if method == "CONNECT":
            self._handle_connect(client_sock, client_ip, client_port, target_host, target_port, flow_key)
        else:
            self._handle_http(client_sock, client_ip, client_port, parsed, flow_key)

    def _handle_connect(self, client_sock, client_ip, client_port, target_host, target_port, flow_key):
        is_blocked, threat_cat, rule_name = self.dpi.inspect_domain(target_host)
        if is_blocked:
            self.telemetry.record_packet(0, dropped=True)
            self._log_and_block(client_ip, target_host, target_port, f"https://{target_host}:{target_port}", threat_cat, rule_name, client_sock)
            return

        upstream_sock = None
        try:
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_sock.settimeout(10.0)
            upstream_sock.connect((target_host, target_port))
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.state_table.update_state(flow_key, flags="ACK")
        except Exception:
            if upstream_sock:
                try:
                    upstream_sock.close()
                except OSError:
                    pass
            try:
                client_sock.close()
            except OSError:
                pass
            return

        self._relay_tunnel(client_sock, upstream_sock, client_ip, target_host, flow_key)

    def _relay_tunnel(self, client_sock, upstream_sock, client_ip, target_host, flow_key):
        sockets = [client_sock, upstream_sock]
        checked_sni = False
        try:
            while self.running:
                readable, _, exceptional = select.select(sockets, [], sockets, 2.0)
                if exceptional:
                    break
                for s in readable:
                    data = s.recv(16384)
                    if not data:
                        return
                    if s is client_sock:
                        if not checked_sni:
                            sni_blocked, sni_host, matched = self.tls.inspect_packet(data)
                            if sni_blocked:
                                self.telemetry.record_packet(0, dropped=True)
                                self.db.log_security_event(client_ip, target_host, 443, "TLS SNI Blacklist", "DROP", sni_host)
                                geo = self.telemetry.geo.lookup(client_ip)
                                append_csv_audit({
                                    "timestamp": datetime.datetime.now().isoformat(),
                                    "source_ip": client_ip,
                                    "dest_ip": target_host,
                                    "dest_port": 443,
                                    "protocol": "TCP",
                                    "action": "DROP",
                                    "threat_category": "TLS SNI Blacklist",
                                    "rule_triggered": matched,
                                    "country": geo["country"],
                                    "asn": geo["asn"]
                                })
                                return
                            checked_sni = True
                        upstream_sock.sendall(data)
                        self.telemetry.record_packet(len(data), dropped=False)
                        self.state_table.update_state(flow_key, packet_bytes=len(data))
                    else:
                        client_sock.sendall(data)
                        self.telemetry.record_packet(len(data), dropped=False)
        except Exception:
            pass
        finally:
            self.state_table.update_state(flow_key, flags="FIN")
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    def _handle_http(self, client_sock, client_ip, client_port, parsed, flow_key):
        target_host = parsed["host"]
        target_port = parsed["port"]
        raw_url = parsed["raw_url"]
        path = parsed["path"]
        body = parsed["body"]
        headers = parsed["headers"]
        user_agent = headers.get("user-agent", "")

        is_threat, threat_cat, rule_name = self.dpi.inspect_domain(target_host)
        if not is_threat:
            is_threat, threat_cat, rule_name = self.dpi.inspect_url_path(path)
        if not is_threat:
            is_threat, threat_cat, rule_name = self.dpi.inspect_user_agent(user_agent)
        if not is_threat:
            is_threat, threat_cat, rule_name = self.dpi.inspect_payload(raw_url)
        if not is_threat and body:
            is_threat, threat_cat, rule_name = self.dpi.inspect_payload(body)

        if is_threat:
            self.telemetry.record_packet(0, dropped=True)
            self._log_and_block(client_ip, target_host, target_port, raw_url, threat_cat, rule_name, client_sock)
            return

        self.state_table.update_state(flow_key, flags="ACK")
        upstream_sock = None
        try:
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_sock.settimeout(10.0)
            upstream_sock.connect((target_host, target_port))
            upstream_sock.sendall(parsed["raw_bytes"])
            while self.running:
                chunk = upstream_sock.recv(8192)
                if not chunk:
                    break
                client_sock.sendall(chunk)
                self.telemetry.record_packet(len(chunk), dropped=False)
                self.state_table.update_state(flow_key, packet_bytes=len(chunk))
        except Exception:
            pass
        finally:
            self.state_table.update_state(flow_key, flags="FIN")
            if upstream_sock:
                try:
                    upstream_sock.close()
                except OSError:
                    pass
            try:
                client_sock.close()
            except OSError:
                pass

    def _log_and_block(self, client_ip, host, port, url, threat_category, rule_name, client_sock):
        self.db.log_security_event(client_ip, host, port, threat_category, "DROP", rule_name)
        geo = self.telemetry.geo.lookup(client_ip)
        append_csv_audit({
            "timestamp": datetime.datetime.now().isoformat(),
            "source_ip": client_ip,
            "dest_ip": host,
            "dest_port": port,
            "protocol": "TCP",
            "action": "DROP",
            "threat_category": threat_category,
            "rule_triggered": rule_name,
            "country": geo["country"],
            "asn": geo["asn"]
        })
        self._send_block_response(client_sock, client_ip, host, threat_category, rule_name, url)
        try:
            client_sock.close()
        except OSError:
            pass

    def _send_block_response(self, client_sock, client_ip, host, threat_category, rule_name, url=""):
        html = generate_403_html(client_ip, host, url, threat_category, rule_name)
        html_bytes = html.encode("utf-8")
        headers = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(html_bytes)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        try:
            client_sock.sendall(headers.encode("latin-1") + html_bytes)
        except OSError:
            pass

