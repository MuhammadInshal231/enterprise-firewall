import csv
import io
import json
import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

from core.acl_engine import DatabaseManager, AclEngine
from core.license_manager import LicenseManager
from dashboard.auth import AuthManager

class DashboardServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, engine=None):
        self.engine = engine
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_dir = base_dir
        self.db = engine.db if engine else DatabaseManager()
        self.acl = engine.acl if engine else AclEngine(self.db)
        self.auth = AuthManager(self.db.db_path)
        self.license = LicenseManager()
        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        super().server_bind()

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _get_auth_context(self):
        token = self.headers.get("X-Auth-Token")
        if not token:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
        if not token:
            cookie_header = self.headers.get("Cookie", "")
            for cookie in cookie_header.split(";"):
                if "=" in cookie:
                    k, v = cookie.strip().split("=", 1)
                    if k == "session_token":
                        token = v
                        break
        if token:
            valid, username, role = self.server.auth.validate_session(token)
            if valid:
                return username, role, token
        return None, None, None

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._serve_file("dashboard/index.html", "text/html")
        elif path == "/style.css":
            self._serve_file("dashboard/style.css", "text/css")
        elif path == "/app.js":
            self._serve_file("dashboard/app.js", "application/javascript")
        elif path == "/api/stats":
            self._handle_stats()
        elif path == "/api/stream":
            self._handle_stream()
        elif path == "/api/rules":
            self._handle_get_rules()
        elif path == "/api/bans":
            self._handle_get_bans()
        elif path == "/api/license":
            self._handle_license()
        elif path == "/api/export/rules":
            self._handle_export_rules()
        elif path == "/api/export/logs":
            self._handle_export_logs()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/auth/login":
            self._handle_login()
            return

        username, role, token = self._get_auth_context()
        if not role:
            self._send_json({"error": "Authentication required"}, 401)
            return

        if path == "/api/auth/logout":
            if token:
                self.server.auth.revoke_session(token)
            self._send_json({"status": "logged_out"})
        elif path == "/api/rules":
            if role != "ADMIN":
                self._send_json({"error": "Forbidden: ADMIN role required"}, 403)
                return
            self._handle_add_rule()
        elif path == "/api/bans":
            if role != "ADMIN":
                self._send_json({"error": "Forbidden: ADMIN role required"}, 403)
                return
            self._handle_add_ban()
        else:
            self.send_error(404, "Not Found")

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        username, role, token = self._get_auth_context()
        if not role:
            self._send_json({"error": "Authentication required"}, 401)
            return

        if role != "ADMIN":
            self._send_json({"error": "Forbidden: ADMIN role required"}, 403)
            return

        if path.startswith("/api/rules/"):
            rule_id_str = path.split("/")[-1]
            try:
                rule_id = int(rule_id_str)
                success = self.server.acl.delete_rule(rule_id)
                self._send_json({"status": "deleted" if success else "not_found"})
            except ValueError:
                self._send_json({"error": "Invalid rule ID"}, 400)
        elif path.startswith("/api/bans/"):
            ip = path.split("/")[-1]
            if self.server.engine:
                self.server.engine.ids.unban_ip(ip)
            else:
                self.server.db.remove_auto_ban(ip)
            self._send_json({"status": "unbanned", "ip": ip})
        else:
            self.send_error(404, "Not Found")

    def _serve_file(self, rel_path, content_type):
        parts = rel_path.replace("\\", "/").split("/")
        full_path = os.path.normpath(os.path.join(self.server.base_dir, *parts))
        if not os.path.exists(full_path):
            self.send_error(404, "File Not Found")
            return
        try:
            with open(full_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(500, "Internal Server Error")

    def _handle_login(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            req = json.loads(body.decode("utf-8"))
            username = req.get("username", "")
            password = req.get("password", "")
            token, role = self.server.auth.authenticate(username, password)
            if token:
                self._send_json({"token": token, "username": username, "role": role})
            else:
                self._send_json({"error": "Invalid credentials"}, 401)
        except Exception as e:
            self._send_json({"error": str(e)}, 400)

    def _handle_stats(self):
        engine = self.server.engine
        metrics = engine.telemetry.get_latest_metrics() if engine else {
            "total_packets": 0, "total_bytes": 0, "total_dropped": 0, "active_sessions": 0,
            "pps": 0, "bps": 0, "drops_per_sec": 0
        }
        events = self.server.db.get_recent_events(limit=25)
        rules = self.server.acl.rules_cache if self.server.acl else []
        bans = engine.ids.get_bans() if engine else self.server.db.get_active_bans()
        lic = self.server.license.get_status()

        data = {
            "metrics": metrics,
            "recent_events": events,
            "rules_count": len(rules),
            "active_bans_count": len(bans),
            "license": lic
        }
        self._send_json(data)

    def _handle_stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        engine = self.server.engine
        try:
            for _ in range(30):
                ring = engine.telemetry.get_ring_buffer() if engine else []
                payload = json.dumps({"ring_buffer": ring})
                msg = f"data: {payload}\n\n".encode("utf-8")
                self.wfile.write(msg)
                self.wfile.flush()
                import time
                time.sleep(1.0)
        except Exception:
            pass

    def _handle_get_rules(self):
        rules = self.server.acl.rules_cache if self.server.acl else self.server.db.get_rules()
        self._send_json(rules)

    def _handle_add_rule(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            req = json.loads(body.decode("utf-8"))
            priority = int(req.get("priority", 100))
            action = req.get("action", "ALLOW").upper()
            direction = req.get("direction", "INBOUND").upper()
            protocol = req.get("protocol", "TCP").upper()
            src_cidr = req.get("source_cidr", "0.0.0.0/0")
            dst_cidr = req.get("dest_cidr", "0.0.0.0/0")
            dst_port = req.get("dest_port")
            interface = req.get("interface", "ANY")
            rule_id = self.server.acl.add_rule(
                priority=priority, action=action, direction=direction,
                protocol=protocol, source_cidr=src_cidr, dest_cidr=dst_cidr,
                dest_port=dst_port, interface=interface
            )
            self._send_json({"status": "created", "rule_id": rule_id}, 201)
        except Exception as e:
            self._send_json({"error": str(e)}, 400)

    def _handle_get_bans(self):
        engine = self.server.engine
        bans = engine.ids.get_bans() if engine else self.server.db.get_active_bans()
        self._send_json(bans)

    def _handle_add_ban(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            req = json.loads(body.decode("utf-8"))
            ip = req.get("ip_address")
            duration = int(req.get("duration", 300))
            reason = req.get("reason", "Manual Operator Ban")
            if not ip:
                self._send_json({"error": "Missing ip_address"}, 400)
                return
            if self.server.engine:
                self.server.engine.ids.ban_ip(ip, duration=duration, reason=reason)
            else:
                self.server.db.add_auto_ban(ip, duration=duration, reason=reason)
            self._send_json({"status": "banned", "ip": ip}, 201)
        except Exception as e:
            self._send_json({"error": str(e)}, 400)

    def _handle_license(self):
        status = self.server.license.get_status()
        self._send_json(status)

    def _handle_export_rules(self):
        rules = self.server.acl.rules_cache if self.server.acl else self.server.db.get_rules()
        data = {
            "version": "2.1.0",
            "export_time": os.getenv("EXPORT_TIMESTAMP", ""),
            "rules": rules
        }
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", "attachment; filename=firewall_rules.json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_export_logs(self):
        events = self.server.db.get_all_events()
        output = io.StringIO()
        fieldnames = ["id", "timestamp", "source_ip", "dest_ip", "dest_port", "threat_type", "action_taken", "payload_sample"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for evt in events:
            writer.writerow(evt)
        body = output.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=firewall_audit_log.csv")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

