import http.client
import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.license_manager import LicenseManager
from core.raw_socket import CoreFirewallEngine
from dashboard.auth import AuthManager
from dashboard.server import DashboardHandler, DashboardServer

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 18080
DASHBOARD_PORT = 18081
MOCK_UPSTREAM_PORT = 18088

class MockUpstreamServer:
    def __init__(self, host="127.0.0.1", port=18088):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
                req = conn.recv(1024)
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n\r\nOK"
                )
                conn.sendall(resp)
                conn.close()
            except OSError:
                break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

def send_proxy_request(target_url, custom_headers=None):
    parsed = http.client.urlsplit(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    req_line = f"GET {target_url} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if custom_headers:
        for k, v in custom_headers.items():
            req_line += f"{k}: {v}\r\n"
    req_line += "Connection: close\r\n\r\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((PROXY_HOST, PROXY_PORT))
    s.sendall(req_line.encode("latin-1"))

    resp_data = bytearray()
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp_data.extend(chunk)
        except socket.timeout:
            break
    s.close()

    text = resp_data.decode("latin-1", errors="ignore")
    status_code = None
    if text.startswith("HTTP/"):
        parts = text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                pass
    return status_code, text

def run_tests():
    mock_server = MockUpstreamServer(port=MOCK_UPSTREAM_PORT)
    mock_server.start()

    engine = CoreFirewallEngine(proxy_host=PROXY_HOST, proxy_port=PROXY_PORT)
    engine.start()

    dash_server = DashboardServer((PROXY_HOST, DASHBOARD_PORT), DashboardHandler, engine=engine)
    dash_thread = threading.Thread(target=dash_server.serve_forever, daemon=True)
    dash_thread.start()

    time.sleep(1.0)
    results = []

    try:
        lm = LicenseManager()
        valid, tier, _ = lm.verify_token()
        if valid and tier == "ENTERPRISE":
            results.append(("TC-01", "Offline Cryptographic License Validation", "PASS", f"Tier: {tier}"))
        else:
            results.append(("TC-01", "Offline Cryptographic License Validation", "FAIL", f"Valid: {valid}"))
    except Exception as e:
        results.append(("TC-01", "Offline Cryptographic License Validation", "ERR", str(e)))

    try:
        url = f"http://127.0.0.1:{MOCK_UPSTREAM_PORT}/test"
        code, _ = send_proxy_request(url)
        if code == 200:
            results.append(("TC-02", "Normal Clean HTTP Traffic", "PASS", f"HTTP {code}"))
        else:
            results.append(("TC-02", "Normal Clean HTTP Traffic", "FAIL", f"HTTP {code}"))
    except Exception as e:
        results.append(("TC-02", "Normal Clean HTTP Traffic", "ERR", str(e)))

    try:
        url = "http://example.com"
        code, body = send_proxy_request(url)
        if code == 403 and "Domain Blacklist" in body:
            results.append(("TC-03", "Blacklisted Domain Blocking", "PASS", "HTTP 403 Blocked"))
        else:
            results.append(("TC-03", "Blacklisted Domain Blocking", "FAIL", f"HTTP {code}"))
    except Exception as e:
        results.append(("TC-03", "Blacklisted Domain Blocking", "ERR", str(e)))

    try:
        url = f"http://127.0.0.1:{MOCK_UPSTREAM_PORT}/query?id=1%27%20OR%20%271%27=%271"
        code, body = send_proxy_request(url)
        if code == 403 and "SQLi" in body:
            results.append(("TC-04", "Deep Packet Inspection SQLi", "PASS", "HTTP 403 Blocked"))
        else:
            results.append(("TC-04", "Deep Packet Inspection SQLi", "FAIL", f"HTTP {code}"))
    except Exception as e:
        results.append(("TC-04", "Deep Packet Inspection SQLi", "ERR", str(e)))

    try:
        url = f"http://127.0.0.1:{MOCK_UPSTREAM_PORT}/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
        code, body = send_proxy_request(url)
        if code == 403 and "XSS" in body:
            results.append(("TC-05", "Deep Packet Inspection XSS", "PASS", "HTTP 403 Blocked"))
        else:
            results.append(("TC-05", "Deep Packet Inspection XSS", "FAIL", f"HTTP {code}"))
    except Exception as e:
        results.append(("TC-05", "Deep Packet Inspection XSS", "ERR", str(e)))

    try:
        am = AuthManager(engine.db.db_path)
        token, role = am.authenticate("admin", "admin123")
        if token and role == "ADMIN":
            with engine.db.lock:
                c = engine.db._get_connection()
                c.execute("DELETE FROM rules WHERE priority = 888;")
                c.commit()
                c.close()
            engine.acl.reload_rules()

            conn = http.client.HTTPConnection(PROXY_HOST, DASHBOARD_PORT, timeout=5.0)
            payload = json.dumps({"priority": 888, "action": "DROP", "source_cidr": "198.51.100.0/24", "dest_port": 80})
            headers = {"Content-Type": "application/json", "X-Auth-Token": token}
            conn.request("POST", "/api/rules", body=payload, headers=headers)
            resp = conn.getresponse()
            if resp.status == 201:
                results.append(("TC-06", "PBKDF2 Auth & RBAC Mutation", "PASS", "Token + HTTP 201"))
            else:
                results.append(("TC-06", "PBKDF2 Auth & RBAC Mutation", "FAIL", f"HTTP {resp.status}"))
            conn.close()

            with engine.db.lock:
                c = engine.db._get_connection()
                c.execute("DELETE FROM rules WHERE priority = 888;")
                c.commit()
                c.close()
            engine.acl.reload_rules()
        else:
            results.append(("TC-06", "PBKDF2 Auth & RBAC Mutation", "FAIL", "Auth failed"))
    except Exception as e:
        results.append(("TC-06", "PBKDF2 Auth & RBAC Mutation", "ERR", str(e)))

    try:
        conn = http.client.HTTPConnection(PROXY_HOST, DASHBOARD_PORT, timeout=5.0)
        conn.request("GET", "/api/stats")
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()

        conn = http.client.HTTPConnection(PROXY_HOST, DASHBOARD_PORT, timeout=5.0)
        conn.request("GET", "/api/export/rules")
        resp_exp = conn.getresponse()
        exp_data = json.loads(resp_exp.read().decode("utf-8"))
        conn.close()

        if resp.status == 200 and "metrics" in data and resp_exp.status == 200 and "rules" in exp_data:
            results.append(("TC-07", "Web SOC Dashboard & Data Export", "PASS", "HTTP 200 JSON"))
        else:
            results.append(("TC-07", "Web SOC Dashboard & Data Export", "FAIL", f"HTTP {resp.status}"))
    except Exception as e:
        results.append(("TC-07", "Web SOC Dashboard & Data Export", "ERR", str(e)))

    engine.stop()
    dash_server.shutdown()
    mock_server.stop()

    print("\n" + "=" * 80)
    print("      ENTERPRISE FIREWALL v2.1 END-TO-END VERIFICATION SUITE      ")
    print("=" * 80)
    print(f"{'TEST ID':<10} {'TEST DESCRIPTION':<38} {'STATUS':<10} {'DETAILS':<20}")
    print("-" * 80)
    all_passed = True
    for tid, desc, stat, det in results:
        print(f"{tid:<10} {desc:<38} {stat:<10} {det:<20}")
        if stat != "PASS":
            all_passed = False
    print("=" * 80)

    if all_passed:
        print("\n[SUCCESS] ALL VERIFICATION TESTS PASSED (100% SUCCESS RATE)\n")
        sys.exit(0)
    else:
        print("\n[FAILURE] ONE OR MORE VERIFICATION TESTS FAILED\n")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()

