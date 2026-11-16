import os
import signal
import sys
import threading
import time

from core.license_manager import LicenseManager
from core.raw_socket import CoreFirewallEngine
from dashboard.server import DashboardHandler, DashboardServer

def main():
    license_mgr = LicenseManager()
    valid, tier, details = license_mgr.verify_token()
    if not valid:
        print(f"[FATAL] License validation failed: {details.get('error', 'Unauthorized')}")
        print("[FATAL] Firewall engine initialization aborted.")
        sys.exit(1)

    print("==========================================================")
    print("   ENTERPRISE LAYER-7 APPLICATION PROXY FIREWALL v2.1     ")
    print("==========================================================")
    print(f"[*] License Status:     VALID (Tier: {tier})")
    print(f"[*] Machine HWID:       {license_mgr.get_hwid()}")
    print("[*] Proxy Engine:       127.0.0.1:8080 (TCP / TLS SNI / L7)")
    print("[*] Web SOC Dashboard:  http://127.0.0.1:8081")
    print("----------------------------------------------------------")

    engine = CoreFirewallEngine(proxy_host="127.0.0.1", proxy_port=8080)
    engine.start()

    dash_server = DashboardServer(("127.0.0.1", 8081), DashboardHandler, engine=engine)
    dash_thread = threading.Thread(target=dash_server.serve_forever, daemon=True)
    dash_thread.start()

    print("[*] All subsystems online and active. Press Ctrl+C to stop.")

    def shutdown(signum, frame):
        print("\n[*] Initiating graceful shutdown of firewall engine...")
        engine.stop()
        dash_server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1.0)

if __name__ == "__main__":
    main()
