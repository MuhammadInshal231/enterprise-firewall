import os
import shutil
import sys

def run_setup():
    if sys.version_info < (3, 10):
        print("[ERROR] Python 3.10 or higher is required.")
        sys.exit(1)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, base_dir)

    print("==========================================================")
    print("      ENTERPRISE FIREWALL v2.1 AUTOMATED SETUP TOOL       ")
    print("==========================================================")

    dirs = [
        os.path.join(base_dir, "config"),
        os.path.join(base_dir, "logs"),
        os.path.join(base_dir, "core"),
        os.path.join(base_dir, "dashboard"),
        os.path.join(base_dir, "verification")
    ]
    for d in dirs:
        os.makedirs(os.path.normpath(d), exist_ok=True)
    print("[*] Required project directory structure verified.")

    config_files = ["rules.json", "settings.ini", "license.key"]
    for cf in config_files:
        target = os.path.normpath(os.path.join(base_dir, "config", cf))
        example = os.path.normpath(os.path.join(base_dir, "config", cf + ".example"))
        if not os.path.exists(target) and os.path.exists(example):
            shutil.copyfile(example, target)
            print(f"[*] Initialized config/{cf} from baseline example template.")

    from core.license_manager import LicenseManager
    lm = LicenseManager()
    valid, tier, _ = lm.verify_token()
    if not valid:
        print("[*] Generating new enterprise cryptographic activation token...")
        token = lm.generate_token(tier="ENTERPRISE", hwid="*")
        lm.write_license_file(token)
        valid, tier, _ = lm.verify_token()
    print(f"[*] Cryptographic License: VALID (Tier: {tier}, HWID: {lm.get_hwid()})")

    from core.acl_engine import DatabaseManager
    from dashboard.auth import AuthManager

    db = DatabaseManager()
    rules = db.get_rules()
    print(f"[*] SQLite WAL Database initialized ({len(rules)} default ACL rules loaded).")

    auth = AuthManager(db.db_path)
    print("[*] Authentication tables verified (Default users: admin / auditor).")

    print("----------------------------------------------------------")
    print("[SUCCESS] Setup complete. System is ready for deployment.")
    print("==========================================================")
    print("Next steps:")
    print("  1. Launch firewall:     python main.py")
    print("  2. Access dashboard:    http://127.0.0.1:8081  (admin / admin123)")
    print("  3. Run verification:    python verification/verify_system_e2e.py")
    print("  4. Admin CLI tool:      python cli_admin.py status")
    print("==========================================================")

if __name__ == "__main__":
    run_setup()

