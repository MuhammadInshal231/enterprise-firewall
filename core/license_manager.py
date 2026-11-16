import hashlib
import hmac
import json
import os
import platform
import time
import uuid

SECRET_KEY = b"ENTERPRISE_FIREWALL_SECRET_KEY_v2.1_CORE"

class LicenseManager:
    def __init__(self, key_path=None, secret_key=None):
        if key_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.key_path = os.path.normpath(os.path.join(base_dir, "config", "license.key"))
        else:
            self.key_path = os.path.normpath(os.path.abspath(key_path))
        self.secret_key = secret_key or SECRET_KEY

    def get_hwid(self):
        node = platform.node() or "default_node"
        mac = uuid.getnode()
        raw = f"{node}-{mac}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def generate_token(self, tier="ENTERPRISE", expires=None, hwid=None):
        if tier not in ("TRIAL", "STANDARD", "ENTERPRISE"):
            raise ValueError("Invalid tier")
        if expires is None:
            expires = int(time.time()) + 315360000
        if hwid is None:
            hwid = self.get_hwid()
        payload = {
            "tier": tier,
            "expires": int(expires),
            "hwid": str(hwid)
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()
        token_data = {
            "payload": payload,
            "signature": sig
        }
        return json.dumps(token_data, indent=2)

    def write_license_file(self, token_str):
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        with open(self.key_path, "w", encoding="utf-8") as f:
            f.write(token_str)

    def verify_token(self, token_str=None):
        if token_str is None:
            if not os.path.exists(self.key_path):
                example_path = self.key_path + ".example"
                if os.path.exists(example_path):
                    try:
                        with open(example_path, "r", encoding="utf-8") as f:
                            token_str = f.read()
                        self.write_license_file(token_str)
                    except Exception:
                        pass
                if not os.path.exists(self.key_path):
                    token_str = self.generate_token(tier="ENTERPRISE", hwid="*")
                    self.write_license_file(token_str)
            if token_str is None:
                try:
                    with open(self.key_path, "r", encoding="utf-8") as f:
                        token_str = f.read()
                except Exception as e:
                    return False, "READ_ERROR", {"error": str(e)}

        try:
            data = json.loads(token_str)
            payload = data.get("payload", {})
            sig = data.get("signature", "")
        except Exception:
            return False, "CORRUPT_TOKEN", {"error": "Malformed license token"}

        tier = payload.get("tier")
        expires = payload.get("expires", 0)
        hwid = payload.get("hwid")

        if tier not in ("TRIAL", "STANDARD", "ENTERPRISE"):
            return False, "INVALID_TIER", {"error": "Unauthorized tier"}

        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_sig = hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, sig):
            return False, "SIGNATURE_MISMATCH", {"error": "Cryptographic signature mismatch"}

        if int(expires) < int(time.time()):
            return False, "EXPIRED", {"error": "License expired"}

        current_hwid = self.get_hwid()
        if hwid != "*" and hwid != current_hwid:
            return False, "HWID_MISMATCH", {"error": "Hardware identity mismatch"}

        return True, tier, payload

    def get_status(self):
        valid, tier, details = self.verify_token()
        return {
            "valid": valid,
            "tier": tier,
            "hwid": self.get_hwid(),
            "details": details
        }

