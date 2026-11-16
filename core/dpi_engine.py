import json
import os
import re
import urllib.parse

class DeepPacketInspector:
    def __init__(self, rules_file_path=None):
        if rules_file_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.rules_file_path = os.path.normpath(os.path.join(base_dir, "config", "rules.json"))
        else:
            self.rules_file_path = os.path.normpath(os.path.abspath(rules_file_path))

        self.compiled_sqli = [
            ("SQLi-Boolean-Quote", re.compile(r"('|\")\s*(or|and)\s*('|\")?1('|\")?\s*=\s*('|\")?1('|\")?", re.IGNORECASE)),
            ("SQLi-Boolean-Numeric", re.compile(r"('|\")\s*(or|and)\s+1\s*=\s*1", re.IGNORECASE)),
            ("SQLi-Union-Select", re.compile(r"union\s+(all\s+)?select", re.IGNORECASE)),
            ("SQLi-Drop-Table", re.compile(r"drop\s+table", re.IGNORECASE)),
            ("SQLi-Sleep-Benchmark", re.compile(r"(sleep|benchmark)\s*\(", re.IGNORECASE)),
            ("SQLi-Comment-Dash", re.compile(r"(--|;--)", re.IGNORECASE))
        ]

        self.compiled_xss = [
            ("XSS-Script-Tag", re.compile(r"<\s*script[^>]*>", re.IGNORECASE)),
            ("XSS-Javascript-URI", re.compile(r"javascript\s*:", re.IGNORECASE)),
            ("XSS-Event-Handler", re.compile(r"(onerror|onload|onclick|onmouseover)\s*=", re.IGNORECASE)),
            ("XSS-Alert-Call", re.compile(r"alert\s*\(", re.IGNORECASE)),
            ("XSS-Document-Cookie", re.compile(r"document\.cookie", re.IGNORECASE)),
            ("XSS-IFrame-Tag", re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE))
        ]

        self.compiled_cred = [
            ("Cleartext Credentials-BasicAuth", re.compile(r"authorization\s*:\s*basic\s+[a-z0-9+/=]+", re.IGNORECASE)),
            ("Cleartext Credentials-PasswordParam", re.compile(r"(password|passwd|pwd)\s*=\s*[^&\s]+", re.IGNORECASE)),
            ("Cleartext Credentials-APIKey", re.compile(r"(api_key|apikey|secret_key)\s*=\s*[^&\s]+", re.IGNORECASE))
        ]

        self.compiled_cmd = [
            ("Command-Injection", re.compile(r"(cmd\.exe|/etc/passwd|eval\(|base64_decode)", re.IGNORECASE))
        ]

        self.blacklisted_domains = []
        self.blocked_paths = []
        self.blocked_keywords = []
        self.blocked_user_agents = []
        self._load_config()

    def _load_config(self):
        target_path = self.rules_file_path
        if not os.path.exists(target_path) and os.path.exists(target_path + ".example"):
            target_path = target_path + ".example"
        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.blacklisted_domains = [d.lower().strip() for d in data.get("blacklisted_domains", [])]
                    self.blocked_paths = [p.lower().strip() for p in data.get("blocked_url_paths", [])]
                    self.blocked_keywords = [k.lower().strip() for k in data.get("blocked_keywords", [])]
                    self.blocked_user_agents = [u.lower().strip() for u in data.get("blocked_user_agents", [])]
            except Exception:
                pass

    def inspect_domain(self, host):
        if not host:
            return False, "CLEAN", ""
        self._load_config()
        host_lower = host.lower().strip()
        if ":" in host_lower:
            host_lower = host_lower.split(":")[0]

        for domain in self.blacklisted_domains:
            if host_lower == domain or host_lower.endswith("." + domain):
                return True, "Domain Blacklist", domain
        return False, "CLEAN", ""

    def inspect_url_path(self, path):
        if not path:
            return False, "CLEAN", ""
        self._load_config()
        decoded_path = urllib.parse.unquote_plus(path).lower()
        for bp in self.blocked_paths:
            if bp in decoded_path:
                return True, "Restricted URL Path", bp
        return False, "CLEAN", ""

    def inspect_user_agent(self, user_agent):
        if not user_agent:
            return False, "CLEAN", ""
        self._load_config()
        ua_lower = str(user_agent).lower()
        for bua in self.blocked_user_agents:
            if bua in ua_lower:
                return True, "Blocked User-Agent", bua
        return False, "CLEAN", ""

    def inspect_payload(self, raw_content):
        if not raw_content:
            return False, "CLEAN", ""

        if isinstance(raw_content, bytes):
            try:
                text = raw_content.decode("utf-8")
            except UnicodeDecodeError:
                text = raw_content.decode("latin-1", errors="ignore")
        else:
            text = str(raw_content)

        decoded_text = urllib.parse.unquote_plus(text)
        targets = [text, decoded_text]

        for target in targets:
            for rule_name, pattern in self.compiled_sqli:
                m = pattern.search(target)
                if m:
                    return True, "SQLi (Deep Packet Inspection)", rule_name

            for rule_name, pattern in self.compiled_xss:
                m = pattern.search(target)
                if m:
                    return True, "XSS (Deep Packet Inspection)", rule_name

            for rule_name, pattern in self.compiled_cred:
                m = pattern.search(target)
                if m:
                    return True, rule_name.split("-")[0], rule_name

            for rule_name, pattern in self.compiled_cmd:
                m = pattern.search(target)
                if m:
                    return True, "Command Injection", rule_name

            for kw in self.blocked_keywords:
                if kw in target.lower():
                    return True, "Keyword Filter", kw

        return False, "CLEAN", ""

