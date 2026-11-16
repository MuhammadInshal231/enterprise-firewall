import datetime
import threading
import time

class TCPFlagAnalyzer:
    @staticmethod
    def inspect(flags):
        if flags is None:
            return "CLEAN"

        if isinstance(flags, str):
            flags_upper = flags.upper()
            if flags_upper in ("0", "NULL"):
                return "NULL_SCAN"
            if "FIN" in flags_upper and "PSH" in flags_upper and "URG" in flags_upper:
                return "XMAS_SCAN"
            if flags_upper in ("SYN_SCAN", "STEALTH_SYN"):
                return "SYN_SCAN"
            if "SYN" in flags_upper and "FIN" in flags_upper:
                return "SYN_FIN_SCAN"
            return "CLEAN"

        if flags == 0:
            return "NULL_SCAN"
        if flags == 41:
            return "XMAS_SCAN"
        if flags == 2:
            return "SYN_SCAN"
        if (flags & 0x02) and (flags & 0x01):
            return "SYN_FIN_SCAN"
        return "CLEAN"

class TokenBucketRateLimiter:
    def __init__(self, rate=50.0, capacity=100.0):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last_update = time.time()
        self.lock = threading.Lock()

    def allow(self, cost=1.0):
        with self.lock:
            now = time.time()
            delta = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            self.last_update = now
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False

class IntrusionPreventionSystem:
    def __init__(self, database_manager=None, default_rate=50.0, default_burst=100.0, ban_threshold=5, ban_duration=300):
        self.db = database_manager
        self.default_rate = default_rate
        self.default_burst = default_burst
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self.limiters = {}
        self.violation_counts = {}
        self.memory_bans = {}
        self.lock = threading.Lock()

    def _get_limiter(self, ip_address):
        with self.lock:
            if ip_address not in self.limiters:
                self.limiters[ip_address] = TokenBucketRateLimiter(rate=self.default_rate, capacity=self.default_burst)
            return self.limiters[ip_address]

    def is_ip_banned(self, ip_address):
        now = time.time()
        with self.lock:
            if ip_address in self.memory_bans:
                expires_at, reason = self.memory_bans[ip_address]
                if now < expires_at:
                    return True, reason, expires_at
                else:
                    del self.memory_bans[ip_address]

        if self.db:
            is_banned, reason, expires_at = self.db.is_ip_banned(ip_address)
            if is_banned:
                return True, reason, expires_at

        return False, None, None

    def record_violation(self, ip_address, reason="Security Policy Violation"):
        with self.lock:
            self.violation_counts[ip_address] = self.violation_counts.get(ip_address, 0) + 1
            count = self.violation_counts[ip_address]

        if count >= self.ban_threshold:
            self.ban_ip(ip_address, duration=self.ban_duration, reason=reason)
            return True
        return False

    def ban_ip(self, ip_address, duration=None, reason="Automated IDS Mitigation"):
        if duration is None:
            duration = self.ban_duration
        expires_at = time.time() + duration
        with self.lock:
            self.memory_bans[ip_address] = (expires_at, reason)
        if self.db:
            self.db.add_auto_ban(ip_address, duration=duration, reason=reason)

    def unban_ip(self, ip_address):
        with self.lock:
            if ip_address in self.memory_bans:
                del self.memory_bans[ip_address]
            if ip_address in self.violation_counts:
                del self.violation_counts[ip_address]
        if self.db:
            self.db.remove_auto_ban(ip_address)

    def check_packet(self, ip_address, flags=None):
        banned, reason, _ = self.is_ip_banned(ip_address)
        if banned:
            return False, f"BANNED: {reason}"

        if flags is not None:
            flag_result = TCPFlagAnalyzer.inspect(flags)
            if flag_result != "CLEAN":
                self.record_violation(ip_address, reason=f"Abnormal TCP Flags: {flag_result}")
                return False, f"FLAG_ANOMALY: {flag_result}"

        limiter = self._get_limiter(ip_address)
        if not limiter.allow():
            self.record_violation(ip_address, reason="Rate Limit Exceeded")
            return False, "RATE_LIMITED"

        return True, "CLEAN"

    def get_bans(self):
        result = []
        now = time.time()
        with self.lock:
            for ip, (exp, rsn) in list(self.memory_bans.items()):
                if now < exp:
                    result.append({"ip_address": ip, "reason": rsn, "expires_at": exp})
                else:
                    del self.memory_bans[ip]

        if self.db:
            db_bans = self.db.get_active_bans()
            existing_ips = {b["ip_address"] for b in result}
            for b in db_bans:
                if b["ip_address"] not in existing_ips:
                    result.append(b)

        return result

