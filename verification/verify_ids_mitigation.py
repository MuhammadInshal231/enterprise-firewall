import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ids_engine import IntrusionPreventionSystem, TCPFlagAnalyzer, TokenBucketRateLimiter

def test_tcp_flag_analyzer():
    assert TCPFlagAnalyzer.inspect(0) == "NULL_SCAN"
    assert TCPFlagAnalyzer.inspect(41) == "XMAS_SCAN"
    assert TCPFlagAnalyzer.inspect(2) == "SYN_SCAN"
    assert TCPFlagAnalyzer.inspect(16) == "CLEAN"
    assert TCPFlagAnalyzer.inspect("NULL") == "NULL_SCAN"
    assert TCPFlagAnalyzer.inspect("FIN_PSH_URG") == "XMAS_SCAN"

def test_token_bucket():
    bucket = TokenBucketRateLimiter(rate=10.0, capacity=2.0)
    assert bucket.allow() is True
    assert bucket.allow() is True
    assert bucket.allow() is False

    time.sleep(0.25)
    assert bucket.allow() is True

def test_ids_auto_ban():
    ips = IntrusionPreventionSystem(database_manager=None, default_rate=10.0, default_burst=2.0, ban_threshold=3, ban_duration=2)
    test_ip = "198.51.100.99"

    for _ in range(2):
        ips.check_packet(test_ip)

    b1 = ips.record_violation(test_ip, reason="Test Violation 1")
    assert b1 is False

    b2 = ips.record_violation(test_ip, reason="Test Violation 2")
    assert b2 is False

    b3 = ips.record_violation(test_ip, reason="Test Violation 3")
    assert b3 is True

    is_banned, reason, _ = ips.is_ip_banned(test_ip)
    assert is_banned is True

    allowed, status = ips.check_packet(test_ip)
    assert allowed is False
    assert "BANNED" in status

    ips.unban_ip(test_ip)
    is_banned, _, _ = ips.is_ip_banned(test_ip)
    assert is_banned is False

if __name__ == "__main__":
    test_tcp_flag_analyzer()
    test_token_bucket()
    test_ids_auto_ban()
    print("verify_ids_mitigation.py: ALL TESTS PASSED")
