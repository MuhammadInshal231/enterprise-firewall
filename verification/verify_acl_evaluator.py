import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.acl_engine import AclEngine, RuleEvaluator

def test_rule_matching():
    evaluator = RuleEvaluator()
    evaluator.add_rule(priority=1, action="DROP", protocol="TCP", source_cidr="10.0.0.0/8", dest_port=80)
    evaluator.add_rule(priority=2, action="ALLOW", protocol="TCP", source_cidr="0.0.0.0/0", dest_port=80)

    pkt1 = {
        "src_ip": "10.0.0.55",
        "dst_ip": "192.168.1.1",
        "dest_port": 80,
        "protocol": "TCP"
    }
    assert evaluator.evaluate(pkt1) == "DROP"

    pkt2 = {
        "src_ip": "172.16.0.5",
        "dst_ip": "192.168.1.1",
        "dest_port": 80,
        "protocol": "TCP"
    }
    assert evaluator.evaluate(pkt2) == "ALLOW"

    pkt3 = {
        "src_ip": "10.0.0.55",
        "dst_ip": "192.168.1.1",
        "dest_port": 443,
        "protocol": "TCP"
    }
    assert evaluator.evaluate(pkt3) == "ALLOW"

def test_management_lockout_failsafe():
    evaluator = RuleEvaluator()
    evaluator.add_rule(priority=1, action="DROP", protocol="TCP", source_cidr="0.0.0.0/0", dest_port=None)

    pkt_ssh = {
        "src_ip": "198.51.100.20",
        "dst_ip": "192.168.1.1",
        "dest_port": 22,
        "protocol": "TCP"
    }
    assert evaluator.evaluate(pkt_ssh) == "ALLOW"

    pkt_dash = {
        "src_ip": "198.51.100.20",
        "dst_ip": "192.168.1.1",
        "dest_port": 8081,
        "protocol": "TCP"
    }
    assert evaluator.evaluate(pkt_dash) == "ALLOW"

def test_input_validation():
    evaluator = RuleEvaluator()
    valid, _ = evaluator.validate_inputs("10.0.0.0/8", "0.0.0.0/0", 80)
    assert valid is True

    valid, _ = evaluator.validate_inputs("999.999.999.999/32", "0.0.0.0/0", 80)
    assert valid is False

    valid, _ = evaluator.validate_inputs("10.0.0.0/8", "0.0.0.0/0", 99999)
    assert valid is False

if __name__ == "__main__":
    test_rule_matching()
    test_management_lockout_failsafe()
    test_input_validation()
    print("verify_acl_evaluator.py: ALL TESTS PASSED")

