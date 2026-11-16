import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.spi_state import StateTable

def test_state_transitions():
    tracker = StateTable()
    flow = ("10.0.0.1", "192.168.1.1", 45000, 80, "TCP")

    st1 = tracker.update_state(flow, flags="SYN")
    assert st1 == "NEW"
    assert tracker.get_flow_state(flow) == "NEW"

    st2 = tracker.update_state(flow, flags="ACK")
    assert st2 == "ESTABLISHED"
    assert tracker.get_flow_state(flow) == "ESTABLISHED"

    rev_flow = ("192.168.1.1", "10.0.0.1", 80, 45000, "TCP")
    st3 = tracker.update_state(rev_flow, flags="ACK")
    assert st3 == "ESTABLISHED"

def test_purge_expired():
    tracker = StateTable()
    tracker.TIMEOUTS["NEW"] = 0.05
    flow = ("10.0.0.2", "192.168.1.1", 50000, 80, "TCP")
    tracker.update_state(flow, flags="SYN")
    assert tracker.get_active_count() == 1

    time.sleep(0.1)
    purged = tracker.purge_expired()
    assert purged == 1
    assert tracker.get_active_count() == 0

if __name__ == "__main__":
    test_state_transitions()
    test_purge_expired()
    print("verify_spi_engine.py: ALL TESTS PASSED")

