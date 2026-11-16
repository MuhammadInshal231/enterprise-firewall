import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.dpi_engine import DeepPacketInspector
from core.tls_sni import TLSInspector

def test_dpi_signatures():
    dpi = DeepPacketInspector()

    is_threat, threat_type, _ = dpi.inspect_payload("SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin")
    assert is_threat is True
    assert "SQLi" in threat_type

    is_threat, threat_type, _ = dpi.inspect_payload("artist=1' OR '1'='1")
    assert is_threat is True
    assert "SQLi" in threat_type

    is_threat, threat_type, _ = dpi.inspect_payload("search?q=<script>alert(1)</script>")
    assert is_threat is True
    assert "XSS" in threat_type

    is_threat, threat_type, _ = dpi.inspect_payload("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert is_threat is True
    assert "Cleartext Credentials" in threat_type

    is_threat, threat_type, _ = dpi.inspect_domain("example.com")
    assert is_threat is True

    is_threat, threat_type, _ = dpi.inspect_domain("sub.facebook.com")
    assert is_threat is True

    is_threat, threat_type, _ = dpi.inspect_url_path("/admin-panel/login")
    assert is_threat is True

    is_threat, threat_type, _ = dpi.inspect_payload("GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n")
    assert is_threat is False

def test_tls_sni_inspection():
    sni = b"facebook.com"
    sni_ext = struct.pack(">HH", 0, len(sni) + 5) + struct.pack(">H", len(sni) + 3) + b"\x00" + struct.pack(">H", len(sni)) + sni
    exts = struct.pack(">H", len(sni_ext)) + sni_ext
    ch_body = struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x00\x2f" + b"\x01\x00" + exts
    ch_msg = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    record = struct.pack(">BHH", 0x16, 0x0301, len(ch_msg)) + ch_msg

    parsed = TLSInspector.parse_sni(record)
    assert parsed == "facebook.com"

    inspector = TLSInspector()
    blocked, host, _ = inspector.inspect_packet(record)
    assert blocked is True
    assert host == "facebook.com"

if __name__ == "__main__":
    test_dpi_signatures()
    test_tls_sni_inspection()
    print("verify_dpi_signatures.py: ALL TESTS PASSED")

