import json
import os
import struct

class TLSInspector:
    def __init__(self, rules_file_path=None):
        if rules_file_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.rules_file_path = os.path.normpath(os.path.join(base_dir, "config", "rules.json"))
        else:
            self.rules_file_path = os.path.normpath(os.path.abspath(rules_file_path))

    @staticmethod
    def parse_sni(packet_data):
        if not packet_data or len(packet_data) < 5:
            return None
        try:
            content_type, _, _ = struct.unpack(">BHH", packet_data[0:5])
            if content_type != 0x16:
                return None
            offset = 5
            if len(packet_data) < offset + 4:
                return None
            msg_type = packet_data[offset]
            if msg_type != 0x01:
                return None
            offset += 4
            if len(packet_data) < offset + 34:
                return None
            offset += 34
            if len(packet_data) < offset + 1:
                return None
            session_id_len = packet_data[offset]
            offset += 1 + session_id_len
            if len(packet_data) < offset + 2:
                return None
            cipher_suites_len = struct.unpack(">H", packet_data[offset:offset+2])[0]
            offset += 2 + cipher_suites_len
            if len(packet_data) < offset + 1:
                return None
            compression_len = packet_data[offset]
            offset += 1 + compression_len
            if len(packet_data) < offset + 2:
                return None
            extensions_len = struct.unpack(">H", packet_data[offset:offset+2])[0]
            offset += 2
            ext_end = min(offset + extensions_len, len(packet_data))
            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack(">HH", packet_data[offset:offset+4])
                offset += 4
                if ext_type == 0x0000:
                    if offset + 2 > ext_end:
                        return None
                    sni_list_len = struct.unpack(">H", packet_data[offset:offset+2])[0]
                    sni_offset = offset + 2
                    sni_end = min(sni_offset + sni_list_len, ext_end)
                    while sni_offset + 3 <= sni_end:
                        name_type = packet_data[sni_offset]
                        name_len = struct.unpack(">H", packet_data[sni_offset+1:sni_offset+3])[0]
                        sni_offset += 3
                        if name_type == 0:
                            if sni_offset + name_len <= len(packet_data):
                                sni = packet_data[sni_offset:sni_offset+name_len].decode("utf-8", errors="ignore")
                                return sni.lower().strip()
                        sni_offset += name_len
                    return None
                offset += ext_len
        except (struct.error, IndexError, ValueError):
            return None
        return None

    def match_domain(self, sni_host, domains_list):
        if not sni_host:
            return False, ""
        host_clean = sni_host.lower().strip()
        for domain in domains_list:
            d = domain.lower().strip()
            if host_clean == d or host_clean.endswith("." + d):
                return True, d
        return False, ""

    def inspect_packet(self, packet_data):
        sni = self.parse_sni(packet_data)
        if not sni:
            return False, None, ""
        domains = self._load_blacklisted_domains()
        blocked, matched = self.match_domain(sni, domains)
        return blocked, sni, matched

    def _load_blacklisted_domains(self):
        target_path = self.rules_file_path
        if not os.path.exists(target_path) and os.path.exists(target_path + ".example"):
            target_path = target_path + ".example"
        if not os.path.exists(target_path):
            return []
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("blacklisted_domains", [])
        except Exception:
            return []

