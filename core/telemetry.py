import collections
import configparser
import csv
import datetime
import ipaddress
import logging
import logging.handlers
import os
import threading
import time

class GeoIPLookup:
    def __init__(self):
        self.entries = [
            (ipaddress.ip_network("127.0.0.0/8"), {"country": "LOOPBACK", "region": "Local", "city": "Localhost", "asn": "AS0 Local"}),
            (ipaddress.ip_network("10.0.0.0/8"), {"country": "PRIVATE", "region": "LAN", "city": "Private Network", "asn": "AS0 Private"}),
            (ipaddress.ip_network("192.168.0.0/16"), {"country": "PRIVATE", "region": "LAN", "city": "Private Network", "asn": "AS0 Private"}),
            (ipaddress.ip_network("172.16.0.0/12"), {"country": "PRIVATE", "region": "LAN", "city": "Private Network", "asn": "AS0 Private"}),
            (ipaddress.ip_network("8.8.8.0/24"), {"country": "US", "region": "California", "city": "Mountain View", "asn": "AS15169 Google"}),
            (ipaddress.ip_network("8.8.4.0/24"), {"country": "US", "region": "California", "city": "Mountain View", "asn": "AS15169 Google"}),
            (ipaddress.ip_network("1.1.1.0/24"), {"country": "AU", "region": "NSW", "city": "Sydney", "asn": "AS13335 Cloudflare"}),
            (ipaddress.ip_network("1.0.0.0/24"), {"country": "AU", "region": "NSW", "city": "Sydney", "asn": "AS13335 Cloudflare"}),
            (ipaddress.ip_network("93.184.216.0/24"), {"country": "US", "region": "Massachusetts", "city": "Norwell", "asn": "AS15133 EdgeCast"}),
            (ipaddress.ip_network("185.199.108.0/22"), {"country": "US", "region": "California", "city": "San Francisco", "asn": "AS36459 GitHub"}),
            (ipaddress.ip_network("151.101.0.0/16"), {"country": "US", "region": "California", "city": "San Francisco", "asn": "AS54113 Fastly"}),
            (ipaddress.ip_network("20.0.0.0/8"), {"country": "US", "region": "Washington", "city": "Redmond", "asn": "AS8075 Microsoft"}),
            (ipaddress.ip_network("40.0.0.0/8"), {"country": "US", "region": "Washington", "city": "Redmond", "asn": "AS8075 Microsoft"}),
            (ipaddress.ip_network("52.0.0.0/8"), {"country": "US", "region": "Washington", "city": "Redmond", "asn": "AS8075 Microsoft"}),
            (ipaddress.ip_network("198.51.100.0/24"), {"country": "TEST", "region": "Documentation", "city": "TestNet", "asn": "AS0 Test"}),
            (ipaddress.ip_network("203.0.113.0/24"), {"country": "TEST", "region": "Documentation", "city": "TestNet", "asn": "AS0 Test"})
        ]
        self.cache = {}
        self.lock = threading.Lock()

    def lookup(self, ip_str):
        if not ip_str:
            return {"country": "GLOBAL", "region": "Unknown", "city": "Unknown", "asn": "AS-UNKNOWN"}
        with self.lock:
            if ip_str in self.cache:
                return self.cache[ip_str]
        try:
            addr = ipaddress.ip_address(ip_str)
            for net, meta in self.entries:
                if addr in net:
                    with self.lock:
                        self.cache[ip_str] = meta
                    return meta
        except ValueError:
            pass
        fallback = {"country": "GLOBAL", "region": "Unknown", "city": "Unknown", "asn": "AS-UNKNOWN"}
        with self.lock:
            self.cache[ip_str] = fallback
        return fallback

class TelemetryCollector:
    def __init__(self, maxlen=60):
        self.ring_buffer = collections.deque(maxlen=maxlen)
        self.lock = threading.Lock()
        self.current_packets = 0
        self.current_bytes = 0
        self.current_dropped = 0
        self.active_sessions = 0
        self.total_packets = 0
        self.total_bytes = 0
        self.total_dropped = 0
        self.running = True
        self.geo = GeoIPLookup()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def record_packet(self, byte_count, dropped=False):
        with self.lock:
            self.current_packets += 1
            self.current_bytes += byte_count
            self.total_packets += 1
            self.total_bytes += byte_count
            if dropped:
                self.current_dropped += 1
                self.total_dropped += 1

    def set_active_sessions(self, count):
        with self.lock:
            self.active_sessions = count

    def _worker(self):
        while self.running:
            time.sleep(1.0)
            with self.lock:
                item = {
                    "timestamp": int(time.time()),
                    "packets": self.current_packets,
                    "bytes": self.current_bytes,
                    "dropped": self.current_dropped,
                    "active_sessions": self.active_sessions
                }
                self.ring_buffer.append(item)
                self.current_packets = 0
                self.current_bytes = 0
                self.current_dropped = 0

    def get_ring_buffer(self):
        with self.lock:
            return list(self.ring_buffer)

    def get_latest_metrics(self):
        with self.lock:
            latest = self.ring_buffer[-1] if self.ring_buffer else {
                "packets": 0, "bytes": 0, "dropped": 0, "active_sessions": 0
            }
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_dropped": self.total_dropped,
                "active_sessions": self.active_sessions,
                "pps": latest.get("packets", 0),
                "bps": latest.get("bytes", 0),
                "drops_per_sec": latest.get("dropped", 0)
            }

def setup_logger(ini_path=None):
    if ini_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ini_path = os.path.normpath(os.path.join(base_dir, "config", "settings.ini"))
    if not os.path.exists(ini_path) and os.path.exists(ini_path + ".example"):
        ini_path = ini_path + ".example"
    parser = configparser.ConfigParser()
    log_file = "logs/firewall.log"
    max_bytes = 10485760
    backup_count = 5
    if os.path.exists(ini_path):
        try:
            parser.read(ini_path)
            if "logging" in parser:
                log_file = parser["logging"].get("log_file", log_file)
                max_bytes = parser["logging"].getint("max_bytes", max_bytes)
                backup_count = parser["logging"].getint("backup_count", backup_count)
        except Exception:
            pass
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.isabs(log_file):
        full_log_path = os.path.normpath(log_file)
    else:
        parts = log_file.replace("\\", "/").split("/")
        full_log_path = os.path.normpath(os.path.join(base_dir, *parts))
    os.makedirs(os.path.dirname(full_log_path), exist_ok=True)
    logger = logging.getLogger("firewall")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.handlers.RotatingFileHandler(full_log_path, maxBytes=max_bytes, backupCount=backup_count)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

def append_csv_audit(row_dict, csv_path=None):
    if csv_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        csv_path = os.path.normpath(os.path.join(base_dir, "logs", "firewall_audit.csv"))
    else:
        csv_path = os.path.normpath(os.path.abspath(csv_path))
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    fieldnames = [
        "timestamp", "source_ip", "dest_ip", "dest_port", "protocol",
        "action", "threat_category", "rule_triggered", "country", "asn"
    ]
    file_exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        writer.writerow(row_dict)

