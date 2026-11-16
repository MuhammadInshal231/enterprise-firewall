import threading
import time

class StateTable:
    TIMEOUTS = {
        "NEW": 10.0,
        "ESTABLISHED_TCP": 3600.0,
        "ESTABLISHED_UDP": 180.0,
        "ESTABLISHED_ICMP": 30.0,
        "RELATED": 60.0
    }

    def __init__(self):
        self.table = {}
        self.lock = threading.Lock()

    def update_state(self, flow_key, flags=None, packet_bytes=0):
        with self.lock:
            current_time = time.time()
            if isinstance(flow_key, list):
                flow_key = tuple(flow_key)

            reverse_key = (flow_key[1], flow_key[0], flow_key[3], flow_key[2], flow_key[4])
            protocol = str(flow_key[4]).upper()

            if flow_key in self.table:
                entry = self.table[flow_key]
                entry["last_seen"] = current_time
                entry["packets"] = entry.get("packets", 0) + 1
                entry["bytes"] = entry.get("bytes", 0) + packet_bytes

                if flags:
                    flag_upper = str(flags).upper()
                    if "FIN" in flag_upper or "RST" in flag_upper:
                        entry["state"] = "CLOSING"
                    elif entry["state"] == "NEW" and "ACK" in flag_upper:
                        entry["state"] = "ESTABLISHED"
                return entry["state"]

            elif reverse_key in self.table:
                rev_entry = self.table[reverse_key]
                rev_entry["last_seen"] = current_time
                rev_entry["packets"] = rev_entry.get("packets", 0) + 1
                rev_entry["bytes"] = rev_entry.get("bytes", 0) + packet_bytes

                if flags:
                    flag_upper = str(flags).upper()
                    if rev_entry["state"] == "NEW" and ("SYN_ACK" in flag_upper or "SYN-ACK" in flag_upper or "ACK" in flag_upper):
                        rev_entry["state"] = "ESTABLISHED"
                    elif "FIN" in flag_upper or "RST" in flag_upper:
                        rev_entry["state"] = "CLOSING"
                else:
                    if rev_entry["state"] == "NEW":
                        rev_entry["state"] = "ESTABLISHED"
                return rev_entry["state"]

            else:
                initial_state = "NEW"
                if flags:
                    flag_upper = str(flags).upper()
                    if "ACK" in flag_upper and "SYN" not in flag_upper:
                        initial_state = "ESTABLISHED"
                    elif "FIN" in flag_upper or "RST" in flag_upper:
                        initial_state = "CLOSING"

                self.table[flow_key] = {
                    "state": initial_state,
                    "created_at": current_time,
                    "last_seen": current_time,
                    "packets": 1,
                    "bytes": packet_bytes,
                    "protocol": protocol
                }
                return initial_state

    def get_flow_state(self, flow_key):
        with self.lock:
            if isinstance(flow_key, list):
                flow_key = tuple(flow_key)
            if flow_key in self.table:
                return self.table[flow_key]["state"]
            reverse_key = (flow_key[1], flow_key[0], flow_key[3], flow_key[2], flow_key[4])
            if reverse_key in self.table:
                return self.table[reverse_key]["state"]
            return "UNKNOWN"

    def purge_expired(self):
        with self.lock:
            now = time.time()
            to_delete = []
            for flow, data in self.table.items():
                proto = data.get("protocol", "TCP")
                state = data.get("state", "NEW")
                last = data.get("last_seen", now)

                if state == "NEW":
                    timeout = self.TIMEOUTS.get("NEW", 10.0)
                elif state == "ESTABLISHED":
                    if proto == "TCP":
                        timeout = self.TIMEOUTS.get("ESTABLISHED_TCP", 3600.0)
                    elif proto == "UDP":
                        timeout = self.TIMEOUTS.get("ESTABLISHED_UDP", 180.0)
                    elif proto == "ICMP":
                        timeout = self.TIMEOUTS.get("ESTABLISHED_ICMP", 30.0)
                    else:
                        timeout = 300.0
                elif state == "CLOSING":
                    timeout = 10.0
                else:
                    timeout = 30.0

                if now - last > timeout:
                    to_delete.append(flow)

            for flow in to_delete:
                del self.table[flow]

            return len(to_delete)

    def get_active_count(self):
        with self.lock:
            return len(self.table)

    def get_all_sessions(self):
        with self.lock:
            sessions = []
            for flow, data in self.table.items():
                sessions.append({
                    "src_ip": flow[0],
                    "dst_ip": flow[1],
                    "src_port": flow[2],
                    "dst_port": flow[3],
                    "protocol": flow[4],
                    "state": data["state"],
                    "packets": data.get("packets", 0),
                    "bytes": data.get("bytes", 0),
                    "last_seen": data.get("last_seen", 0)
                })
            return sessions

