import datetime
import json
import os
import sys

from core.acl_engine import AclEngine, DatabaseManager
from core.ids_engine import IntrusionPreventionSystem
from core.license_manager import LicenseManager

def print_status():
    db = DatabaseManager()
    lm = LicenseManager()
    lic = lm.get_status()
    rules = db.get_rules()
    bans = db.get_active_bans()
    events = db.get_recent_events(limit=5)

    print("==================================================")
    print("      ENTERPRISE FIREWALL CLI ADMINISTRATION      ")
    print("==================================================")
    print(f"Status:            ACTIVE (Version 2.1.0)")
    print(f"License Tier:      {lic['tier']} (Valid: {lic['valid']})")
    print(f"Hardware ID:       {lic['hwid']}")
    print(f"Active ACL Rules:  {len(rules)}")
    print(f"Active IP Bans:    {len(bans)}")
    print("--------------------------------------------------")
    print(f"Recent Events (Last 5):")
    for ev in events:
        print(f"  [{ev['timestamp']}] {ev['source_ip']} -> {ev['dest_ip']}:{ev['dest_port']} | {ev['threat_type']} ({ev['action_taken']})")
    print("==================================================")

def handle_rules(args):
    db = DatabaseManager()
    acl = AclEngine(db)

    if not args or args[0] == "list":
        rules = db.get_rules()
        print(f"{'ID':<4} {'PRIO':<6} {'ACTION':<8} {'PROTO':<6} {'SOURCE CIDR':<18} {'PORT':<8} {'ENABLED':<8}")
        print("-" * 65)
        for r in rules:
            port_str = str(r["dest_port"]) if r["dest_port"] is not None else "ANY"
            print(f"{r['id']:<4} {r['priority']:<6} {r['action']:<8} {r['protocol']:<6} {r['source_cidr']:<18} {port_str:<8} {r['is_enabled']:<8}")

    elif args[0] == "add":
        prio = 100
        action = "ALLOW"
        proto = "TCP"
        cidr = "0.0.0.0/0"
        port = None

        i = 1
        while i < len(args):
            arg = args[i]
            if arg in ("--priority", "-p") and i + 1 < len(args):
                prio = int(args[i+1])
                i += 2
            elif arg in ("--action", "-a") and i + 1 < len(args):
                action = args[i+1].upper()
                i += 2
            elif arg in ("--cidr", "-c") and i + 1 < len(args):
                cidr = args[i+1]
                i += 2
            elif arg in ("--port", "-d") and i + 1 < len(args):
                port = int(args[i+1])
                i += 2
            else:
                if i == 1:
                    prio = int(arg)
                elif i == 2:
                    action = arg.upper()
                elif i == 3:
                    cidr = arg
                elif i == 4:
                    port = int(arg)
                i += 1

        rule_id = acl.add_rule(priority=prio, action=action, protocol=proto, source_cidr=cidr, dest_port=port)
        print(f"Rule added successfully with ID {rule_id} (Priority {prio}, {action} {cidr}:{port or 'ANY'})")

    elif args[0] == "delete":
        if len(args) < 2:
            print("Error: Specify rule ID to delete.")
            return
        rule_id_str = args[1].replace("--id=", "").replace("--id", "")
        if not rule_id_str and len(args) > 2:
            rule_id_str = args[2]
        rule_id = int(rule_id_str)
        success = acl.delete_rule(rule_id)
        if success:
            print(f"Rule ID {rule_id} deleted successfully.")
        else:
            print(f"Rule ID {rule_id} not found.")

def handle_ban(args):
    if not args:
        print("Usage: python cli_admin.py ban <ip> [duration_seconds] [reason]")
        return
    ip = args[0]
    duration = int(args[1]) if len(args) > 1 else 300
    reason = args[2] if len(args) > 2 else "Manual CLI Ban"
    db = DatabaseManager()
    ids = IntrusionPreventionSystem(db)
    ids.ban_ip(ip, duration=duration, reason=reason)
    print(f"IP {ip} banned for {duration} seconds. Reason: {reason}")

def handle_unban(args):
    if not args:
        print("Usage: python cli_admin.py unban <ip>")
        return
    ip = args[0]
    db = DatabaseManager()
    ids = IntrusionPreventionSystem(db)
    ids.unban_ip(ip)
    print(f"IP {ip} unbanned.")

def handle_license(args):
    lm = LicenseManager()
    status = lm.get_status()
    print("==================================================")
    print("           CRYPTOGRAPHIC LICENSE STATUS           ")
    print("==================================================")
    print(f"Valid:        {status['valid']}")
    print(f"Tier:         {status['tier']}")
    print(f"Hardware ID:  {status['hwid']}")
    print(f"Details:      {json.dumps(status['details'], indent=2)}")
    print("==================================================")

def handle_export(args):
    db = DatabaseManager()
    if not args or args[0] == "rules":
        rules = db.get_rules()
        print(json.dumps(rules, indent=2))
    elif args[0] == "logs":
        events = db.get_all_events()
        print("id,timestamp,source_ip,dest_ip,dest_port,threat_type,action_taken,payload_sample")
        for ev in events:
            sample = (ev.get("payload_sample") or "").replace('"', '""')
            print(f'{ev["id"]},"{ev["timestamp"]}","{ev["source_ip"]}","{ev["dest_ip"]}",{ev["dest_port"]},"{ev["threat_type"]}","{ev["action_taken"]}","{sample}"')

def main():
    if len(sys.argv) < 2:
        print_status()
        return

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]

    if cmd == "status":
        print_status()
    elif cmd == "rules":
        handle_rules(args)
    elif cmd == "ban":
        handle_ban(args)
    elif cmd == "unban":
        handle_unban(args)
    elif cmd == "license":
        handle_license(args)
    elif cmd == "export":
        handle_export(args)
    else:
        print(f"Unknown command: {cmd}")
        print("Available commands: status, rules, ban, unban, license, export")

if __name__ == "__main__":
    main()

