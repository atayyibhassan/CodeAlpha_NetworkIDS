# auto_response.py - simple intrusion response for Suricata alerts
# Reads Suricata's eve.json log, counts alerts per attacker IP, and blocks
# an IP with iptables when it reaches BLOCK_THRESHOLD alerts.
# DRY_RUN = True only PRINTS the command, so it is safe to test.

import json
import subprocess
import sys
import time

EVE_FILE = sys.argv[1] if len(sys.argv) > 1 else "logs/eve.json"
FOLLOW = "--follow" in sys.argv          # keep watching the file (live monitoring)
BLOCK_THRESHOLD = 1                      # alerts before blocking an IP
DRY_RUN = "--live" not in sys.argv       # pass --live to really run iptables
WHITELIST = {"192.168.1.1", "192.168.1.10"}   # never block gateway or our own server

alert_count = {}      # source IP -> number of alerts
blocked = set()       # IPs already blocked


def block_ip(ip):
    """Block an IP address using iptables (Linux, needs root)."""
    command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    if DRY_RUN:
        print("   [DRY RUN] would run:", " ".join(command))
    else:
        subprocess.run(command, check=False)
    blocked.add(ip)


def handle_line(line):
    """Process one JSON line from eve.json."""
    try:
        event = json.loads(line)
    except ValueError:
        return                                   # skip broken lines
    if event.get("event_type") != "alert":
        return                                   # we only care about alerts

    ip = event["src_ip"]
    signature = event["alert"]["signature"]
    alert_count[ip] = alert_count.get(ip, 0) + 1
    print(f"ALERT: {signature}  from {ip}  (alerts from this IP: {alert_count[ip]})")

    if ip in WHITELIST or ip in blocked:
        return
    if alert_count[ip] >= BLOCK_THRESHOLD:
        print(f"-> RESPONSE: blocking {ip}")
        block_ip(ip)


def main():
    with open(EVE_FILE) as f:
        for line in f:                            # read existing alerts
            handle_line(line)
        while FOLLOW:                             # then wait for new ones
            line = f.readline()
            if line:
                handle_line(line)
            else:
                time.sleep(1)
    print(f"\nFinished. Blocked IPs: {sorted(blocked)}")


main()
