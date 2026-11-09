# dashboard.py - draws a simple dashboard (PNG) from Suricata's eve.json
import json
import matplotlib
matplotlib.use("Agg")          # draw to a file, no window needed
import matplotlib.pyplot as plt

by_signature, by_source = {}, {}
with open("logs/eve.json") as f:
    for line in f:
        e = json.loads(line)
        if e.get("event_type") == "alert":
            sig = e["alert"]["signature"].replace("LOCAL ", "")
            by_signature[sig] = by_signature.get(sig, 0) + 1
            by_source[e["src_ip"]] = by_source.get(e["src_ip"], 0) + 1

fig, (a1, a2) = plt.subplots(1, 2, figsize=(12, 5))
a1.barh(list(by_signature.keys()), list(by_signature.values()), color="#c62828")
a1.set_title("Alerts by attack type")
a1.set_xlabel("Number of alerts")
a2.bar(list(by_source.keys()), list(by_source.values()), color="#2457d6")
a2.set_title("Alerts by attacker IP")
a2.set_ylabel("Number of alerts")
plt.setp(a2.get_xticklabels(), rotation=45, ha="right")
plt.tight_layout()
plt.savefig("ids_dashboard.png", dpi=110)
print("Saved ids_dashboard.png")
