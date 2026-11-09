# CodeAlpha_NetworkIDS
Network intrusion detection with Suricata: custom rules, alert log, auto-response script and dashboard.

## Run the offline demo (Linux / WSL)
    sudo apt install suricata python3-scapy python3-matplotlib
    python3 make_pcap.py
    mkdir -p logs
    suricata -c /etc/suricata/suricata.yaml -S local.rules -r test_traffic.pcap -l logs -k none --set vars.address-groups.HOME_NET="[192.168.1.0/24]"
    python3 auto_response.py logs/eve.json
    python3 dashboard.py

`sample_logs/` holds the output of my test run. `auto_response.py` is dry-run unless `--live` is given.
