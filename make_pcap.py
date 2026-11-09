# Builds a small test capture (test_traffic.pcap) with normal and malicious traffic
from scapy.all import IP, TCP, ICMP, Ether, wrpcap
pkts, t = [], 1700000000.0

def add(p):
    global t
    p.time = t
    t += 0.05
    pkts.append(p)

SERVER = "192.168.1.10"

def http(client, sport, request):
    # full TCP handshake + one HTTP request, so Suricata can parse HTTP
    add(Ether()/IP(src=client, dst=SERVER)/TCP(sport=sport, dport=80, flags="S", seq=100))
    add(Ether()/IP(src=SERVER, dst=client)/TCP(sport=80, dport=sport, flags="SA", seq=500, ack=101))
    add(Ether()/IP(src=client, dst=SERVER)/TCP(sport=sport, dport=80, flags="A", seq=101, ack=501))
    add(Ether()/IP(src=client, dst=SERVER)/TCP(sport=sport, dport=80, flags="PA", seq=101, ack=501)/request.encode())

# Normal traffic (should NOT alert)
http("192.168.1.20", 40001, "GET /index.html HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
# Ping
add(Ether()/IP(src="192.168.1.50", dst=SERVER)/ICMP(type=8))
# Port scan: 15 SYNs to different ports from .66
for port in range(20, 35):
    add(Ether()/IP(src="192.168.1.66", dst=SERVER)/TCP(sport=44444, dport=port, flags="S"))
# SSH brute force: 8 connection attempts from .77
for i in range(8):
    add(Ether()/IP(src="192.168.1.77", dst=SERVER)/TCP(sport=50000+i, dport=22, flags="S"))
# SQL injection
http("192.168.1.88", 41001, "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
# Directory traversal
http("192.168.1.89", 41002, "GET /download?file=../../etc/passwd HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
# sqlmap scanner
http("192.168.1.90", 41003, "GET /login HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: sqlmap/1.7\r\n\r\n")
wrpcap("test_traffic.pcap", pkts)
print("pcap created with", len(pkts), "packets")
