import subprocess
import time
from collections import defaultdict
import requests
import re
from responder import block_ip

print("\033[1;36m[Sentinel] Agent started...\033[0m")

# get public IP to avoid blocking ourselves
try:
    MY_IP = requests.get("https://api.ipify.org", timeout=2).text
except:
    MY_IP = "127.0.0.1"

traffic = defaultdict(list)
THRESHOLD = 30  # requests in 10s to trigger block

def extract_ip(part):
    """Extract a valid IPv4 from a string"""
    match = re.search(r"(\d{1,3}\.){3}\d{1,3}", part)
    if match:
        return match.group(0)
    return None

# tcpdump: only TCP + port 80, line buffered
cmd = ["tcpdump", "-i", "any", "-n", "-l", "tcp", "and", "port", "80"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

while True:
    line = proc.stdout.readline()
    if not line:
        time.sleep(0.01)
        continue

    try:
        parts = line.split()
        if len(parts) < 3:
            continue

        src_ip = extract_ip(parts[2])
        if not src_ip:
            continue  # skip invalid tokens like In/Out

        # skip self / localhost / private IPs
        if src_ip == MY_IP or src_ip.startswith(("127.", "192.168.", "10.")):
            continue

        now = time.time()
        traffic[src_ip].append(now)
        traffic[src_ip] = [t for t in traffic[src_ip] if now - t < 10]

        # cap to prevent memory overflow
        if len(traffic[src_ip]) > 200:
            traffic[src_ip] = traffic[src_ip][-200:]

        # detection logic
        if len(traffic[src_ip]) >= THRESHOLD:
            print(f"\n\033[1;33m[AI Engine]\033[0m High traffic detected from {src_ip} ({len(traffic[src_ip])} requests in 10s)")
            print(f"\033[1;31m[Threat]\033[0m Potential DDoS attack from {src_ip}")
            print(f"\033[1;34m[Decision Engine]\033[0m Blocking IP: {src_ip} using iptables...\n")
            block_ip(src_ip)
            traffic[src_ip] = []

        time.sleep(0.01)  # prevent CPU spike

    except Exception as e:
        print(f"[Error] {e}")
        continue