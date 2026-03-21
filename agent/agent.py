import subprocess
import time
from collections import defaultdict
import socket
import requests
from responder import block_ip

print("[Sentinel] Agent started...")

# get public IP to avoid blocking ourselves
try:
    MY_IP = requests.get("https://api.ipify.org", timeout=2).text
except:
    MY_IP = "127.0.0.1"

traffic = defaultdict(list)
THRESHOLD = 30  # requests in 10s to trigger block

# safer tcpdump: only TCP + port 80 (HTTP)
cmd = ["tcpdump", "-i", "any", "-n", "-l", "tcp", "and", "port", "80"]

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

while True:
    line = proc.stdout.readline()
    if not line:
        time.sleep(0.01)
        continue

    try:
        parts = line.split()
        src = parts[2]  # source IP
        ip = src.split(".")[0:4]
        ip = ".".join(ip)

        # skip self IPs / localhost / private ranges
        if ip == MY_IP or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            continue

        now = time.time()
        traffic[ip].append(now)

        # keep last 10 seconds only
        traffic[ip] = [t for t in traffic[ip] if now - t < 10]

        # cap traffic list to prevent memory overflow
        if len(traffic[ip]) > 200:
            traffic[ip] = traffic[ip][-200:]

        # detection logic
        if len(traffic[ip]) >= THRESHOLD:
            print(f"[AI Engine] High traffic detected from {ip} ({len(traffic[ip])} requests in 10s)")
            print(f"[Threat] Potential DDoS attack from {ip}")
            block_ip(ip)
            traffic[ip] = []

        # slight sleep to prevent CPU spike
        time.sleep(0.01)

    except Exception as e:
        # just log, don’t crash
        print(f"[Error] {e}")
        continue