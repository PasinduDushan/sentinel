import subprocess
import time
from collections import defaultdict
from detector import detect_ddos
from responder import block_ip

print("[Sentinel] Agent started...")

traffic = defaultdict(list)

cmd = ["tcpdump", "-n", "ip"]

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

while True:
    line = proc.stdout.readline()

    if not line:
        continue

    try:
        parts = line.split()
        src = parts[2]  # source IP
        ip = src.split(".")
        ip = ".".join(ip[:4])  # clean IP

        now = time.time()
        traffic[ip].append(now)

        # keep last 10 seconds only
        traffic[ip] = [t for t in traffic[ip] if now - t < 10]

        if detect_ddos(ip, len(traffic[ip])):
            block_ip(ip)
            traffic[ip] = []

    except:
        continue