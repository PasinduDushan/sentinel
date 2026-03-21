import os
import re

blocked = set()

def block_ip(ip):
    # validate IP format before blocking
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        print(f"[Error] Invalid IP: {ip}, skipping block")
        return

    if ip in blocked:
        return

    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked.add(ip)
    print(f"[✓] Threat neutralized: {ip} blocked\n")