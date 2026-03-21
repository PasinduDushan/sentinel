import os

blocked = set()

def block_ip(ip):
    if ip in blocked:
        return

    print(f"[Decision Engine] Blocking IP: {ip} using iptables...")
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked.add(ip)
    print("[✓] Threat neutralized\n")