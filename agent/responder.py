import os
import re
import subprocess
from datetime import datetime

LOG_FILE = "/opt/sentinel/logs/agent.log"

blocked = set()

def log_event(message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def block_ip(ip):
    # validate IP format before blocking
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        log_event(f"[Error] Invalid IP: {ip}, skipping block")
        return

    if ip in blocked:
        return

    result = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
    if result.returncode != 0:
        log_event(f"[Error] Failed to block {ip}: {result.stderr.strip()}")
        return

    blocked.add(ip)
    log_event(f"[✓] Threat neutralized: {ip} blocked")