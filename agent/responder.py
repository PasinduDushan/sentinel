import os
import re
import subprocess
from datetime import datetime

LOG_FILE = "/opt/sentinel/logs/agent.log"

blocked = set()

def run_iptables(args):
    """Run iptables command and return CompletedProcess."""
    return subprocess.run(["iptables", *args], capture_output=True, text=True)

def ensure_drop_rule(chain, ip):
    """Ensure DROP rule exists at top of given chain."""
    # If already present, treat as success.
    check = run_iptables(["-C", chain, "-s", ip, "-j", "DROP"])
    if check.returncode == 0:
        return True, "already-exists"

    # Insert at top so it is evaluated before broad ACCEPT rules.
    add = run_iptables(["-I", chain, "1", "-s", ip, "-j", "DROP"])
    if add.returncode != 0:
        return False, add.stderr.strip()

    return True, "inserted"

def chain_exists(chain):
    result = run_iptables(["-nL", chain])
    return result.returncode == 0

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

    input_ok, input_msg = ensure_drop_rule("INPUT", ip)

    # Docker-published ports often bypass INPUT and traverse DOCKER-USER/FORWARD.
    docker_ok = True
    docker_msg = "chain-missing"
    if chain_exists("DOCKER-USER"):
        docker_ok, docker_msg = ensure_drop_rule("DOCKER-USER", ip)

    if not input_ok or not docker_ok:
        log_event(
            f"[Error] Failed to block {ip}: INPUT={input_msg}, DOCKER-USER={docker_msg}"
        )
        return

    blocked.add(ip)
    log_event(
        f"[✓] Threat neutralized: {ip} blocked (INPUT={input_msg}, DOCKER-USER={docker_msg})"
    )