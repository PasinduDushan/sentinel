import os
import re
import subprocess
from datetime import datetime

LOG_FILE = "/opt/sentinel/logs/agent.log"
BLOCK_TTL_SECONDS = int(os.getenv("SENTINEL_BLOCK_TTL_SECONDS", "3600"))
MAX_ACTIVE_BLOCKS = int(os.getenv("SENTINEL_MAX_ACTIVE_BLOCKS", "500"))
WHITELIST = {
    ip.strip() for ip in os.getenv("SENTINEL_WHITELIST", "").split(",") if ip.strip()
}

blocked = {}

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

def rule_exists(chain, ip):
    return run_iptables(["-C", chain, "-s", ip, "-j", "DROP"]).returncode == 0

def ip_is_blocked_in_kernel(ip):
    if rule_exists("INPUT", ip):
        return True
    if chain_exists("DOCKER-USER") and rule_exists("DOCKER-USER", ip):
        return True
    return False

def remove_drop_rule(chain, ip):
    """Remove DROP rule if present for an IP in a chain."""
    # Delete until rule no longer exists to handle duplicates.
    while rule_exists(chain, ip):
        delete = run_iptables(["-D", chain, "-s", ip, "-j", "DROP"])
        if delete.returncode != 0:
            return False, delete.stderr.strip()
    return True, "removed"

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

    if ip in WHITELIST:
        log_event(f"[Info] {ip} is whitelisted, skipping block")
        return

    if ip in blocked:
        # If rules were flushed manually (e.g. iptables -F), re-apply block.
        if ip_is_blocked_in_kernel(ip):
            blocked[ip] = datetime.now().timestamp()
            return
        blocked.pop(ip, None)
        log_event(f"[Info] Cached block for {ip} was stale; re-applying firewall rules")

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

    blocked[ip] = datetime.now().timestamp()
    log_event(
        f"[✓] Threat neutralized: {ip} blocked (INPUT={input_msg}, DOCKER-USER={docker_msg})"
    )

    # Keep active block list bounded by evicting oldest entries.
    while len(blocked) > MAX_ACTIVE_BLOCKS:
        oldest_ip = min(blocked, key=blocked.get)
        unblock_ip(oldest_ip, reason="max-cap-evict")

def unblock_ip(ip, reason="manual"):
    """Unblock IP from all managed chains and cache."""
    input_ok, input_msg = remove_drop_rule("INPUT", ip)

    docker_ok = True
    docker_msg = "chain-missing"
    if chain_exists("DOCKER-USER"):
        docker_ok, docker_msg = remove_drop_rule("DOCKER-USER", ip)

    blocked.pop(ip, None)

    if not input_ok or not docker_ok:
        log_event(
            f"[Error] Failed to unblock {ip} ({reason}): INPUT={input_msg}, DOCKER-USER={docker_msg}"
        )
        return False

    log_event(
        f"[Info] Unblocked {ip} ({reason}) (INPUT={input_msg}, DOCKER-USER={docker_msg})"
    )
    return True

def cleanup_expired_blocks():
    """Unblock IPs that exceeded TTL; return how many were removed."""
    if BLOCK_TTL_SECONDS <= 0:
        return 0

    now = datetime.now().timestamp()
    expired_ips = [ip for ip, ts in blocked.items() if now - ts >= BLOCK_TTL_SECONDS]

    removed = 0
    for ip in expired_ips:
        if unblock_ip(ip, reason=f"ttl-expired-{BLOCK_TTL_SECONDS}s"):
            removed += 1
    return removed