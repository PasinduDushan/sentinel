import os
import re
import subprocess
from datetime import datetime

LOG_FILE = "/opt/sentinel/logs/agent.log"
BLOCK_TTL_SECONDS = int(os.getenv("SENTINEL_BLOCK_TTL_SECONDS", "3600"))
MAX_ACTIVE_BLOCKS = int(os.getenv("SENTINEL_MAX_ACTIVE_BLOCKS", "500"))
SUBNET_BLOCK_TTL_SECONDS = int(os.getenv("SENTINEL_SUBNET_BLOCK_TTL_SECONDS", "1800"))
ESCALATE_ENABLED = os.getenv("SENTINEL_ESCALATE_ENABLED", "1") == "1"
ESCALATE_STRIKES = int(os.getenv("SENTINEL_ESCALATE_STRIKES", "5"))
ESCALATE_WINDOW_SECONDS = int(os.getenv("SENTINEL_ESCALATE_WINDOW_SECONDS", "120"))
ESCALATE_PREFIX = int(os.getenv("SENTINEL_ESCALATE_PREFIX", "24"))
WHITELIST = {
    ip.strip() for ip in os.getenv("SENTINEL_WHITELIST", "").split(",") if ip.strip()
}

blocked = {}
blocked_subnets = {}
strike_history = {}

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

def subnet_for_ip(ip):
    if ESCALATE_PREFIX != 24:
        return None
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return None

def record_strike(ip):
    now_ts = datetime.now().timestamp()
    history = strike_history.setdefault(ip, [])
    history.append(now_ts)
    strike_history[ip] = [t for t in history if now_ts - t <= ESCALATE_WINDOW_SECONDS]
    return len(strike_history[ip])

def maybe_escalate_subnet(ip):
    if not ESCALATE_ENABLED:
        return

    strike_count = record_strike(ip)
    if strike_count < ESCALATE_STRIKES:
        return

    subnet = subnet_for_ip(ip)
    if not subnet:
        return

    if subnet in WHITELIST:
        return

    if subnet in blocked_subnets and ip_is_blocked_in_kernel(subnet):
        blocked_subnets[subnet] = datetime.now().timestamp()
        return

    input_ok, input_msg = ensure_drop_rule("INPUT", subnet)
    docker_ok = True
    docker_msg = "chain-missing"
    if chain_exists("DOCKER-USER"):
        docker_ok, docker_msg = ensure_drop_rule("DOCKER-USER", subnet)

    if not input_ok or not docker_ok:
        log_event(
            f"[Error] Failed subnet escalation for {subnet}: INPUT={input_msg}, DOCKER-USER={docker_msg}"
        )
        return

    blocked_subnets[subnet] = datetime.now().timestamp()
    log_event(
        f"[Escalation] Subnet blocked {subnet} after repeated hits from {ip} "
        f"(strikes={strike_count} in {ESCALATE_WINDOW_SECONDS}s)"
    )

def unblock_subnet(subnet, reason="manual"):
    input_ok, input_msg = remove_drop_rule("INPUT", subnet)

    docker_ok = True
    docker_msg = "chain-missing"
    if chain_exists("DOCKER-USER"):
        docker_ok, docker_msg = remove_drop_rule("DOCKER-USER", subnet)

    blocked_subnets.pop(subnet, None)

    if not input_ok or not docker_ok:
        log_event(
            f"[Error] Failed to unblock subnet {subnet} ({reason}): "
            f"INPUT={input_msg}, DOCKER-USER={docker_msg}"
        )
        return False

    log_event(
        f"[Info] Unblocked subnet {subnet} ({reason}) "
        f"(INPUT={input_msg}, DOCKER-USER={docker_msg})"
    )
    return True

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
            maybe_escalate_subnet(ip)
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
    maybe_escalate_subnet(ip)
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
    if BLOCK_TTL_SECONDS <= 0 and SUBNET_BLOCK_TTL_SECONDS <= 0:
        return 0

    now = datetime.now().timestamp()
    expired_ips = []
    if BLOCK_TTL_SECONDS > 0:
        expired_ips = [ip for ip, ts in blocked.items() if now - ts >= BLOCK_TTL_SECONDS]

    expired_subnets = []
    if SUBNET_BLOCK_TTL_SECONDS > 0:
        expired_subnets = [
            subnet for subnet, ts in blocked_subnets.items()
            if now - ts >= SUBNET_BLOCK_TTL_SECONDS
        ]

    removed = 0
    for ip in expired_ips:
        if unblock_ip(ip, reason=f"ttl-expired-{BLOCK_TTL_SECONDS}s"):
            removed += 1

    for subnet in expired_subnets:
        if unblock_subnet(subnet, reason=f"ttl-expired-{SUBNET_BLOCK_TTL_SECONDS}s"):
            removed += 1

    # Keep strike history bounded.
    if ESCALATE_WINDOW_SECONDS > 0:
        for ip in list(strike_history.keys()):
            history = [t for t in strike_history[ip] if now - t <= ESCALATE_WINDOW_SECONDS]
            if history:
                strike_history[ip] = history
            else:
                strike_history.pop(ip, None)

    return removed