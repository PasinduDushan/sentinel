#!/usr/bin/env python3
"""
Sentinel Agent Management Script
Allows sending commands to the running agent (restart, update)
"""

import sys
import os
import time
import subprocess

COMMAND_FILE = "/opt/sentinel/command"
STATUS_FILE = "/opt/sentinel/update.status"
DEFAULT_CONFIG_FILE = "/etc/default/sentinel"

def run_command(cmd):
    """Run shell command and return (rc, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)

def read_runtime_config():
    """Read runtime settings from /etc/default/sentinel with fallbacks."""
    config = {
        "SENTINEL_BLOCK_TTL_SECONDS": "3600",
        "SENTINEL_MAX_ACTIVE_BLOCKS": "500",
        "SENTINEL_WHITELIST": "",
        "SENTINEL_SUBNET_BLOCK_TTL_SECONDS": "1800",
        "SENTINEL_ESCALATE_ENABLED": "1",
        "SENTINEL_ESCALATE_STRIKES": "5",
        "SENTINEL_ESCALATE_WINDOW_SECONDS": "120",
        "SENTINEL_ESCALATE_PREFIX": "24",
        "SENTINEL_AI_ENABLED": "1",
        "SENTINEL_AI_LEARNING_SAMPLES": "300",
        "SENTINEL_AI_MIN_BLOCK_SCORE": "70",
        "SENTINEL_AI_WARMUP_MULTIPLIER": "1.7",
        "SENTINEL_AI_ANOMALY_WEIGHT": "0.35",
        "SENTINEL_AI_ZSCORE_BLOCK": "3.0",
    }

    if not os.path.exists(DEFAULT_CONFIG_FILE):
        return config

    try:
        with open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key in config:
                    config[key] = value
    except Exception:
        pass

    return config

def count_drop_rules(chain):
    """Count source-IP drop rules in a chain."""
    rc, out, _ = run_command(["iptables", "-S", chain])
    if rc != 0:
        return None

    count = 0
    for line in out.splitlines():
        if " -s " in line and " -j DROP" in line:
            count += 1
    return count

def show_summary():
    """Print one-shot Sentinel status summary."""
    print("Sentinel Summary")
    print("================")

    rc_active, active_out, active_err = run_command(["systemctl", "is-active", "sentinel.service"])
    rc_enabled, enabled_out, enabled_err = run_command(["systemctl", "is-enabled", "sentinel.service"])

    service_state = active_out if rc_active == 0 else (active_out or active_err or "unknown")
    service_enabled = enabled_out if rc_enabled == 0 else (enabled_out or enabled_err or "unknown")

    print(f"Service state    : {service_state}")
    print(f"Service enabled  : {service_enabled}")

    config = read_runtime_config()
    print(f"Block TTL (sec)  : {config['SENTINEL_BLOCK_TTL_SECONDS']}")
    print(f"Subnet TTL (sec) : {config['SENTINEL_SUBNET_BLOCK_TTL_SECONDS']}")
    print(f"Max active blocks: {config['SENTINEL_MAX_ACTIVE_BLOCKS']}")
    print(f"Escalation       : {config['SENTINEL_ESCALATE_ENABLED']}")
    print(f"Escalate strikes : {config['SENTINEL_ESCALATE_STRIKES']}")
    print(f"Escalate window  : {config['SENTINEL_ESCALATE_WINDOW_SECONDS']}")
    print(f"Escalate prefix  : /{config['SENTINEL_ESCALATE_PREFIX']}")
    print(f"AI enabled       : {config['SENTINEL_AI_ENABLED']}")
    print(f"AI warmup samples: {config['SENTINEL_AI_LEARNING_SAMPLES']}")
    print(f"AI min score     : {config['SENTINEL_AI_MIN_BLOCK_SCORE']}")
    print(f"AI warmup x-th   : {config['SENTINEL_AI_WARMUP_MULTIPLIER']}")
    print(f"AI anomaly weight: {config['SENTINEL_AI_ANOMALY_WEIGHT']}")
    print(f"AI zscore block  : {config['SENTINEL_AI_ZSCORE_BLOCK']}")
    print(f"Whitelist        : {config['SENTINEL_WHITELIST'] or '(empty)'}")

    input_drop_count = count_drop_rules("INPUT")
    docker_drop_count = count_drop_rules("DOCKER-USER")

    input_text = str(input_drop_count) if input_drop_count is not None else "n/a"
    docker_text = str(docker_drop_count) if docker_drop_count is not None else "n/a"

    print(f"INPUT DROP rules : {input_text}")
    print(f"DOCKER-USER DROP : {docker_text}")
    print("Logs             : /opt/sentinel/logs/agent.log")

def send_command(cmd):
    """Send a command to the agent"""
    if not os.access("/opt/sentinel", os.W_OK):
        print("Error: You need root privileges to manage Sentinel")
        sys.exit(1)
    
    try:
        with open(COMMAND_FILE, 'w') as f:
            f.write(cmd.lower())
        print(f"✓ Command sent: {cmd}")
        print(f"  Agent will execute this within ~1 second")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def clear_status_file():
    """Remove old status file so only fresh update statuses are displayed."""
    if os.path.exists(STATUS_FILE):
        try:
            os.remove(STATUS_FILE)
        except Exception:
            pass

def read_last_status_line():
    if not os.path.exists(STATUS_FILE):
        return None
    try:
        with open(STATUS_FILE, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        if not lines:
            return None
        return lines[-1]
    except Exception:
        return None

def wait_for_update_status(timeout_seconds=180):
    """Show live update progress and return non-zero on failure/timeout."""
    print("Waiting for update progress...")
    start = time.time()
    last_printed = None

    while (time.time() - start) < timeout_seconds:
        status_line = read_last_status_line()
        if status_line and status_line != last_printed:
            print(f"  {status_line}")
            last_printed = status_line

            if "UPDATE_ERROR" in status_line:
                print("✗ Update failed")
                return 1
            if "UPDATE_COMPLETE" in status_line:
                print("✓ Update completed successfully")
                return 0

        time.sleep(1)

    print("✗ Timed out waiting for update status")
    print("  Check logs: sudo tail -f /opt/sentinel/logs/agent.log")
    return 1

def main():
    if len(sys.argv) < 2:
        print("Usage: sentinel-manage.py <command>")
        print("")
        print("Commands:")
        print("  restart    - Gracefully restart the agent")
        print("  update     - Pull latest from GitHub and restart")
        print("  summary    - Show service/runtime/block summary")
        print("  status     - Alias of summary")
        print("")
        print("Examples:")
        print("  sudo ./sentinel-manage.py restart")
        print("  sudo ./sentinel-manage.py update")
        print("  sudo ./sentinel-manage.py summary")
        sys.exit(1)
    
    cmd = sys.argv[1]
    if cmd not in ["restart", "update", "summary", "status"]:
        print(f"Unknown command: {cmd}")
        print("Valid commands: restart, update, summary, status")
        sys.exit(1)

    if cmd in ["summary", "status"]:
        show_summary()
        return
    
    if cmd == "update":
        clear_status_file()
        send_command(cmd)
        sys.exit(wait_for_update_status())

    send_command(cmd)

if __name__ == "__main__":
    main()
