import subprocess
import time
import sys
import os
from datetime import datetime
from collections import defaultdict
import requests
import re
from responder import block_ip

LOG_FILE = "/opt/sentinel/logs/agent.log"

def log_event(message):
    """Write to stdout and directly to the agent log file."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

log_event("[Sentinel] Agent started")

# Command file location
COMMAND_FILE = "/opt/sentinel/command"
CORE_PATH = "/opt/sentinel/core"

def check_command():
    """Check if a command file exists and return its content"""
    if os.path.exists(COMMAND_FILE):
        try:
            with open(COMMAND_FILE, 'r') as f:
                cmd = f.read().strip().lower()
            os.remove(COMMAND_FILE)  # consume the command
            return cmd
        except:
            return None
    return None

def handle_restart():
    """Gracefully restart the agent"""
    log_event("[Sentinel] Restart command received")
    log_event("[Sentinel] Gracefully shutting down")
    time.sleep(1)
    sys.exit(0)  # systemd/supervisor will restart it

def handle_update():
    """Update from GitHub and restart"""
    log_event("[Sentinel] Update command received")
    try:
        log_event("[Sentinel] Pulling latest from GitHub")
        # Git pull in the sentinel core directory
        result = subprocess.run(
            ["git", "-C", CORE_PATH, "pull"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            log_event("[Success] Updated to latest version")
        else:
            log_event(f"[Error] Update failed: {result.stderr.strip()}")
            return
    except Exception as e:
        log_event(f"[Error] Update error: {e}")
        return
    
    log_event("[Sentinel] Restarting after update")
    time.sleep(1)
    sys.exit(0)  # systemd/supervisor will restart it

# get public IP to avoid blocking ourselves
try:
    MY_IP = requests.get("https://api.ipify.org", timeout=2).text
except:
    MY_IP = "127.0.0.1"

traffic = defaultdict(list)
THRESHOLD = 30  # requests in 10s to trigger block
command_check_counter = 0

def extract_ip(part):
    """Extract a valid IPv4 from a string"""
    match = re.search(r"(\d{1,3}\.){3}\d{1,3}", part)
    if match:
        return match.group(0)
    return None

# tcpdump: only TCP + port 80, line buffered
cmd = ["tcpdump", "-i", "eth0", "-n", "-l", "tcp", "and", "port", "80"]
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
            log_event(f"[AI Engine] High traffic detected from {src_ip} ({len(traffic[src_ip])} requests in 10s)")
            log_event(f"[Threat] Potential DDoS attack from {src_ip}")
            log_event(f"[Decision Engine] Blocking IP: {src_ip} using iptables")
            block_ip(src_ip)
            traffic[src_ip] = []

        # Check for commands every 100 iterations (~1 second)
        command_check_counter += 1
        if command_check_counter >= 100:
            cmd = check_command()
            if cmd == "restart":
                handle_restart()
            elif cmd == "update":
                handle_update()
            command_check_counter = 0

        time.sleep(0.01)  # prevent CPU spike

    except Exception as e:
        log_event(f"[Error] {e}")
        continue