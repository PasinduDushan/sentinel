import subprocess
import time
import sys
import os
from collections import defaultdict
import requests
import re
from responder import block_ip

print("\033[1;36m[Sentinel] Agent started...\033[0m")

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
    print("\033[1;36m[Sentinel] Restart command received...\033[0m")
    sys.stdout.flush()
    print("\033[1;36m[Sentinel] Gracefully shutting down...\033[0m")
    sys.stdout.flush()
    time.sleep(1)
    sys.exit(0)  # systemd/supervisor will restart it

def handle_update():
    """Update from GitHub and restart"""
    print("\033[1;36m[Sentinel] Update command received...\033[0m")
    sys.stdout.flush()
    try:
        print("\033[1;36m[Sentinel] Pulling latest from GitHub...\033[0m")
        sys.stdout.flush()
        # Git pull in the sentinel core directory
        result = subprocess.run(
            ["git", "-C", CORE_PATH, "pull"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            print(f"\033[1;32m[Success] Updated to latest version\033[0m")
            sys.stdout.flush()
        else:
            print(f"\033[1;31m[Error] Update failed: {result.stderr}\033[0m")
            sys.stdout.flush()
            return
    except Exception as e:
        print(f"\033[1;31m[Error] Update error: {e}\033[0m")
        sys.stdout.flush()
        return
    
    print("\033[1;36m[Sentinel] Restarting after update...\033[0m")
    sys.stdout.flush()
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
            print(f"\n\033[1;33m[AI Engine]\033[0m High traffic detected from {src_ip} ({len(traffic[src_ip])} requests in 10s)")
            sys.stdout.flush()
            print(f"\033[1;31m[Threat]\033[0m Potential DDoS attack from {src_ip}")
            sys.stdout.flush()
            print(f"\033[1;34m[Decision Engine]\033[0m Blocking IP: {src_ip} using iptables...\n")
            sys.stdout.flush()
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
        print(f"[Error] {e}")
        continue