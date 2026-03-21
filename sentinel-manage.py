#!/usr/bin/env python3
"""
Sentinel Agent Management Script
Allows sending commands to the running agent (restart, update)
"""

import sys
import os
import time

COMMAND_FILE = "/opt/sentinel/command"
STATUS_FILE = "/opt/sentinel/update.status"

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
        print("")
        print("Examples:")
        print("  sudo ./sentinel-manage.py restart")
        print("  sudo ./sentinel-manage.py update")
        sys.exit(1)
    
    cmd = sys.argv[1]
    if cmd not in ["restart", "update"]:
        print(f"Unknown command: {cmd}")
        print("Valid commands: restart, update")
        sys.exit(1)
    
    if cmd == "update":
        clear_status_file()
        send_command(cmd)
        sys.exit(wait_for_update_status())

    send_command(cmd)

if __name__ == "__main__":
    main()
