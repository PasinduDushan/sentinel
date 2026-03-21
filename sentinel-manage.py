#!/usr/bin/env python3
"""
Sentinel Agent Management Script
Allows sending commands to the running agent (restart, update)
"""

import sys
import os

COMMAND_FILE = "/opt/sentinel/command"

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
    
    send_command(cmd)

if __name__ == "__main__":
    main()
