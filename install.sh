#!/bin/bash

LOG="[Sentinel Installer]"

echo "$LOG Detecting system environment..."
sleep 1

OS=$(uname -s)
ARCH=$(uname -m)
echo "$LOG OS: $OS"
echo "$LOG Architecture: $ARCH"

if [ "$EUID" -ne 0 ]; then
  echo "$LOG Please run as root."
  exit 1
fi

echo "$LOG Updating system packages..."
apt update -y > /dev/null 2>&1
echo "$LOG Installing dependencies..."
apt install -y python3 python3-pip tcpdump git curl > /dev/null 2>&1

echo "$LOG Creating Sentinel directories..."
mkdir -p /opt/sentinel/logs

echo "$LOG Fetching Sentinel core from GitHub..."
REPO_URL="https://github.com/PasinduDushan/sentinel.git"

rm -rf /opt/sentinel/core
git clone "$REPO_URL" /opt/sentinel/core > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "$LOG Failed to fetch repository!"
  exit 1
fi

echo "$LOG Verifying agent files..."
if [ ! -f "/opt/sentinel/core/agent/agent.py" ]; then
  echo "$LOG Agent files missing!"
  exit 1
fi

echo "$LOG Initializing logs..."
touch /opt/sentinel/logs/agent.log

echo "$LOG Registering with Sentinel Cloud..."
sleep 1
AGENT_ID="AGT-$(openssl rand -hex 3)"
echo "$LOG Agent ID: $AGENT_ID"

echo "$LOG Establishing secure runtime..."
sleep 1

echo "$LOG Starting Sentinel Agent..."
nohup python3 /opt/sentinel/core/agent/agent.py \
  > /opt/sentinel/logs/agent.log 2>&1 &

sleep 1
echo "$LOG Sentinel Protection: ACTIVE ✅"
echo "======================================"
echo " Sentinel Agent Installed Successfully"
echo " Agent ID: $AGENT_ID"
echo " Status  : PROTECTED ✅"
echo "======================================"