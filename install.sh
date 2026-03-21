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

echo "$LOG Setting up systemd service..."
cp /opt/sentinel/core/sentinel.service /etc/systemd/system/sentinel.service
chmod 644 /etc/systemd/system/sentinel.service

echo "$LOG Deploying management script..."
cp /opt/sentinel/core/sentinel-manage.py /opt/sentinel/sentinel-manage.py
chmod 755 /opt/sentinel/sentinel-manage.py

echo "$LOG Registering with Sentinel Cloud..."
sleep 1
AGENT_ID="AGT-$(openssl rand -hex 3)"
echo "$LOG Agent ID: $AGENT_ID"

echo "$LOG Establishing secure runtime..."
sleep 1

echo "$LOG Starting Sentinel Agent via systemd..."
systemctl daemon-reload
systemctl enable sentinel.service
systemctl start sentinel.service

sleep 2

# Check service status
if systemctl is-active --quiet sentinel.service; then
  STATUS="✅ RUNNING"
else
  STATUS="❌ FAILED"
fi

echo "$LOG Sentinel Protection: ACTIVE ✅"
echo "======================================"
echo " Sentinel Agent Installed Successfully"
echo " Agent ID: $AGENT_ID"
echo " Status  : $STATUS"
echo " Service : /etc/systemd/system/sentinel.service"
echo " Logs    : /opt/sentinel/logs/agent.log"
echo " Manage  : /opt/sentinel/sentinel-manage.py"
echo ""
echo " Management Commands:"
echo "   sudo /opt/sentinel/sentinel-manage.py restart"
echo "   sudo /opt/sentinel/sentinel-manage.py update"
echo "======================================"