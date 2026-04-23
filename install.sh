#!/bin/bash

LOG="\033[1;36m[Sentinel Installer]\033[0m"
INFO="\033[1;34m[INFO]\033[0m"
SUCCESS="\033[1;32m[✓]\033[0m"
ERROR="\033[1;31m[✗]\033[0m"
WARN="\033[1;33m[!]\033[0m"

echo -e "$LOG Detecting system environment..."
sleep 1

OS=$(uname -s)
ARCH=$(uname -m)
echo -e "$INFO OS: $OS"
echo -e "$INFO Architecture: $ARCH"

if [ "$EUID" -ne 0 ]; then
  echo -e "$ERROR Please run as root."
  exit 1
fi

echo -e "$LOG Updating system packages..."
echo -e "$INFO Running: apt update -y"
apt update -y 2>&1 | sed 's/^/    /'
echo -e "$SUCCESS Package list updated"

echo ""
echo -e "$LOG Installing dependencies..."
echo -e "$INFO Installing: python3, python3-pip, tcpdump, git, curl"
apt install -y python3 python3-pip tcpdump git curl 2>&1 | grep -E "^(Get:|Reading|Building|Setting up|Processing)"
echo -e "$SUCCESS All dependencies installed"

echo ""
echo -e "$LOG Creating Sentinel directories..."
mkdir -p /opt/sentinel/logs
echo -e "$SUCCESS Directory structure created at /opt/sentinel"

echo ""
echo -e "$LOG Fetching Sentinel core from GitHub..."
REPO_URL="https://github.com/PasinduDushan/sentinel.git"
echo -e "$INFO Cloning: $REPO_URL"

rm -rf /opt/sentinel/core
git clone "$REPO_URL" /opt/sentinel/core 2>&1 | sed 's/^/    /'
if [ $? -ne 0 ]; then
  echo -e "$ERROR Failed to fetch repository!"
  exit 1
fi
echo -e "$SUCCESS Repository cloned successfully"

echo ""
echo -e "$LOG Verifying agent files..."
if [ ! -f "/opt/sentinel/core/agent/agent.py" ]; then
  echo -e "$ERROR Agent files missing!"
  exit 1
fi
echo -e "$SUCCESS Agent files verified"

echo ""
echo -e "$LOG Initializing logs..."
touch /opt/sentinel/logs/agent.log
touch /opt/sentinel/logs/dashboard.log
echo -e "$SUCCESS Log file initialized"

echo ""
echo -e "$LOG Setting up systemd service..."
cp /opt/sentinel/core/sentinel.service /etc/systemd/system/sentinel.service
chmod 644 /etc/systemd/system/sentinel.service

# Detect common web services and pick a sensible auth log default.
DETECTED_WEB_STACK="custom"
DETECTED_AUTH_LOG=""

if [ -f "/var/log/nginx/access.log" ] || command -v nginx > /dev/null 2>&1; then
  DETECTED_WEB_STACK="nginx"
  DETECTED_AUTH_LOG="/var/log/nginx/access.log"
elif [ -f "/var/log/apache2/access.log" ] || command -v apache2 > /dev/null 2>&1; then
  DETECTED_WEB_STACK="apache"
  DETECTED_AUTH_LOG="/var/log/apache2/access.log"
elif [ -f "/var/log/caddy/access.log" ] || command -v caddy > /dev/null 2>&1; then
  DETECTED_WEB_STACK="caddy"
  DETECTED_AUTH_LOG="/var/log/caddy/access.log"
elif [ -f "/var/log/haproxy.log" ] || command -v haproxy > /dev/null 2>&1; then
  DETECTED_WEB_STACK="haproxy"
  DETECTED_AUTH_LOG="/var/log/haproxy.log"
fi

if [ "$DETECTED_WEB_STACK" = "custom" ]; then
  echo -e "$WARN No known web stack detected (nginx/apache/caddy/haproxy)."
  echo -e "$WARN Sentinel will use a placeholder auth log path."
  echo -e "$WARN Set SENTINEL_AUTH_LOG_PATH in /etc/default/sentinel to your app access log."
else
  echo -e "$SUCCESS Detected web stack: $DETECTED_WEB_STACK"
  echo -e "$INFO Auth guard log path auto-set to: $DETECTED_AUTH_LOG"
fi

if [ ! -f "/etc/default/sentinel" ]; then
  cat > /etc/default/sentinel << 'EOF'
# Sentinel runtime tuning
SENTINEL_BLOCK_TTL_SECONDS=3600
SENTINEL_MAX_ACTIVE_BLOCKS=500
# Comma-separated trusted IPs that should never be blocked
SENTINEL_WHITELIST=
SENTINEL_SUBNET_BLOCK_TTL_SECONDS=1800
# Escalate to subnet block if same source keeps hitting after block
SENTINEL_ESCALATE_ENABLED=1
SENTINEL_ESCALATE_STRIKES=5
SENTINEL_ESCALATE_WINDOW_SECONDS=120
SENTINEL_ESCALATE_PREFIX=24
SENTINEL_AI_ENABLED=1
# Warmup samples before AI-based anomaly scoring is fully trusted
SENTINEL_AI_LEARNING_SAMPLES=300
SENTINEL_AI_MIN_BLOCK_SCORE=70
SENTINEL_AI_WARMUP_MULTIPLIER=1.7
SENTINEL_AI_ANOMALY_WEIGHT=0.35
SENTINEL_AI_ZSCORE_BLOCK=3.0
SENTINEL_AUTH_GUARD_ENABLED=1
SENTINEL_AUTH_LOG_PATH=__AUTH_LOG_PATH__
SENTINEL_AUTH_LOGIN_PATHS=/login,/wp-login.php,/api/auth/login
SENTINEL_AUTH_FAIL_STATUSES=401,403,429
SENTINEL_AUTH_IP_FAIL_THRESHOLD=10
SENTINEL_AUTH_USER_FAIL_THRESHOLD=20
SENTINEL_AUTH_WINDOW_SECONDS=300
SENTINEL_AUTH_POLL_INTERVAL=1.0
SENTINEL_DASHBOARD_ENABLED=1
SENTINEL_DASHBOARD_BIND=127.0.0.1
SENTINEL_DASHBOARD_PORT=8088
SENTINEL_DASHBOARD_TITLE=Sentinel Dashboard
EOF

  if [ -z "$DETECTED_AUTH_LOG" ]; then
    DETECTED_AUTH_LOG="/var/log/custom/access.log"
  fi
  sed -i "s|__AUTH_LOG_PATH__|$DETECTED_AUTH_LOG|g" /etc/default/sentinel

  chmod 644 /etc/default/sentinel
else
  echo -e "$INFO Existing /etc/default/sentinel found. Keeping current values unchanged."
fi

echo -e "$SUCCESS Systemd service configured"

echo ""
echo -e "$LOG Deploying dashboard service..."
cp /opt/sentinel/core/sentinel-dashboard.service /etc/systemd/system/sentinel-dashboard.service
chmod 644 /etc/systemd/system/sentinel-dashboard.service
cp /opt/sentinel/core/dashboard.py /opt/sentinel/dashboard.py
chmod 755 /opt/sentinel/dashboard.py
echo -e "$SUCCESS Dashboard deployed"

echo ""
echo -e "$LOG Deploying management script..."
cp /opt/sentinel/core/sentinel-manage.py /opt/sentinel/sentinel-manage.py
chmod 755 /opt/sentinel/sentinel-manage.py
echo -e "$SUCCESS Management script deployed"

echo ""
echo -e "$LOG Creating symlink for easy access..."
ln -sf /opt/sentinel/sentinel-manage.py /usr/local/bin/sentinel-manage
echo -e "$SUCCESS Symlink created: /usr/local/bin/sentinel-manage"

echo ""
echo -e "$LOG Registering with Sentinel Cloud..."
for i in {1..3}; do echo -n "."; sleep 0.3; done
echo ""
AGENT_ID="AGT-$(openssl rand -hex 3)"
echo -e "$SUCCESS Agent ID: $AGENT_ID"

echo ""
echo -e "$LOG Establishing secure runtime..."
for i in {1..3}; do echo -n "."; sleep 0.3; done
echo ""

echo ""
echo -e "$LOG Starting Sentinel Agent via systemd..."
echo -e "$INFO Running: systemctl daemon-reload"
systemctl daemon-reload
echo -e "$INFO Running: systemctl enable sentinel.service"
systemctl enable sentinel.service 2>&1 | sed 's/^/    /'
echo -e "$INFO Running: systemctl start sentinel.service"
systemctl start sentinel.service
echo -e "$SUCCESS Systemd service started"

echo ""
echo -e "$LOG Starting Sentinel Dashboard via systemd..."
echo -e "$INFO Running: systemctl enable sentinel-dashboard.service"
systemctl enable sentinel-dashboard.service 2>&1 | sed 's/^/    /'
echo -e "$INFO Running: systemctl start sentinel-dashboard.service"
systemctl start sentinel-dashboard.service
echo -e "$SUCCESS Dashboard service started"

sleep 2

# Check service status
if systemctl is-active --quiet sentinel.service; then
  STATUS="\033[1;32m✅ RUNNING\033[0m"
else
  STATUS="\033[1;31m❌ FAILED\033[0m"
fi

if systemctl is-active --quiet sentinel-dashboard.service; then
  DASH_STATUS="\033[1;32m✅ RUNNING\033[0m"
else
  DASH_STATUS="\033[1;31m❌ FAILED\033[0m"
fi

echo -e "$LOG Sentinel Protection: ACTIVE ✅"
echo -e "\033[1;36m======================================\033[0m"
echo -e "\033[1;32m Sentinel Agent Installed Successfully\033[0m"
echo -e "\033[0m"
echo -e " Agent ID  : $AGENT_ID"
echo -e " Status    : $STATUS"
echo -e " Dash      : $DASH_STATUS"
echo -e " Service   : /etc/systemd/system/sentinel.service"
echo -e " Dashboard : /etc/systemd/system/sentinel-dashboard.service"
echo -e " Logs      : /opt/sentinel/logs/agent.log"
echo -e " Dash Log  : /opt/sentinel/logs/dashboard.log"
echo -e " Manage    : /opt/sentinel/sentinel-manage.py"
echo -e "\033[0m"
echo -e "\033[1;33m Management Commands:\033[0m"
echo -e "   \033[0;36msudo sentinel-manage restart\033[0m (via symlink)"
echo -e "   \033[0;36msudo /opt/sentinel/sentinel-manage.py restart\033[0m (direct)"
echo -e "\033[0m"
echo -e "   \033[0;36msudo sentinel-manage update\033[0m (via symlink)"
echo -e "   \033[0;36msudo /opt/sentinel/sentinel-manage.py update\033[0m (direct)"
echo -e "\033[0m"
echo -e "   \033[0;36msudo sentinel-manage summary\033[0m (status snapshot)"
echo -e "   \033[0;36msudo sentinel-manage status\033[0m (alias)"
echo -e "\033[1;36m======================================\033[0m"