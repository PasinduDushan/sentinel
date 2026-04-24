# Sentinel Operations Runbook

This runbook covers installation, configuration, day-to-day operations, troubleshooting, and complete removal.

## 1) One-shot installation

Use this on a target Linux server (Ubuntu or Debian recommended):

    curl -sSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh | sudo bash

Equivalent one-shot command:

    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh)"

Installer outcome:

1. Installs dependencies: python3, pip, tcpdump, git, curl.
2. Deploys code to /opt/sentinel/core.
3. Creates /opt/sentinel/logs/agent.log.
4. Installs systemd unit /etc/systemd/system/sentinel.service.
5. Seeds runtime config /etc/default/sentinel.
6. Installs manager /opt/sentinel/sentinel-manage.py and symlink /usr/local/bin/sentinel-manage.
7. Installs dashboard /opt/sentinel/dashboard.py and /etc/systemd/system/sentinel-dashboard.service.
8. Enables and starts sentinel.service.
9. Enables and starts sentinel-dashboard.service.

## 2) Important paths

1. Core code: /opt/sentinel/core
2. Service file: /etc/systemd/system/sentinel.service
3. Runtime config: /etc/default/sentinel
4. Logs: /opt/sentinel/logs/agent.log
5. Manager: /opt/sentinel/sentinel-manage.py
6. Manager shortcut: /usr/local/bin/sentinel-manage
7. Dashboard: /opt/sentinel/dashboard.py
8. Dashboard service: /etc/systemd/system/sentinel-dashboard.service

## 3) Day-to-day commands

Service lifecycle:

    sudo systemctl status sentinel.service
    sudo systemctl restart sentinel.service
    sudo systemctl stop sentinel.service
    sudo systemctl start sentinel.service

Manager lifecycle:

    sudo sentinel-manage restart
    sudo sentinel-manage update
    sudo sentinel-manage summary
    sudo sentinel-manage status

Dashboard lifecycle:

    sudo systemctl status sentinel-dashboard.service
    sudo systemctl restart sentinel-dashboard.service
    sudo systemctl stop sentinel-dashboard.service

Recommended secure access:

    ssh -L 8088:127.0.0.1:8088 user@YOUR_SERVER_IP

Then open:

    http://127.0.0.1:8088

If you see `Permission denied (publickey)`, the tunnel syntax is fine but SSH authentication is not. Use the correct login user, install your public key on the server, or connect with the account that already has SSH access.

Logs:

    sudo tail -f /opt/sentinel/logs/agent.log
    sudo tail -n 200 /opt/sentinel/logs/agent.log
    sudo journalctl -u sentinel.service -f

Firewall visibility:

    sudo iptables -L INPUT -n -v --line-numbers
    sudo iptables -L DOCKER-USER -n -v --line-numbers
    sudo iptables -S INPUT
    sudo iptables -S DOCKER-USER

## 4) Runtime config

Edit:

    sudo nano /etc/default/sentinel

Apply:

    sudo systemctl daemon-reload
    sudo systemctl restart sentinel.service

### 4.1 Defaults

1. SENTINEL_BLOCK_TTL_SECONDS=3600
2. SENTINEL_MAX_ACTIVE_BLOCKS=500
3. SENTINEL_WHITELIST=
4. SENTINEL_SUBNET_BLOCK_TTL_SECONDS=1800
5. SENTINEL_ESCALATE_ENABLED=1
6. SENTINEL_ESCALATE_STRIKES=5
7. SENTINEL_ESCALATE_WINDOW_SECONDS=120
8. SENTINEL_ESCALATE_PREFIX=24
9. SENTINEL_AI_ENABLED=1
10. SENTINEL_AI_LEARNING_SAMPLES=300
11. SENTINEL_AI_MIN_BLOCK_SCORE=70
12. SENTINEL_AI_WARMUP_MULTIPLIER=1.7
13. SENTINEL_AI_ANOMALY_WEIGHT=0.35
14. SENTINEL_AI_ZSCORE_BLOCK=3.0
15. SENTINEL_AUTH_GUARD_ENABLED=1
16. SENTINEL_AUTH_LOG_PATH=/var/log/nginx/access.log
17. SENTINEL_AUTH_LOGIN_PATHS=/login,/wp-login.php,/api/auth/login
18. SENTINEL_AUTH_FAIL_STATUSES=401,403,429
19. SENTINEL_AUTH_IP_FAIL_THRESHOLD=10
20. SENTINEL_AUTH_USER_FAIL_THRESHOLD=20
21. SENTINEL_AUTH_WINDOW_SECONDS=300
22. SENTINEL_AUTH_POLL_INTERVAL=1.0
23. SENTINEL_WEB_GUARD_ENABLED=1
24. SENTINEL_WEB_LOG_PATH=/var/log/nginx/access.log
25. SENTINEL_WEB_ATTACK_THRESHOLD=2
26. SENTINEL_WEB_ATTACK_WINDOW_SECONDS=300
27. SENTINEL_WEB_RATE_LIMIT_THRESHOLD=120
28. SENTINEL_WEB_RATE_LIMIT_WINDOW_SECONDS=60
29. SENTINEL_WEB_POLL_INTERVAL=1.0
30. SENTINEL_DASHBOARD_ENABLED=1
31. SENTINEL_DASHBOARD_BIND=127.0.0.1
32. SENTINEL_DASHBOARD_PORT=8088
33. SENTINEL_DASHBOARD_TITLE=Sentinel Dashboard

### 4.2 Recommended starting profile (balanced)

    SENTINEL_BLOCK_TTL_SECONDS=900
    SENTINEL_MAX_ACTIVE_BLOCKS=120
    SENTINEL_WHITELIST=
    SENTINEL_SUBNET_BLOCK_TTL_SECONDS=600
    SENTINEL_ESCALATE_ENABLED=1
    SENTINEL_ESCALATE_STRIKES=10
    SENTINEL_ESCALATE_WINDOW_SECONDS=180
    SENTINEL_ESCALATE_PREFIX=24
    SENTINEL_AI_ENABLED=1
    SENTINEL_AI_LEARNING_SAMPLES=400
    SENTINEL_AI_MIN_BLOCK_SCORE=72
    SENTINEL_AI_WARMUP_MULTIPLIER=1.8
    SENTINEL_AI_ANOMALY_WEIGHT=0.35
    SENTINEL_AI_ZSCORE_BLOCK=3.2
    SENTINEL_AUTH_GUARD_ENABLED=1
    SENTINEL_AUTH_LOG_PATH=/var/log/nginx/access.log
    SENTINEL_AUTH_LOGIN_PATHS=/login,/wp-login.php,/api/auth/login
    SENTINEL_AUTH_FAIL_STATUSES=401,403,429
    SENTINEL_AUTH_IP_FAIL_THRESHOLD=12
    SENTINEL_AUTH_USER_FAIL_THRESHOLD=25
    SENTINEL_AUTH_WINDOW_SECONDS=300
    SENTINEL_AUTH_POLL_INTERVAL=1.0
    SENTINEL_WEB_GUARD_ENABLED=1
    SENTINEL_WEB_LOG_PATH=/var/log/nginx/access.log
    SENTINEL_WEB_ATTACK_THRESHOLD=2
    SENTINEL_WEB_ATTACK_WINDOW_SECONDS=300
    SENTINEL_WEB_RATE_LIMIT_THRESHOLD=120
    SENTINEL_WEB_RATE_LIMIT_WINDOW_SECONDS=60
    SENTINEL_WEB_POLL_INTERVAL=1.0
    SENTINEL_DASHBOARD_ENABLED=1
    SENTINEL_DASHBOARD_BIND=127.0.0.1
    SENTINEL_DASHBOARD_PORT=8088
    SENTINEL_DASHBOARD_TITLE=Sentinel Dashboard

### 4.4 Dashboard

The dashboard is the clean demo surface for leadership and day-to-day ops.

It shows:

1. Sentinel service health.
2. Dashboard service health.
3. Firewall DROP counts.
4. Top offenders by packet counters.
5. Recent AI/auth/escalation events.
6. Runtime policy values.

Default access:

1. Dashboard binds to 127.0.0.1 by default.
2. Use SSH forwarding for secure access.
3. Set SENTINEL_DASHBOARD_BIND only if you explicitly want remote exposure.

### 4.3 Brute-force login protection

Sentinel can now detect login brute-force from access logs and block abusive IPs.

How it works:

1. Tails web access log path from SENTINEL_AUTH_LOG_PATH.
2. Filters requests to configured login path tokens.
3. Counts failed status responses in sliding time window.
4. Blocks source IP if per-IP threshold is exceeded.
5. Optionally correlates username-style query parameters and blocks participating IPs for distributed attempts.

Common setup notes:

1. If you use Apache, set SENTINEL_AUTH_LOG_PATH=/var/log/apache2/access.log.
2. Add your app login endpoints to SENTINEL_AUTH_LOGIN_PATHS.
3. Ensure failed auth responses return one of SENTINEL_AUTH_FAIL_STATUSES.

Dashboard notes:

1. Use SSH tunnel for demo access.
2. If you need a public binding, restrict it with firewall rules.
3. Dashboard is built for operators, not general end users.

## 5) Safe testing

Only test on systems you own or are authorized to test.

Install test tool:

    sudo apt update
    sudo apt install -y apache2-utils

Load test:

    ab -n 1000 -c 50 http://YOUR_SERVER_IP/

Observe reaction:

    sudo tail -f /opt/sentinel/logs/agent.log
    sudo iptables -L INPUT -n -v --line-numbers | grep DROP

## 6) Troubleshooting

No logs:

1. Check service status.
2. Tail /opt/sentinel/logs/agent.log directly.
3. Verify process under systemd.

Rules exist but traffic still appears to pass:

1. Check INPUT and DOCKER-USER chains.
2. Ensure DROP rules are near top.
3. Test fresh connections, not old established sessions.

Too many blocked IPs:

1. Lower SENTINEL_BLOCK_TTL_SECONDS.
2. Lower SENTINEL_SUBNET_BLOCK_TTL_SECONDS.
3. Lower SENTINEL_MAX_ACTIVE_BLOCKS.
4. Increase SENTINEL_ESCALATE_STRIKES.
5. Increase SENTINEL_AI_MIN_BLOCK_SCORE.
6. Add trusted sources to SENTINEL_WHITELIST.

DROP counter keeps increasing:

1. Normal behavior.
2. It means packets still reach host NIC and are dropped by firewall.
3. This indicates blocking is working.

## 7) Complete uninstall

Remove Sentinel completely:

    sudo systemctl stop sentinel.service 2>/dev/null || true
    sudo systemctl disable sentinel.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/sentinel.service
    sudo systemctl daemon-reload
    sudo systemctl reset-failed
    sudo rm -rf /opt/sentinel
    sudo rm -f /usr/local/bin/sentinel-manage
    sudo rm -f /etc/default/sentinel

Optional firewall cleanup:

1. Remove Sentinel-created DROP rules carefully.
2. Avoid blanket flush unless you fully understand your host firewall policy.

## 8) Daily operator checklist

1. Run summary: sudo sentinel-manage summary.
2. Check recent logs.
3. Watch top DROP counters.
4. Tune config if too noisy or too permissive.
5. Update with sudo sentinel-manage update when needed.
