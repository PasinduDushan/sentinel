# Sentinel

Sentinel is a lightweight Linux DDoS protection agent that monitors inbound HTTP traffic, applies adaptive local AI scoring, and enforces firewall drops automatically.

It also includes brute-force login protection plus a web-attack guard for suspicious SQL injection, XSS, and per-path burst activity.

## One-shot install

    curl -sSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh | sudo bash

Equivalent one-shot form:

    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh)"

## Quick commands

    sudo sentinel-manage summary
    sudo sentinel-manage restart
    sudo sentinel-manage update
    sudo tail -f /opt/sentinel/logs/agent.log

Dashboard service:

    sudo systemctl status sentinel-dashboard.service
    sudo systemctl restart sentinel-dashboard.service

Secure access for local demo:

    ssh -L 8088:127.0.0.1:8088 user@YOUR_SERVER_IP
    http://127.0.0.1:8088

Use a real SSH account that already has key-based access on the server. If root login is disabled, connect as your normal sudo user instead of `root`.

## Documentation Index

1. Operations runbook: [docs/OPERATIONS.md](docs/OPERATIONS.md)
2. System internals and logic: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Security note

Use Sentinel only on infrastructure you own or have explicit authorization to protect and test.
