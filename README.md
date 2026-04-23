# Sentinel

Sentinel is a lightweight Linux DDoS protection agent that monitors inbound HTTP traffic, applies adaptive local AI scoring, and enforces firewall drops automatically.

## One-shot install

    curl -sSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh | sudo bash

Equivalent one-shot form:

    sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh)"

## Quick commands

    sudo sentinel-manage summary
    sudo sentinel-manage restart
    sudo sentinel-manage update
    sudo tail -f /opt/sentinel/logs/agent.log

## Documentation Index

1. Operations runbook: [docs/OPERATIONS.md](docs/OPERATIONS.md)
2. System internals and logic: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Security note

Use Sentinel only on infrastructure you own or have explicit authorization to protect and test.

Use Sentinel only on infrastructure you own or have explicit authorization to protect and test.
