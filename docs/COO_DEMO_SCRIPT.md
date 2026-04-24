# Sentinel COO Demo Script

Internal use only. Use this as your live talk track and command order.

## 1) One-line pitch

Sentinel is a lightweight, self-contained security agent that watches real traffic, learns normal behavior, and automatically blocks abuse at the firewall before it becomes an outage or compromise.

## 2) Demo order

Follow this order so the story stays clean:

1. Install Sentinel.
2. Verify the service is running.
3. Open the dashboard through SSH tunneling.
4. Show the summary and explain the layers.
5. Explain the AI pieces.
6. Show how to update it.
7. Show how to remove it.
8. Show how to clear firewall rules if needed.

## 3) Installation

Say:

- "This installs Sentinel directly onto the Linux server."
- "It sets up the agent, the dashboard, the logs, and the systemd services."

Run one of these:

```bash
curl -sSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh | sudo bash
```

or:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PasinduDushan/sentinel/refs/heads/main/install.sh)"
```

What to point out after install:

- Sentinel service is enabled and started.
- Dashboard service is enabled and started.
- Logs are created under /opt/sentinel/logs.
- Runtime config is placed in /etc/default/sentinel.

## 4) Status check

Run:

```bash
sudo sentinel-manage summary
```

Say:

- "This is the operator snapshot. It shows the service state, dashboard state, AI settings, web protection, and firewall counters."

Point out:

- Sentinel service state.
- Dashboard service state.
- AI enabled.
- Auth guard enabled.
- Web guard enabled.
- Endpoint AI settings.
- Dashboard URL.
- Input and DOCKER-USER DROP counts.

## 5) Dashboard login

Say:

- "The dashboard binds to localhost by default, so I reach it securely through SSH forwarding."

Use the tunnel command from your laptop:

```bash
ssh -L 8088:127.0.0.1:8088 user@YOUR_SERVER_IP
```

Then open:

```text
http://127.0.0.1:8088
```

If asked why this is secure, say:

- "I am not exposing the dashboard publicly. I am forwarding only the local port through SSH."

## 6) What the dashboard shows

Point out:

- Service health.
- Firewall rule counts.
- Web guard blocks.
- SQLi and XSS hits.
- Rate-limit hits.
- Endpoint AI hits.
- Login abuse settings.
- Recent events.
- Update status.

Say:

- "This gives us an operator view, not just silent blocking."
- "You can see the active policy and the reasons the system is reacting."

## 7) Explain the protection layers

Say this in order:

- "Layer one is network traffic monitoring and firewall blocking."
- "Layer two is login brute-force detection from access logs."
- "Layer three is web attack detection for SQL injection, XSS, and repeated path abuse."
- "Layer four is adaptive scoring that learns baseline behavior instead of relying on one rigid threshold."

## 8) Explain the endpoint-aware AI feature

This is the new unique feature.

Say:

- "Sentinel now learns what each endpoint normally looks like."
- "A login route, a search route, and an API route do not behave the same way, so the scoring should not treat them the same."
- "If a specific path suddenly becomes much hotter than its own baseline, Sentinel can mark it as endpoint-anomalous and block the source."
- "That gives us endpoint-aware adaptive scoring, which is more precise than one global rule."

Use the simple explanation:

- "It learns normal per endpoint, then scores deviations from that endpoint’s own baseline."

If asked why it matters, say:

- "It is smarter, reduces false positives, and sounds advanced because it is actually doing something useful."

## 9) Explain active defense

Say:

- "When Sentinel sees a sustained burst, a suspicious payload, or an endpoint anomaly, it blocks the source at the firewall."
- "That means the server does not waste application resources on clearly abusive traffic."
- "Blocks are temporary and controlled by TTLs."

## 10) Commands to show live

Use these during the demo if needed:

```bash
sudo sentinel-manage summary
sudo sentinel-manage restart
sudo sentinel-manage update
sudo systemctl status sentinel.service
sudo systemctl status sentinel-dashboard.service
sudo journalctl -u sentinel.service -f
sudo journalctl -u sentinel-dashboard.service -f
sudo tail -f /opt/sentinel/logs/agent.log
sudo tail -f /opt/sentinel/logs/dashboard.log
```

If you need firewall visibility:

```bash
sudo iptables -L INPUT -n -v --line-numbers
sudo iptables -L DOCKER-USER -n -v --line-numbers
sudo iptables -S INPUT
sudo iptables -S DOCKER-USER
```

## 11) How to update Sentinel

Say:

- "Updates are handled by the Sentinel manager, which pulls the latest code and restarts the agent cleanly."

Run:

```bash
sudo sentinel-manage update
```

Then explain:

- It pulls from GitHub.
- It syncs runtime service and manager files.
- It restarts the agent.
- It records update status in the log and status file.

## 12) How to remove Sentinel

Say:

- "This is the clean uninstall path."
- "It removes the service, the code, the manager link, and the config."

Run:

```bash
sudo systemctl stop sentinel.service 2>/dev/null || true
sudo systemctl stop sentinel-dashboard.service 2>/dev/null || true
sudo systemctl disable sentinel.service 2>/dev/null || true
sudo systemctl disable sentinel-dashboard.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/sentinel.service
sudo rm -f /etc/systemd/system/sentinel-dashboard.service
sudo systemctl daemon-reload
sudo systemctl reset-failed
sudo rm -rf /opt/sentinel
sudo rm -f /usr/local/bin/sentinel-manage
sudo rm -f /etc/default/sentinel
```

If asked about leftovers, say:

- "The uninstall removes the agent and services, but firewall rules may still exist until we clean them separately."

## 13) How to clear iptables DROP rules

Use this carefully and only if you own the host or are authorized to modify the firewall.

Say:

- "This is only for cleanup or testing. I would not blanket-flush a production firewall without understanding the impact."

To remove Sentinel-style DROP rules from INPUT and DOCKER-USER:

```bash
sudo systemctl stop sentinel.service

for CHAIN in INPUT DOCKER-USER; do
	while sudo iptables -S "$CHAIN" 2>/dev/null | grep -q -- "-j DROP"; do
		RULE=$(sudo iptables -S "$CHAIN" | grep -- "-j DROP" | head -n1 | sed 's/^-A /-D /')
		sudo iptables $RULE
	done
done
```

Verify:

```bash
sudo iptables -L INPUT -n --line-numbers | grep DROP
sudo iptables -L DOCKER-USER -n --line-numbers | grep DROP
```

If you want to clear all rules on a lab box you control, be explicit that this is destructive and should be done only when you fully understand the policy impact.

## 14) Likely COO questions and answers

### "What problem does this solve?"

It reduces the time between attack activity and mitigation. Instead of waiting for manual review, Sentinel blocks abusive sources automatically and gives operators clear visibility.

### "How is it different from a normal firewall?"

A normal firewall is mostly static. Sentinel adds behavior-based scoring, login abuse detection, endpoint-aware web scoring, suspicious request pattern detection, and operational visibility.

### "Will it block legitimate traffic?"

It can if tuned too aggressively, which is why the system is configurable. The point is to start balanced, monitor, and tighten thresholds where needed.

### "Is the AI real?"

Yes, but it is practical AI rather than hype. It learns baseline traffic patterns, endpoint behavior, and anomalies. It is designed to be explainable and lightweight.

### "Can it work without the cloud?"

Yes. The protection logic runs locally. That makes it faster, simpler, and easier to keep under control.

## 15) What to emphasize

- Real-time action.
- Low operational overhead.
- Clear visibility through summary and dashboard.
- Local decision-making.
- Tunable thresholds for real environments.
- Protection beyond DDoS: login abuse, suspicious web requests, and endpoint-aware anomaly detection.

## 16) What not to oversell

- Do not say it replaces a full enterprise SIEM or WAF.
- Do not claim perfect detection.
- Do not say it is an LLM-based autonomous security analyst.
- Do not promise it will stop every attack.

Use this wording instead:

- "It is a focused, practical defense layer that catches common abuse early and acts automatically."
- "It is designed to be useful in the real world, not just impressive in a slide deck."

## 17) Strong demo phrases

- "It learns normal before it trusts itself fully."
- "It blocks at the edge before the app feels the blast radius."
- "It gives us both defense and explanation."
- "This is what practical AI looks like in infrastructure security."
- "It is built to be understandable by operators, not just engineers."
- "It learns per endpoint, not just per host."

## 18) Best next AI upgrade to mention if asked

Say:

- "The next natural step is natural-language incident summaries, where Sentinel turns the block data into a short human-readable incident note."
- "That would make the dashboard even more useful for executives and operators."

## 19) Demo closing line

Sentinel is not just another blocker. It is a practical, explainable, adaptive defense layer that turns live traffic into action and turns raw security noise into something an operator can actually use.
