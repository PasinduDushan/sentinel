# Sentinel Architecture

This document explains how Sentinel works from top to bottom, including detection logic, AI warmup behavior, firewall enforcement, and lifecycle management.

## 1) High-level flow

1. Capture traffic events from tcpdump (TCP port 80).
2. Parse and normalize source IP.
3. Track source activity in a rolling 10-second window.
4. Score risk with context plus adaptive anomaly logic.
5. Enforce block in iptables when decision threshold is met.
6. Escalate repeated offenders to subnet block when policy triggers.
7. Periodically cleanup expired rules and stale state.
8. Surface status and health through a local dashboard.
9. Handle management commands (restart/update) in-band.

## 2) Main components

1. [agent/agent.py](../agent/agent.py)
- Main loop, command handling, traffic windows, AI invocation, and logging.

2. [agent/detector.py](../agent/detector.py)
- AdaptiveRiskEngine: context scoring plus online anomaly baseline with warmup.

3. [agent/responder.py](../agent/responder.py)
- Firewall enforcement, stale-rule healing, TTL cleanup, strike tracking, and escalation.

4. [agent/auth_guard.py](../agent/auth_guard.py)
- Access-log-based brute-force login detector.

5. [sentinel-manage.py](../sentinel-manage.py)
- Operational command interface (restart/update/summary).

6. [sentinel.service](../sentinel.service)
- Systemd runtime and environment-driven tuning.

7. [dashboard.py](../dashboard.py)
- Local read-only web dashboard for service health, counters, recent events, and policy visibility.

8. [sentinel-dashboard.service](../sentinel-dashboard.service)
- Systemd unit for the dashboard web UI.

## 3) Detection pipeline details

### 3.1 Capture and parsing

1. Agent consumes tcpdump line stream.
2. IP extraction uses regex-based IPv4 parse.
3. Self/private/local traffic is skipped.

### 3.2 Rolling window model

1. Each source IP stores event timestamps.
2. Old entries outside 10 seconds are removed.
3. List length is capped per source to protect memory.

### 3.3 Adaptive AI risk scoring

Detector computes two major parts:

1. Context score:
- Request ratio over static threshold.
- Repeat offender strike influence.
- Fan-in pressure (many active sources).

2. Anomaly score:
- Online baseline using mean/variance over observed traffic levels.
- z-score anomaly signal against learned baseline.

Final score is weighted blend:

score = (1 - anomaly_weight) * context_score + anomaly_weight * anomaly_score

Decision:

1. During warmup: stricter hard floor based on warmup multiplier.
2. After warmup: block when min score reached or z-score policy triggers.

### 3.4 Auth brute-force guard

1. Reads access log incrementally and handles log rotation.
2. Filters login-related request paths.
3. Counts failed auth statuses in sliding window.
4. Emits block actions when thresholds are exceeded.
5. Supports optional username correlation for distributed brute-force patterns.

## 4) Warmup learning phase

Warmup purpose:

1. Let each server learn its own normal baseline before trusting anomaly-heavy decisions.
2. Reduce false positives from cold start.

Warmup behavior:

1. Samples are collected continuously.
2. In learning mode, stricter fallback threshold is used.
3. Once learning_samples is reached, full AI scoring mode is used.

Important note:

1. Baseline is in-memory in the current implementation.
2. Service restart resets learned baseline.

## 5) Enforcement and firewall logic

When block decision is positive:

1. Insert DROP in INPUT chain at top position.
2. Insert DROP in DOCKER-USER chain when present.
3. Validate kernel rule existence.
4. Log decision and enforcement result.

Why both chains:

1. Container traffic may route through DOCKER-USER/FORWARD path.
2. INPUT-only enforcement can miss Docker-exposed flows.

## 6) Escalation model

1. Strike history tracks repeated hits per IP over a configurable window.
2. If strike threshold is met, agent can block subnet (default /24).
3. Subnet block has independent TTL.

## 7) Cleanup and state consistency

Periodic cleanup does:

1. Unblock expired IP rules.
2. Unblock expired subnet rules.
3. Trim stale strike history.
4. Enforce max active rule cap by evicting oldest blocks.

Stale cache recovery:

1. If manual firewall flush happens, in-memory state may differ.
2. Responder rechecks kernel rules and re-applies block when needed.

## 8) Command and update lifecycle

Command channel:

1. Manager writes command file in /opt/sentinel.
2. Agent polls command file with short interval.
3. Command executes in main agent process context.

Update flow:

1. Agent receives update command.
2. Performs git pull in core path.
3. Writes update status lines.
4. Exits for controlled systemd restart.
5. Marks update complete after restart.

## 9) Dashboard layer

Dashboard purpose:

1. Give operators a live, polished view of Sentinel.
2. Show service health, current policy, and recent incidents.
3. Highlight active DROP rules and top offenders.
4. Provide a safe read-only control plane for demos and day-to-day monitoring.

Access model:

1. Binds to localhost by default.
2. Can be reached securely with SSH port forwarding.
3. Can be exposed only if an operator intentionally changes the bind address.

## 10) Operational interpretation notes

DROP counter increases:

1. Expected when attack source continues sending.
2. Firewall is still dropping packets correctly.

Cloud IP ownership:

1. WHOIS org only identifies range owner.
2. Does not prove attacker identity or intent.

## 11) Runtime tuning strategy

When too strict:

1. Raise AI min score.
2. Raise escalation strikes.
3. Reduce anomaly weight.
4. Shorten TTLs and lower max active blocks.

When too lenient:

1. Lower AI min score slightly.
2. Lower escalation strikes.
3. Increase anomaly weight moderately.
4. Keep whitelist tight and explicit.
