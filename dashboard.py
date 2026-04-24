#!/usr/bin/env python3
"""Sentinel dashboard web UI."""

import html
import json
import os
import re
import subprocess
from collections import Counter
from datetime import datetime

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TITLE = os.getenv("SENTINEL_DASHBOARD_TITLE", "Sentinel Dashboard")
BIND = os.getenv("SENTINEL_DASHBOARD_BIND", "127.0.0.1")
PORT = int(os.getenv("SENTINEL_DASHBOARD_PORT", "8088"))
LOG_FILE = "/opt/sentinel/logs/agent.log"
STATUS_FILE = "/opt/sentinel/update.status"
DEFAULT_CONFIG_FILE = "/etc/default/sentinel"
SERVICE_NAME = "sentinel.service"
DASHBOARD_SERVICE_NAME = "sentinel-dashboard.service"
MAX_RECENT_EVENTS = 18
MAX_TOP_RULES = 12
MAX_STATUS_LINES = 10


def run_command(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout or "", result.stderr or ""
    except Exception as exc:
        return 1, "", str(exc)


def read_runtime_config():
    config = {
        "SENTINEL_BLOCK_TTL_SECONDS": "3600",
        "SENTINEL_MAX_ACTIVE_BLOCKS": "500",
        "SENTINEL_WHITELIST": "",
        "SENTINEL_SUBNET_BLOCK_TTL_SECONDS": "1800",
        "SENTINEL_ESCALATE_ENABLED": "1",
        "SENTINEL_ESCALATE_STRIKES": "5",
        "SENTINEL_ESCALATE_WINDOW_SECONDS": "120",
        "SENTINEL_ESCALATE_PREFIX": "24",
        "SENTINEL_AI_ENABLED": "1",
        "SENTINEL_AI_LEARNING_SAMPLES": "300",
        "SENTINEL_AI_MIN_BLOCK_SCORE": "70",
        "SENTINEL_AI_WARMUP_MULTIPLIER": "1.7",
        "SENTINEL_AI_ANOMALY_WEIGHT": "0.35",
        "SENTINEL_AI_ZSCORE_BLOCK": "3.0",
        "SENTINEL_AUTH_GUARD_ENABLED": "1",
        "SENTINEL_AUTH_LOG_PATH": "/var/log/nginx/access.log",
        "SENTINEL_AUTH_LOGIN_PATHS": "/login,/wp-login.php,/api/auth/login",
        "SENTINEL_AUTH_FAIL_STATUSES": "401,403,429",
        "SENTINEL_AUTH_IP_FAIL_THRESHOLD": "10",
        "SENTINEL_AUTH_USER_FAIL_THRESHOLD": "20",
        "SENTINEL_AUTH_WINDOW_SECONDS": "300",
        "SENTINEL_AUTH_POLL_INTERVAL": "1.0",
        "SENTINEL_DASHBOARD_ENABLED": "1",
        "SENTINEL_DASHBOARD_BIND": BIND,
        "SENTINEL_DASHBOARD_PORT": str(PORT),
    }

    if not os.path.exists(DEFAULT_CONFIG_FILE):
        return config

    try:
        with open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key in config:
                    config[key] = value
    except Exception:
        pass

    return config


def systemd_state(service):
    active_rc, active_out, active_err = run_command(["systemctl", "is-active", service])
    enabled_rc, enabled_out, enabled_err = run_command(["systemctl", "is-enabled", service])
    return {
        "active": active_out.strip() if active_rc == 0 else (active_out.strip() or active_err.strip() or "unknown"),
        "enabled": enabled_out.strip() if enabled_rc == 0 else (enabled_out.strip() or enabled_err.strip() or "unknown"),
    }


def read_tail_lines(path, limit=MAX_RECENT_EVENTS):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return [line.rstrip("\n") for line in lines[-limit:]]
    except Exception:
        return []


def read_status_lines(limit=MAX_STATUS_LINES):
    return read_tail_lines(STATUS_FILE, limit)


def parse_drop_rules(chain):
    rc, out, err = run_command(["iptables", "-L", chain, "-n", "-v", "--line-numbers"])
    if rc != 0:
        return []

    rows = []
    for raw in out.splitlines():
        line = raw.strip()
        if not line or "DROP" not in line:
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        if not parts[0].isdigit():
            continue
        row = {
            "line": parts[0],
            "pkts": parts[1],
            "bytes": parts[2],
            "source": parts[8],
            "destination": parts[9],
            "raw": line,
        }
        rows.append(row)
    return rows


def normalize_bytes(value):
    try:
        value = float(value)
    except Exception:
        return value
    suffixes = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while value >= 1024 and idx < len(suffixes) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)} {suffixes[idx]}"
    return f"{value:.1f} {suffixes[idx]}"


def top_offenders(rows):
    offender_map = {}
    for row in rows:
        source = row["source"]
        current_pkts = 0
        current_bytes = 0
        try:
            current_pkts = int(row["pkts"])
        except Exception:
            current_pkts = 0
        try:
            current_bytes = int(row["bytes"])
        except Exception:
            current_bytes = 0

        if source not in offender_map:
            offender_map[source] = {
                "source": source,
                "pkts": current_pkts,
                "bytes": current_bytes,
                "hits": 1,
            }
        else:
            offender_map[source]["hits"] += 1
            offender_map[source]["pkts"] = max(offender_map[source]["pkts"], current_pkts)
            offender_map[source]["bytes"] = max(offender_map[source]["bytes"], current_bytes)

    sorted_rows = sorted(offender_map.values(), key=lambda item: (item["pkts"], item["bytes"]), reverse=True)
    return sorted_rows[:MAX_TOP_RULES]


BLOCK_EVENT_PATTERNS = [
    re.compile(r"Blocking IP: (?P<ip>\S+)", re.IGNORECASE),
    re.compile(r"Threat neutralized: (?P<ip>\S+) blocked", re.IGNORECASE),
    re.compile(r"Auth Guard\].*Blocking (?P<ip>\S+)", re.IGNORECASE),
    re.compile(r"Subnet blocked (?P<ip>\S+)", re.IGNORECASE),
]

WEB_EVENT_PATTERNS = {
    "web_blocks": re.compile(r"\[Web Guard\] Blocking (?P<ip>\S+): (?P<reason>.+)", re.IGNORECASE),
    "web_sqli": re.compile(r"web-sqli-detected", re.IGNORECASE),
    "web_xss": re.compile(r"web-xss-detected", re.IGNORECASE),
    "web_rate_limit": re.compile(r"web-rate-limit", re.IGNORECASE),
}


def recent_events():
    lines = read_tail_lines(LOG_FILE, 120)
    events = []
    for line in reversed(lines):
        if any(token in line for token in ("[AI Engine]", "[Threat]", "[Decision Engine]", "[Auth Guard]", "[Escalation]", "[Sentinel] Update")):
            events.append(line)
        if len(events) >= MAX_RECENT_EVENTS:
            break
    return list(reversed(events))


def event_counts():
    lines = read_tail_lines(LOG_FILE, 300)
    counts = Counter()
    for line in lines:
        for pattern in BLOCK_EVENT_PATTERNS:
            match = pattern.search(line)
            if match:
                counts[match.group("ip")] += 1
                break
    return counts.most_common(MAX_TOP_RULES)


def web_event_counts():
    lines = read_tail_lines(LOG_FILE, 300)
    counts = Counter()
    for line in lines:
        for key, pattern in WEB_EVENT_PATTERNS.items():
            if pattern.search(line):
                counts[key] += 1
    counts["web_total"] = counts["web_blocks"] + counts["web_sqli"] + counts["web_xss"] + counts["web_rate_limit"]
    return counts


def extract_ai_state(lines):
    ai_line = ""
    learning_line = ""
    for line in reversed(lines):
        if "[Sentinel] AI mode=" in line:
            ai_line = line
            break
    for line in reversed(lines):
        if "learning=" in line and "[AI Engine]" in line:
            learning_line = line
            break
    return ai_line, learning_line


def build_payload():
    config = read_runtime_config()
    sentinel_state = systemd_state(SERVICE_NAME)
    dashboard_state = systemd_state(DASHBOARD_SERVICE_NAME)
    input_rows = parse_drop_rules("INPUT")
    docker_rows = parse_drop_rules("DOCKER-USER")
    top_input = top_offenders(input_rows)
    top_docker = top_offenders(docker_rows)
    log_lines = read_tail_lines(LOG_FILE, 300)
    ai_line, learning_line = extract_ai_state(log_lines)
    status_lines = read_status_lines()
    web_counts = web_event_counts()

    payload = {
        "title": TITLE,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "service": sentinel_state,
        "dashboard": dashboard_state,
        "config": config,
        "counts": {
            "input_rules": len(input_rows),
            "docker_rules": len(docker_rows),
            "recent_events": len(recent_events()),
        },
        "top_input": top_input,
        "top_docker": top_docker,
        "events": recent_events(),
        "status_lines": status_lines,
        "event_counts": event_counts(),
        "web_counts": web_counts,
        "ai_line": ai_line,
        "learning_line": learning_line,
        "log_file": LOG_FILE,
    }
    return payload


def json_response(handler, payload, status=200):
    data = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def html_escape(value):
    return html.escape(str(value), quote=True)


def render_table(rows, title, empty_message="No active DROP rules"):
    if not rows:
        return f"""
        <section class=\"panel\">
          <div class=\"panel-header\"><h2>{html_escape(title)}</h2></div>
          <div class=\"empty\">{html_escape(empty_message)}</div>
        </section>
        """

    header = """
      <tr>
        <th>Source</th>
        <th>Packets</th>
        <th>Bytes</th>
        <th>Line</th>
      </tr>
    """
    body = []
    for row in rows:
        body.append(
            f"<tr><td>{html_escape(row.get('source', 'N/A'))}</td><td>{html_escape(row.get('pkts', 'N/A'))}</td><td>{html_escape(normalize_bytes(row.get('bytes', 0)))}</td><td>{html_escape(row.get('line', 'N/A'))}</td></tr>"
        )
    return f"""
    <section class=\"panel\">
      <div class=\"panel-header\"><h2>{html_escape(title)}</h2></div>
      <table>
        <thead>{header}</thead>
        <tbody>{''.join(body)}</tbody>
      </table>
    </section>
    """


def render_dashboard(payload):
    cfg = payload["config"]
    counts = payload["counts"]
    web_counts = payload.get("web_counts", {})

    event_counts = payload["event_counts"]
    event_html = []
    for ip, count in event_counts:
        event_html.append(f"<div class='pill'><span>{html_escape(ip)}</span><strong>{count}</strong></div>")

    ai_line = payload.get("ai_line") or "AI status not yet reported"
    learning_line = payload.get("learning_line") or "AI learning state not yet reported"

    recent_items = []
    for line in payload["events"]:
        recent_items.append(f"<li>{html_escape(line)}</li>")

    status_items = []
    for line in payload["status_lines"]:
        status_items.append(f"<li>{html_escape(line)}</li>")

    top_input_html = render_table(payload["top_input"], "Top INPUT offenders")
    top_docker_html = render_table(payload["top_docker"], "Top DOCKER-USER offenders", "No DROP rules in DOCKER-USER")

    html_text = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <meta http-equiv=\"refresh\" content=\"5\" />
  <title>{html_escape(TITLE)}</title>
  <style>
    :root {{
      --bg: #08111f;
      --panel: rgba(10, 18, 31, 0.82);
      --panel-2: rgba(17, 27, 47, 0.85);
      --line: rgba(122, 167, 255, 0.14);
      --text: #e7eefc;
      --muted: #9fb0cd;
      --accent: #71f7c8;
      --accent-2: #7aa7ff;
      --warn: #ffd37a;
      --danger: #ff7a9d;
      --shadow: 0 20px 80px rgba(0,0,0,0.32);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(113,247,200,0.15), transparent 25%),
        radial-gradient(circle at top right, rgba(122,167,255,0.2), transparent 30%),
        linear-gradient(180deg, #050a13 0%, #08111f 100%);
      min-height: 100vh;
    }}
    .wrap {{ max-width: 1440px; margin: 0 auto; padding: 28px; }}
    .hero {{ display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; margin-bottom: 20px; }}
    .hero h1 {{ margin: 0; font-size: 34px; letter-spacing: -0.03em; }}
    .hero p {{ margin: 6px 0 0; color: var(--muted); }}
    .stamp {{ color: var(--muted); text-align: right; font-size: 14px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-bottom: 16px; }}
    .card, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
    }}
    .card {{ padding: 18px 18px 16px; min-height: 120px; }}
    .card .label {{ color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0.12em; }}
    .card .value {{ font-size: 28px; font-weight: 700; margin-top: 8px; }}
    .card .sub {{ color: var(--muted); margin-top: 8px; font-size: 13px; }}
    .layout {{ display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; }}
    .stack {{ display: grid; gap: 16px; }}
    .panel {{ padding: 16px; }}
    .panel-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
    .panel h2 {{ margin: 0; font-size: 17px; }}
    .muted {{ color: var(--muted); font-size: 13px; }}
    .pill-row {{ display: flex; flex-wrap: wrap; gap: 10px; }}
    .pill {{
      display: flex; justify-content: space-between; gap: 12px;
      padding: 10px 12px; min-width: 180px;
      border-radius: 14px; background: var(--panel-2); border: 1px solid var(--line);
    }}
    .pill strong {{ color: var(--accent); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.06); text-align: left; font-size: 13px; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: #d5e2ff; }}
    .list {{ list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }}
    .list li {{ padding: 10px 12px; border: 1px solid var(--line); border-radius: 12px; background: var(--panel-2); }}
    .config-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }}
    .config-item {{ padding: 10px 12px; border: 1px solid var(--line); border-radius: 12px; background: var(--panel-2); }}
    .config-item span {{ display: block; color: var(--muted); font-size: 12px; margin-bottom: 5px; }}
    .status-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; background: var(--accent); box-shadow: 0 0 18px rgba(113,247,200,0.55); }}
    .warn-dot {{ background: var(--warn); box-shadow: 0 0 18px rgba(255,211,122,0.55); }}
    .bad-dot {{ background: var(--danger); box-shadow: 0 0 18px rgba(255,122,157,0.55); }}
    .empty {{ color: var(--muted); font-size: 13px; padding: 16px 2px 4px; }}
    @media (max-width: 1200px) {{ .grid, .layout {{ grid-template-columns: 1fr; }} .config-grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"hero\">
      <div>
        <h1>{html_escape(TITLE)}</h1>
        <p>Live operations view for attack defense, auth abuse, AI learning, and firewall enforcement.</p>
      </div>
      <div class=\"stamp\">
        <div><span class=\"status-dot\"></span>Updated {html_escape(payload['timestamp'])}</div>
        <div class=\"mono\">Refreshes every 5 seconds</div>
      </div>
    </div>

    <div class=\"grid\">
      <div class=\"card\">
        <div class=\"label\">Sentinel</div>
        <div class=\"value\">{html_escape(payload['service']['active'])}</div>
        <div class=\"sub\">Enabled: {html_escape(payload['service']['enabled'])}</div>
      </div>
            <div class="card">
                <div class="label">Web guard blocks</div>
                <div class="value">{html_escape(web_counts.get('web_total', 0))}</div>
                <div class="sub">SQLi + XSS + rate-limit actions</div>
            </div>
            <div class="card">
                <div class="label">SQLi / XSS hits</div>
                <div class="value">{html_escape(web_counts.get('web_sqli', 0) + web_counts.get('web_xss', 0))}</div>
                <div class="sub">Payload pattern detections</div>
            </div>
            <div class="card">
                <div class="label">Rate-limit hits</div>
                <div class="value">{html_escape(web_counts.get('web_rate_limit', 0))}</div>
                <div class="sub">Per-path burst defense</div>
            </div>
      <div class=\"card\">
        <div class=\"label\">Dashboard</div>
        <div class=\"value\">{html_escape(payload['dashboard']['active'])}</div>
        <div class=\"sub\">Enabled: {html_escape(payload['dashboard']['enabled'])}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">INPUT DROP rules</div>
        <div class=\"value\">{html_escape(counts['input_rules'])}</div>
        <div class=\"sub\">Firewall blocks on host chain</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">DOCKER-USER DROP</div>
        <div class=\"value\">{html_escape(counts['docker_rules'])}</div>
        <div class=\"sub\">Container path enforcement</div>
      </div>
    </div>

    <div class=\"layout\">
      <div class=\"stack\">
        <section class=\"panel\">
          <div class=\"panel-header\"><h2>Top offender signatures</h2><div class=\"muted\">Recent block frequency</div></div>
          <div class=\"pill-row\">{''.join(event_html) if event_html else '<div class="empty">No block events recorded yet</div>'}</div>
        </section>

        {top_input_html}
        {top_docker_html}
      </div>

      <div class=\"stack\">
        <section class=\"panel\">
          <div class=\"panel-header\"><h2>AI and auth config</h2><div class=\"muted\">Active runtime policy</div></div>
          <div class=\"config-grid\">
            <div class=\"config-item\"><span>AI enabled</span><strong>{html_escape(cfg['SENTINEL_AI_ENABLED'])}</strong></div>
            <div class=\"config-item\"><span>AI warmup samples</span><strong>{html_escape(cfg['SENTINEL_AI_LEARNING_SAMPLES'])}</strong></div>
            <div class=\"config-item\"><span>AI min score</span><strong>{html_escape(cfg['SENTINEL_AI_MIN_BLOCK_SCORE'])}</strong></div>
            <div class=\"config-item\"><span>AI anomaly weight</span><strong>{html_escape(cfg['SENTINEL_AI_ANOMALY_WEIGHT'])}</strong></div>
            <div class=\"config-item\"><span>Auth guard</span><strong>{html_escape(cfg['SENTINEL_AUTH_GUARD_ENABLED'])}</strong></div>
            <div class=\"config-item\"><span>Auth log path</span><strong class=\"mono\">{html_escape(cfg['SENTINEL_AUTH_LOG_PATH'])}</strong></div>
                        <div class="config-item"><span>Web guard</span><strong>{html_escape(cfg.get('SENTINEL_WEB_GUARD_ENABLED', '1'))}</strong></div>
                        <div class="config-item"><span>Web log path</span><strong class="mono">{html_escape(cfg.get('SENTINEL_WEB_LOG_PATH', cfg['SENTINEL_AUTH_LOG_PATH']))}</strong></div>
                        <div class="config-item"><span>AI runtime</span><strong class="mono">{html_escape(ai_line)}</strong></div>
                        <div class="config-item"><span>AI learning</span><strong class="mono">{html_escape(learning_line)}</strong></div>
          </div>
        </section>

        <section class=\"panel\">
          <div class=\"panel-header\"><h2>Recent events</h2><div class=\"muted\">Last Sentinel actions</div></div>
          <ul class=\"list\">{''.join(recent_items) if recent_items else '<li>No recent events found</li>'}</ul>
        </section>

        <section class=\"panel\">
          <div class=\"panel-header\"><h2>Update status</h2><div class=\"muted\">Recent update/restart state</div></div>
          <ul class=\"list\">{''.join(status_items) if status_items else '<li>No update status lines yet</li>'}</ul>
        </section>
      </div>
    </div>
  </div>
</body>
</html>"""
    return html_text.encode("utf-8")


class SentinelDashboardHandler(BaseHTTPRequestHandler):
    server_version = "SentinelDashboard/1.0"

    def log_message(self, fmt, *args):
        # Keep the dashboard quiet; Sentinel logs are enough.
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/health", "/api/health"):
            payload = {
                "status": "ok",
                "service": systemd_state(SERVICE_NAME),
                "dashboard": systemd_state(DASHBOARD_SERVICE_NAME),
                "timestamp": datetime.now().isoformat(),
            }
            json_response(self, payload)
            return

        if parsed.path == "/api/summary":
            payload = build_payload()
            json_response(self, payload)
            return

        if parsed.path not in ("/", "/index.html"):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        payload = build_payload()
        body = render_dashboard(payload)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    if not os.path.exists(LOG_FILE):
        Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((BIND, PORT), SentinelDashboardHandler)
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Sentinel dashboard listening on http://{BIND}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
