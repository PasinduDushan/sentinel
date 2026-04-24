import subprocess
import time
import sys
import os
import select
import shutil
from datetime import datetime
from collections import defaultdict
import requests
import re
from responder import block_ip, cleanup_expired_blocks
from detector import AdaptiveRiskEngine
from auth_guard import AuthBruteForceGuard
from web_guard import WebAttackGuard

LOG_FILE = "/opt/sentinel/logs/agent.log"
STATUS_FILE = "/opt/sentinel/update.status"
UPDATE_MARKER_FILE = "/opt/sentinel/update.pending"

def log_event(message):
    """Write to stdout and directly to the agent log file."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def write_status(status, details=""):
    """Write update/restart status for management script visibility."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {status}"
    if details:
        line = f"{line}: {details}"
    try:
        with open(STATUS_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def finalize_pending_update():
    """If previous process restarted after update, mark completion."""
    if os.path.exists(UPDATE_MARKER_FILE):
        write_status("UPDATE_COMPLETE", "Agent restarted with latest code")
        log_event("[Sentinel] Update completed and agent restarted")
        try:
            os.remove(UPDATE_MARKER_FILE)
        except Exception:
            pass

log_event("[Sentinel] Agent started")
finalize_pending_update()

def env_bool(name, default):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")

# Command file location
COMMAND_FILE = "/opt/sentinel/command"
CORE_PATH = "/opt/sentinel/core"


def deploy_runtime_files():
    """Sync runtime helper files from repo to system paths after update."""
    service_src = os.path.join(CORE_PATH, "sentinel.service")
    manage_src = os.path.join(CORE_PATH, "sentinel-manage.py")

    if os.path.exists(service_src):
        shutil.copy2(service_src, "/etc/systemd/system/sentinel.service")
        os.chmod("/etc/systemd/system/sentinel.service", 0o644)

    if os.path.exists(manage_src):
        shutil.copy2(manage_src, "/opt/sentinel/sentinel-manage.py")
        os.chmod("/opt/sentinel/sentinel-manage.py", 0o755)

def check_command():
    """Check if a command file exists and return its content"""
    if os.path.exists(COMMAND_FILE):
        try:
            with open(COMMAND_FILE, 'r') as f:
                cmd = f.read().strip().lower()
            os.remove(COMMAND_FILE)  # consume the command
            return cmd
        except:
            return None
    return None

def handle_restart():
    """Gracefully restart the agent"""
    log_event("[Sentinel] Restart command received")
    log_event("[Sentinel] Gracefully shutting down")
    time.sleep(1)
    sys.exit(0)  # systemd/supervisor will restart it

def handle_update():
    """Update from GitHub and restart"""
    write_status("UPDATE_RECEIVED", "Update command accepted")
    log_event("[Sentinel] Update command received")
    try:
        try:
            with open(UPDATE_MARKER_FILE, "w", encoding="utf-8") as f:
                f.write(str(time.time()))
        except Exception:
            pass

        write_status("UPDATE_PULLING", "Pulling latest changes from GitHub")
        log_event("[Sentinel] Pulling latest from GitHub")
        # Git pull in the sentinel core directory
        result = subprocess.run(
            ["git", "-C", CORE_PATH, "pull"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            pull_summary = (result.stdout or "").strip() or "Git pull completed"
            write_status("UPDATE_SUCCESS", pull_summary)
            log_event("[Success] Updated to latest version")

            try:
                write_status("UPDATE_SYNCING", "Syncing service and manager files")
                deploy_runtime_files()
                subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=15)
                write_status("UPDATE_SYNCED", "Runtime files synchronized")
            except Exception as sync_err:
                write_status("UPDATE_ERROR", f"Runtime sync failed: {sync_err}")
                log_event(f"[Error] Runtime sync failed: {sync_err}")
                return
        else:
            write_status("UPDATE_ERROR", result.stderr.strip())
            log_event(f"[Error] Update failed: {result.stderr.strip()}")
            try:
                os.remove(UPDATE_MARKER_FILE)
            except Exception:
                pass
            return
    except Exception as e:
        write_status("UPDATE_ERROR", str(e))
        log_event(f"[Error] Update error: {e}")
        try:
            os.remove(UPDATE_MARKER_FILE)
        except Exception:
            pass
        return
    
    write_status("UPDATE_RESTARTING", "Restarting agent to apply update")
    log_event("[Sentinel] Restarting after update")
    time.sleep(1)
    sys.exit(0)  # systemd/supervisor will restart it

# get public IP to avoid blocking ourselves
try:
    MY_IP = requests.get("https://api.ipify.org", timeout=2).text
except:
    MY_IP = "127.0.0.1"

traffic = defaultdict(list)
strike_context = defaultdict(int)
THRESHOLD = 30  # requests in 10s to trigger block
COMMAND_CHECK_INTERVAL = 0.5
last_command_check = time.monotonic()
CLEANUP_INTERVAL = 5
last_cleanup_check = time.monotonic()

AI_ENABLED = env_bool("SENTINEL_AI_ENABLED", "1")
AI_LEARNING_SAMPLES = int(os.getenv("SENTINEL_AI_LEARNING_SAMPLES", "300"))
AI_MIN_BLOCK_SCORE = float(os.getenv("SENTINEL_AI_MIN_BLOCK_SCORE", "70"))
AI_WARMUP_MULTIPLIER = float(os.getenv("SENTINEL_AI_WARMUP_MULTIPLIER", "1.7"))
AI_ANOMALY_WEIGHT = float(os.getenv("SENTINEL_AI_ANOMALY_WEIGHT", "0.35"))
AI_ZSCORE_BLOCK = float(os.getenv("SENTINEL_AI_ZSCORE_BLOCK", "3.0"))

AUTH_GUARD_ENABLED = env_bool("SENTINEL_AUTH_GUARD_ENABLED", "1")
AUTH_LOG_PATH = os.getenv("SENTINEL_AUTH_LOG_PATH", "/var/log/nginx/access.log")
AUTH_LOGIN_PATHS = [
    p.strip() for p in os.getenv("SENTINEL_AUTH_LOGIN_PATHS", "/login,/wp-login.php,/api/auth/login").split(",") if p.strip()
]
AUTH_FAIL_STATUSES = [
    int(s.strip()) for s in os.getenv("SENTINEL_AUTH_FAIL_STATUSES", "401,403,429").split(",") if s.strip().isdigit()
]
AUTH_IP_FAIL_THRESHOLD = int(os.getenv("SENTINEL_AUTH_IP_FAIL_THRESHOLD", "10"))
AUTH_USER_FAIL_THRESHOLD = int(os.getenv("SENTINEL_AUTH_USER_FAIL_THRESHOLD", "20"))
AUTH_WINDOW_SECONDS = int(os.getenv("SENTINEL_AUTH_WINDOW_SECONDS", "300"))
AUTH_POLL_INTERVAL = float(os.getenv("SENTINEL_AUTH_POLL_INTERVAL", "1.0"))
last_auth_poll = time.monotonic()

WEB_GUARD_ENABLED = env_bool("SENTINEL_WEB_GUARD_ENABLED", "1")
WEB_LOG_PATH = os.getenv("SENTINEL_WEB_LOG_PATH", AUTH_LOG_PATH)
WEB_ATTACK_THRESHOLD = int(os.getenv("SENTINEL_WEB_ATTACK_THRESHOLD", "2"))
WEB_ATTACK_WINDOW_SECONDS = int(os.getenv("SENTINEL_WEB_ATTACK_WINDOW_SECONDS", "300"))
WEB_RATE_LIMIT_THRESHOLD = int(os.getenv("SENTINEL_WEB_RATE_LIMIT_THRESHOLD", "120"))
WEB_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("SENTINEL_WEB_RATE_LIMIT_WINDOW_SECONDS", "60"))
WEB_POLL_INTERVAL = float(os.getenv("SENTINEL_WEB_POLL_INTERVAL", "1.0"))
last_web_poll = time.monotonic()

risk_engine = AdaptiveRiskEngine(
    enabled=AI_ENABLED,
    learning_samples=AI_LEARNING_SAMPLES,
    min_block_score=AI_MIN_BLOCK_SCORE,
    warmup_multiplier=AI_WARMUP_MULTIPLIER,
    anomaly_weight=AI_ANOMALY_WEIGHT,
    zscore_block=AI_ZSCORE_BLOCK,
)

auth_guard = AuthBruteForceGuard(
    log_path=AUTH_LOG_PATH,
    enabled=AUTH_GUARD_ENABLED,
    login_paths=AUTH_LOGIN_PATHS,
    fail_statuses=AUTH_FAIL_STATUSES,
    ip_fail_threshold=AUTH_IP_FAIL_THRESHOLD,
    user_fail_threshold=AUTH_USER_FAIL_THRESHOLD,
    window_seconds=AUTH_WINDOW_SECONDS,
)

web_guard = WebAttackGuard(
    log_path=WEB_LOG_PATH,
    enabled=WEB_GUARD_ENABLED,
    attack_threshold=WEB_ATTACK_THRESHOLD,
    attack_window_seconds=WEB_ATTACK_WINDOW_SECONDS,
    rate_limit_threshold=WEB_RATE_LIMIT_THRESHOLD,
    rate_limit_window_seconds=WEB_RATE_LIMIT_WINDOW_SECONDS,
)

log_event(
    f"[Sentinel] AI mode={'enabled' if AI_ENABLED else 'disabled'} "
    f"learning_samples={AI_LEARNING_SAMPLES} min_block_score={AI_MIN_BLOCK_SCORE}"
)
log_event(
    f"[Sentinel] Auth guard={'enabled' if AUTH_GUARD_ENABLED else 'disabled'} "
    f"log={AUTH_LOG_PATH} ip_threshold={AUTH_IP_FAIL_THRESHOLD} window={AUTH_WINDOW_SECONDS}s"
)
log_event(
    f"[Sentinel] Web guard={'enabled' if WEB_GUARD_ENABLED else 'disabled'} "
    f"log={WEB_LOG_PATH} attack_threshold={WEB_ATTACK_THRESHOLD} rate_limit={WEB_RATE_LIMIT_THRESHOLD}/{WEB_RATE_LIMIT_WINDOW_SECONDS}s"
)

def extract_ip(part):
    """Extract a valid IPv4 from a string"""
    match = re.search(r"(\d{1,3}\.){3}\d{1,3}", part)
    if match:
        return match.group(0)
    return None

# tcpdump: only TCP + port 80, line buffered
cmd = ["tcpdump", "-i", "eth0", "-n", "-l", "tcp", "and", "port", "80"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

while True:
    now_monotonic = time.monotonic()
    if now_monotonic - last_command_check >= COMMAND_CHECK_INTERVAL:
        cmd = check_command()
        if cmd == "restart":
            handle_restart()
        elif cmd == "update":
            handle_update()
        last_command_check = now_monotonic

    if now_monotonic - last_cleanup_check >= CLEANUP_INTERVAL:
        cleaned = cleanup_expired_blocks()
        if cleaned > 0:
            log_event(f"[Sentinel] Cleanup removed {cleaned} expired block(s)")
        last_cleanup_check = now_monotonic

    if AUTH_GUARD_ENABLED and now_monotonic - last_auth_poll >= AUTH_POLL_INTERVAL:
        offenders = auth_guard.poll()
        for offender_ip, reason in offenders:
            log_event(f"[Auth Guard] Blocking {offender_ip}: {reason}")
            block_ip(offender_ip)
        last_auth_poll = now_monotonic

    if WEB_GUARD_ENABLED and now_monotonic - last_web_poll >= WEB_POLL_INTERVAL:
        offenders = web_guard.poll()
        for offender_ip, reason in offenders:
            log_event(f"[Web Guard] Blocking {offender_ip}: {reason}")
            block_ip(offender_ip)
        last_web_poll = now_monotonic

    # Non-blocking wait for tcpdump output so command handling is never starved.
    readable, _, _ = select.select([proc.stdout], [], [], 0.1)
    if not readable:
        continue

    line = proc.stdout.readline()
    if not line:
        continue

    try:
        parts = line.split()
        if len(parts) < 3:
            continue

        src_ip = extract_ip(parts[2])
        if not src_ip:
            continue  # skip invalid tokens like In/Out

        # skip self / localhost / private IPs
        if src_ip == MY_IP or src_ip.startswith(("127.", "192.168.", "10.")):
            continue

        now = time.time()
        traffic[src_ip].append(now)
        traffic[src_ip] = [t for t in traffic[src_ip] if now - t < 10]

        # cap to prevent memory overflow
        if len(traffic[src_ip]) > 200:
            traffic[src_ip] = traffic[src_ip][-200:]

        # detection logic
        count_10s = len(traffic[src_ip])
        assessment = risk_engine.assess_traffic(
            ip=src_ip,
            request_count=count_10s,
            threshold=THRESHOLD,
            active_ip_count=len(traffic),
            prior_strikes=strike_context[src_ip],
        )

        if assessment["should_block"]:
            strike_context[src_ip] += 1
            reasons = ", ".join(assessment["reasons"]) if assessment["reasons"] else "none"
            learning_text = (
                f"learning={assessment['learning_samples_seen']}/{assessment['learning_samples_total']}"
                if assessment["in_learning"]
                else "learning=complete"
            )
            log_event(
                f"[AI Engine] score={assessment['score']} confidence={assessment['confidence']}% "
                f"z={assessment['zscore']} {learning_text} from {src_ip} ({count_10s} requests in 10s)"
            )
            log_event(f"[AI Engine] Context reasons: {reasons}")
            log_event(f"[Threat] Potential DDoS attack from {src_ip}")
            log_event(f"[Decision Engine] Blocking IP: {src_ip} using iptables")
            block_ip(src_ip)
            traffic[src_ip] = []

        time.sleep(0.01)  # prevent CPU spike

    except Exception as e:
        log_event(f"[Error] {e}")
        continue

# EOC