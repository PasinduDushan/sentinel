import os
import re
import time
from collections import defaultdict


class AuthBruteForceGuard:
    """Detect brute-force login abuse from access logs and emit block actions."""

    def __init__(
        self,
        log_path,
        enabled=True,
        login_paths=None,
        fail_statuses=None,
        ip_fail_threshold=10,
        user_fail_threshold=20,
        window_seconds=300,
        max_lines_per_poll=200,
    ):
        self.enabled = enabled
        self.log_path = log_path
        self.login_paths = login_paths or ["/login", "/wp-login.php", "/api/auth/login"]
        self.fail_statuses = set(fail_statuses or [401, 403, 429])
        self.ip_fail_threshold = max(1, int(ip_fail_threshold))
        self.user_fail_threshold = max(1, int(user_fail_threshold))
        self.window_seconds = max(10, int(window_seconds))
        self.max_lines_per_poll = max(20, int(max_lines_per_poll))

        self.ip_fail_events = defaultdict(list)
        self.user_fail_events = defaultdict(list)
        self.user_to_ips = defaultdict(set)

        self._fh = None
        self._inode = None

    def _is_login_path(self, request_path):
        path = request_path.lower()
        return any(token.lower() in path for token in self.login_paths)

    def _extract_username(self, request_path):
        # Optional best-effort extraction from query string.
        # Example: /login?username=alice or /auth?email=a@b.com
        lower = request_path.lower()
        for key in ("username=", "user=", "email=", "login="):
            idx = lower.find(key)
            if idx == -1:
                continue
            start = idx + len(key)
            end = start
            while end < len(request_path) and request_path[end] not in "&?# " :
                end += 1
            value = request_path[start:end].strip()
            if value:
                return value[:128]
        return None

    def _parse_common_log(self, line):
        # Matches common/combined format-ish lines.
        # 1.2.3.4 - - [date] "METHOD /path HTTP/1.1" 401 1234
        m = re.match(r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"\S+\s+([^\s"]+)\s+[^\"]+"\s+(\d{3})\s+', line)
        if not m:
            return None
        ip = m.group(1)
        request_path = m.group(2)
        status = int(m.group(3))
        return ip, request_path, status

    def _ensure_file_handle(self):
        if not self.enabled:
            return False
        if not os.path.exists(self.log_path):
            return False

        st = os.stat(self.log_path)
        inode = st.st_ino

        if self._fh is None:
            self._fh = open(self.log_path, "r", encoding="utf-8", errors="ignore")
            self._fh.seek(0, os.SEEK_END)
            self._inode = inode
            return True

        # Handle log rotation.
        if self._inode != inode:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = open(self.log_path, "r", encoding="utf-8", errors="ignore")
            self._fh.seek(0, os.SEEK_END)
            self._inode = inode

        return True

    def _prune_old(self):
        now = time.time()
        cutoff = now - self.window_seconds

        for ip in list(self.ip_fail_events.keys()):
            self.ip_fail_events[ip] = [t for t in self.ip_fail_events[ip] if t >= cutoff]
            if not self.ip_fail_events[ip]:
                self.ip_fail_events.pop(ip, None)

        for user in list(self.user_fail_events.keys()):
            self.user_fail_events[user] = [t for t in self.user_fail_events[user] if t >= cutoff]
            if not self.user_fail_events[user]:
                self.user_fail_events.pop(user, None)
                self.user_to_ips.pop(user, None)

    def poll(self):
        """Read recent log lines and return [(ip, reason), ...] to block."""
        if not self._ensure_file_handle():
            return []

        offenders = []
        lines_read = 0

        while lines_read < self.max_lines_per_poll:
            line = self._fh.readline()
            if not line:
                break
            lines_read += 1

            parsed = self._parse_common_log(line)
            if not parsed:
                continue

            ip, request_path, status = parsed
            if not self._is_login_path(request_path):
                continue
            if status not in self.fail_statuses:
                continue

            now = time.time()
            self.ip_fail_events[ip].append(now)

            user = self._extract_username(request_path)
            if user:
                self.user_fail_events[user].append(now)
                self.user_to_ips[user].add(ip)

            self._prune_old()

            ip_count = len(self.ip_fail_events.get(ip, []))
            if ip_count >= self.ip_fail_threshold:
                offenders.append((ip, f"auth-bruteforce-ip-threshold={ip_count}/{self.ip_fail_threshold}"))
                # reset this IP bucket after triggering to reduce repeated duplicate actions
                self.ip_fail_events[ip] = []

            if user:
                user_count = len(self.user_fail_events.get(user, []))
                if user_count >= self.user_fail_threshold:
                    for src_ip in list(self.user_to_ips.get(user, set())):
                        offenders.append((src_ip, f"auth-bruteforce-user-threshold user={user} count={user_count}"))
                    self.user_fail_events[user] = []
                    self.user_to_ips[user].clear()

        # de-duplicate while preserving order
        dedup = []
        seen = set()
        for ip, reason in offenders:
            key = (ip, reason)
            if key in seen:
                continue
            seen.add(key)
            dedup.append((ip, reason))
        return dedup
