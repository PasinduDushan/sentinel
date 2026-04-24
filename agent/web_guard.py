import os
import re
import time
from collections import defaultdict


class WebAttackGuard:
    """Detect web-layer attack patterns and path-abuse from access logs."""

    SQLI_PATTERNS = [
        re.compile(r"(?:\bunion\b(?:\s+all)?\s+\bselect\b|\bselect\b\s+.+\s+\bfrom\b)", re.IGNORECASE),
        re.compile(r"(?:\bor\b\s+1=1|\band\b\s+1=1|\b1=1\b)", re.IGNORECASE),
        re.compile(r"(?:information_schema|benchmark\s*\(|sleep\s*\(|load_file\s*\(|into\s+outfile|xp_cmdshell)", re.IGNORECASE),
        re.compile(r"(?:--|/\*|\*/|%27|%22|%3d|%3b)", re.IGNORECASE),
    ]

    XSS_PATTERNS = [
        re.compile(r"(?:<\s*script|%3c\s*script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)", re.IGNORECASE),
        re.compile(r"(?:<\s*img|<\s*svg|<\s*iframe|<\s*body|<\s*object|<\s*embed)", re.IGNORECASE),
    ]

    def __init__(
        self,
        log_path,
        enabled=True,
        attack_threshold=1,
        attack_window_seconds=300,
        rate_limit_threshold=120,
        rate_limit_window_seconds=60,
        max_lines_per_poll=250,
    ):
        self.enabled = enabled
        self.log_path = log_path
        self.attack_threshold = max(1, int(attack_threshold))
        self.attack_window_seconds = max(10, int(attack_window_seconds))
        self.rate_limit_threshold = max(5, int(rate_limit_threshold))
        self.rate_limit_window_seconds = max(10, int(rate_limit_window_seconds))
        self.max_lines_per_poll = max(20, int(max_lines_per_poll))

        self.ip_attack_events = defaultdict(list)
        self.route_events = defaultdict(list)

        self._fh = None
        self._inode = None

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

        if self._inode != inode:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = open(self.log_path, "r", encoding="utf-8", errors="ignore")
            self._fh.seek(0, os.SEEK_END)
            self._inode = inode

        return True

    def _parse_common_log(self, line):
        match = re.match(r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"\S+\s+([^\s"]+)\s+[^\"]+"\s+(\d{3})\s+', line)
        if not match:
            return None
        ip = match.group(1)
        request_path = match.group(2)
        status = int(match.group(3))
        return ip, request_path, status

    def _normalize_path(self, request_path):
        path = request_path.split("?", 1)[0].strip()
        if not path:
            return "/"
        path = re.sub(r"/\d+(?=/|$)", "/:id", path)
        path = re.sub(r"/[0-9a-fA-F]{8,}(?=/|$)", "/:id", path)
        path = re.sub(r"//+", "/", path)
        return path.lower()

    def _matches_attack_pattern(self, request_path):
        for pattern in self.SQLI_PATTERNS:
            if pattern.search(request_path):
                return "sqli", pattern.pattern
        for pattern in self.XSS_PATTERNS:
            if pattern.search(request_path):
                return "xss", pattern.pattern
        return None, None

    def _prune_old(self):
        now = time.time()
        attack_cutoff = now - self.attack_window_seconds
        rate_cutoff = now - self.rate_limit_window_seconds

        for ip in list(self.ip_attack_events.keys()):
            self.ip_attack_events[ip] = [t for t in self.ip_attack_events[ip] if t >= attack_cutoff]
            if not self.ip_attack_events[ip]:
                self.ip_attack_events.pop(ip, None)

        for key in list(self.route_events.keys()):
            self.route_events[key] = [t for t in self.route_events[key] if t >= rate_cutoff]
            if not self.route_events[key]:
                self.route_events.pop(key, None)

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
            normalized_path = self._normalize_path(request_path)
            now = time.time()

            attack_type, attack_pattern = self._matches_attack_pattern(request_path)
            if attack_type:
                self.ip_attack_events[ip].append(now)
                self._prune_old()
                attack_count = len(self.ip_attack_events.get(ip, []))
                if attack_count >= self.attack_threshold:
                    offenders.append((ip, f"web-{attack_type}-detected hits={attack_count}/{self.attack_threshold} path={normalized_path}"))
                    self.ip_attack_events[ip] = []
                    continue

            route_key = f"{ip}|{normalized_path}"
            self.route_events[route_key].append(now)
            self._prune_old()
            route_count = len(self.route_events.get(route_key, []))
            if route_count >= self.rate_limit_threshold:
                offenders.append((ip, f"web-rate-limit path={normalized_path} hits={route_count}/{self.rate_limit_threshold} window={self.rate_limit_window_seconds}s"))
                self.route_events[route_key] = []

        dedup = []
        seen = set()
        for ip, reason in offenders:
            key = (ip, reason)
            if key in seen:
                continue
            seen.add(key)
            dedup.append((ip, reason))
        return dedup
