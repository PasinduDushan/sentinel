import os
import re
import time
from math import sqrt
from collections import defaultdict


class EndpointProfile:
    def __init__(self, learning_samples=120):
        self.learning_samples = max(20, int(learning_samples))
        self.samples_seen = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, value):
        self.samples_seen += 1
        delta = value - self.mean
        self.mean += delta / self.samples_seen
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def variance(self):
        if self.samples_seen < 2:
            return 0.0
        return self.m2 / (self.samples_seen - 1)

    def stddev(self):
        return sqrt(self.variance())

    def zscore(self, value):
        if self.samples_seen < self.learning_samples:
            return 0.0
        stddev = self.stddev()
        if stddev == 0:
            return 0.0
        return (value - self.mean) / stddev


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
        endpoint_learning_samples=120,
        endpoint_zscore_block=3.0,
        endpoint_anomaly_weight=0.45,
        max_lines_per_poll=250,
    ):
        self.enabled = enabled
        self.log_path = log_path
        self.attack_threshold = max(1, int(attack_threshold))
        self.attack_window_seconds = max(10, int(attack_window_seconds))
        self.rate_limit_threshold = max(5, int(rate_limit_threshold))
        self.rate_limit_window_seconds = max(10, int(rate_limit_window_seconds))
        self.endpoint_learning_samples = max(20, int(endpoint_learning_samples))
        self.endpoint_zscore_block = float(endpoint_zscore_block)
        self.endpoint_anomaly_weight = float(endpoint_anomaly_weight)
        self.max_lines_per_poll = max(20, int(max_lines_per_poll))

        self.ip_attack_events = defaultdict(list)
        self.route_events = defaultdict(list)
        self.endpoint_profiles = {}

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

    def _endpoint_profile(self, normalized_path):
        if normalized_path not in self.endpoint_profiles:
            self.endpoint_profiles[normalized_path] = EndpointProfile(self.endpoint_learning_samples)
        return self.endpoint_profiles[normalized_path]

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
            route_key = f"{ip}|{normalized_path}"
            path_profile = self._endpoint_profile(normalized_path)

            attack_type, attack_pattern = self._matches_attack_pattern(request_path)
            if attack_type:
                self.ip_attack_events[ip].append(now)
                self._prune_old()
                attack_count = len(self.ip_attack_events.get(ip, []))
                if attack_count >= self.attack_threshold:
                    offenders.append((ip, f"web-{attack_type}-detected hits={attack_count}/{self.attack_threshold} path={normalized_path}"))
                    self.ip_attack_events[ip] = []
                    self.route_events[route_key].append(now)
                    path_profile.update(len(self.route_events.get(route_key, [])))
                    continue

            self.route_events[route_key].append(now)
            self._prune_old()
            route_count = len(self.route_events.get(route_key, []))
            path_zscore = path_profile.zscore(route_count)
            path_profile.update(route_count)

            if path_profile.samples_seen >= self.endpoint_learning_samples and path_zscore >= self.endpoint_zscore_block:
                offenders.append((ip, f"endpoint-anomaly path={normalized_path} z={path_zscore:.2f} mean={path_profile.mean:.2f} hits={route_count} weight={self.endpoint_anomaly_weight}"))
                self.route_events[route_key] = []
                continue

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
