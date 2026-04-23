import math


class AdaptiveRiskEngine:
    """Context-aware local anomaly scorer with a warmup learning period."""

    def __init__(
        self,
        enabled=True,
        learning_samples=300,
        min_block_score=70.0,
        warmup_multiplier=1.7,
        anomaly_weight=0.35,
        zscore_block=3.0,
    ):
        self.enabled = enabled
        self.learning_samples = max(30, int(learning_samples))
        self.min_block_score = float(min_block_score)
        self.warmup_multiplier = max(1.0, float(warmup_multiplier))
        self.anomaly_weight = min(0.9, max(0.0, float(anomaly_weight)))
        self.zscore_block = max(1.0, float(zscore_block))

        # Welford online baseline stats over observed request_count_10s.
        self.sample_count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def _base_score(self, request_count, threshold, active_ip_count, prior_strikes):
        reasons = []
        score = 0.0

        ratio = request_count / float(threshold)
        score += min(70.0, ratio * 55.0)
        if ratio >= 1.0:
            reasons.append("request-rate-over-threshold")

        if prior_strikes > 0:
            strike_boost = min(20.0, prior_strikes * 6.0)
            score += strike_boost
            reasons.append(f"repeat-offender-strikes={prior_strikes}")

        if active_ip_count >= 20:
            score += 10.0
            reasons.append(f"wide-fan-in-active-ips={active_ip_count}")

        if request_count >= max(10, int(threshold * 0.8)) and prior_strikes > 0:
            score += 10.0
            reasons.append("high-rate-plus-recurrence")

        return min(100.0, score), reasons

    def _zscore(self, value):
        if self.sample_count < 20:
            return 0.0
        variance = self.m2 / max(1, self.sample_count - 1)
        std = math.sqrt(max(1e-6, variance))
        return max(0.0, (value - self.mean) / std)

    def _update_baseline(self, value):
        self.sample_count += 1
        delta = value - self.mean
        self.mean += delta / self.sample_count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def assess_traffic(self, ip, request_count, threshold, active_ip_count, prior_strikes):
        """Return dict: should_block, score, confidence, reasons + learning state."""
        if threshold <= 0:
            threshold = 1

        base_score, reasons = self._base_score(
            request_count=request_count,
            threshold=threshold,
            active_ip_count=active_ip_count,
            prior_strikes=prior_strikes,
        )

        in_learning = self.sample_count < self.learning_samples
        zscore = self._zscore(request_count)

        # Convert z-score to anomaly score 0..100 around configured block level.
        anomaly_score = min(100.0, max(0.0, (zscore / self.zscore_block) * 100.0))
        if zscore >= self.zscore_block:
            reasons.append(f"ai-anomaly-zscore={round(zscore, 2)}")

        if self.enabled:
            score = ((1.0 - self.anomaly_weight) * base_score) + (self.anomaly_weight * anomaly_score)
        else:
            score = base_score

        score = min(100.0, score)
        confidence = min(99.0, 45.0 + score * 0.5)

        # During learning, keep safety by requiring a stricter hard threshold.
        warmup_hard_floor = max(int(threshold * self.warmup_multiplier), threshold + 10)
        if in_learning:
            should_block = request_count >= warmup_hard_floor
            reasons.append("ai-learning-mode")
        else:
            should_block = (
                score >= self.min_block_score
                or (self.enabled and zscore >= self.zscore_block and request_count >= max(10, int(threshold * 0.7)))
            )

        # Update baseline after computing score to avoid peeking current sample.
        clipped_value = min(request_count, max(threshold * 3, 10))
        self._update_baseline(clipped_value)

        return {
            "ip": ip,
            "should_block": should_block,
            "score": round(score, 2),
            "confidence": round(confidence, 2),
            "reasons": reasons,
            "in_learning": in_learning,
            "learning_samples_seen": self.sample_count,
            "learning_samples_total": self.learning_samples,
            "zscore": round(zscore, 3),
        }