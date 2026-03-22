def assess_traffic(ip, request_count, threshold, active_ip_count, prior_strikes):
    """
    Lightweight context-aware risk scorer.
    Returns dict: should_block, score, confidence, reasons.
    """
    if threshold <= 0:
        threshold = 1

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

    score = min(100.0, score)
    should_block = score >= 70.0
    confidence = min(99.0, 45.0 + score * 0.5)

    return {
        "ip": ip,
        "should_block": should_block,
        "score": round(score, 2),
        "confidence": round(confidence, 2),
        "reasons": reasons,
    }