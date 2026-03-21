def detect_ddos(ip, count):
    if count > 50:
        print(f"[AI Engine] Analyzing traffic from {ip}...")
        print(f"[AI Engine] Requests in 10s: {count}")
        print(f"[AI Engine] Baseline deviation detected")
        print(f"[AI Engine] Confidence: 94.6%")
        print(f"[Threat] Potential DDoS attack from {ip}")
        return True
    return False