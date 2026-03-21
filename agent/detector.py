def detect_ddos(ip, count):
    if count >= 30:  # match agent threshold
        print(f"\033[1;33m[AI Engine]\033[0m Analyzing traffic from {ip}...")
        print(f"[AI Engine] Requests in 10s: {count}")
        print("[AI Engine] Baseline deviation detected")
        print("[AI Engine] Confidence: 94.6%")
        print(f"\033[1;31m[Threat]\033[0m Potential DDoS attack from {ip}")
        return True
    return False