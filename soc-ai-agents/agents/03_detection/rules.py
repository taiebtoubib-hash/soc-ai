"""
Detection Rules: List of static heuristics for threat detection.
"""

RULES = [
    {
        "name": "Port Scan Detected",
        "condition": lambda a: a.unique_dst_ports_last_5min > 20,
        "confidence": 0.8,
        "needs_ml": True
    },
    {
        "name": "High Reputation Threat",
        "condition": lambda a: a.src_reputation_score > 80,
        "confidence": 0.9,
        "needs_ml": False
    },
    {
        "name": "Internal Brute Force",
        "condition": lambda a: a.is_src_internal and a.same_src_ip_count_last_5min > 100,
        "confidence": 0.7,
        "needs_ml": True
    }
]
