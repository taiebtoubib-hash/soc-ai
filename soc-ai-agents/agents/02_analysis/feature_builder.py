"""
agents/02_analysis/feature_builder.py
---------------------------------------
Builds the 41-feature vector from an EnrichedAlert.

Feature order MUST match training/train_threat.py exactly.
Any change here MUST be mirrored in the training scripts,
otherwise the ML models will silently produce garbage results.
"""

from shared.models import EnrichedAlert
from shared.logger import get_logger

log = get_logger("feature_builder")


# ── Feature order — must mirror training exactly ──────────────────

FEATURE_ORDER = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

# ── Protocol encoding ─────────────────────────────────────────────
_PROTOCOL_MAP = {"icmp": 0, "tcp": 1, "udp": 2}

# ── TCP flag encoding ─────────────────────────────────────────────
_FLAG_MAP = {
    "OTH":    0,
    "REJ":    1,
    "RSTO":   2,
    "RSTOS0": 3,
    "RSTR":   4,
    "S0":     5,
    "S1":     6,
    "S2":     7,
    "S3":     8,
    "SF":     9,
    "SH":    10,
}


def build_features(enriched: EnrichedAlert) -> dict:
    """
    Produce a dict with exactly the 41 features listed in
    ``FEATURE_ORDER``.  Missing raw fields default to 0 / 0.0.

    Args:
        enriched: The EnrichedAlert produced by the analysis agent.

    Returns:
        dict mapping every feature name →  numeric value.
    """
    raw = enriched.alert.raw or {}

    # ── Encoded fields ────────────────────────────────────────────

    protocol_type = _PROTOCOL_MAP.get(
        enriched.alert.protocol.lower(), 0
    )

    # Service: use a simple stable hash clamped to a small int range;
    # downstream models handle this as a categorical encoded integer.
    service_str = str(raw.get("service", "other"))
    service = abs(hash(service_str)) % 70   # 70 unique services in KDD

    flag = _FLAG_MAP.get(str(raw.get("flag", "SF")), 0)

    # ── Feature dict ─────────────────────────────────────────────

    features = {
        # ── connection-level ──────────────────────────────────
        "duration":          int(raw.get("duration", 0)),
        "protocol_type":     protocol_type,
        "service":           service,
        "flag":              flag,
        "src_bytes":         int(raw.get("src_bytes", 0)),
        "dst_bytes":         int(raw.get("dst_bytes", 0)),
        "land":              int(raw.get("land", 0)),
        "wrong_fragment":    int(raw.get("wrong_fragment", 0)),
        "urgent":            int(raw.get("urgent", 0)),

        # ── content features ──────────────────────────────────
        "hot":               int(raw.get("hot", 0)),
        "num_failed_logins": int(raw.get("num_failed_logins", 0)),
        "logged_in":         int(raw.get("logged_in", 0)),
        "num_compromised":   int(raw.get("num_compromised", 0)),
        "root_shell":        int(raw.get("root_shell", 0)),
        "su_attempted":      int(raw.get("su_attempted", 0)),
        "num_root":          int(raw.get("num_root", 0)),
        "num_file_creations":int(raw.get("num_file_creations", 0)),
        "num_shells":        int(raw.get("num_shells", 0)),
        "num_access_files":  int(raw.get("num_access_files", 0)),
        "num_outbound_cmds": int(raw.get("num_outbound_cmds", 0)),
        "is_host_login":     int(raw.get("is_host_login", 0)),
        "is_guest_login":    int(raw.get("is_guest_login", 0)),

        # ── traffic-based (2-second window in KDD / correlation here) ─
        "count":             enriched.same_src_ip_count_last_5min,
        "srv_count":         int(raw.get("srv_count", 0)),
        "serror_rate":       float(raw.get("serror_rate", 0.0)),
        "srv_serror_rate":   float(raw.get("srv_serror_rate", 0.0)),
        "rerror_rate":       float(raw.get("rerror_rate", 0.0)),
        "srv_rerror_rate":   float(raw.get("srv_rerror_rate", 0.0)),
        "same_srv_rate":     float(raw.get("same_srv_rate", 1.0)),
        "diff_srv_rate":     float(raw.get("diff_srv_rate", 0.0)),
        "srv_diff_host_rate":float(raw.get("srv_diff_host_rate", 0.0)),

        # ── destination-host-based (100-connection window in KDD) ─────
        "dst_host_count":              int(raw.get("dst_host_count", 0)),
        "dst_host_srv_count":          int(raw.get("dst_host_srv_count", 0)),
        "dst_host_same_srv_rate":      float(raw.get("dst_host_same_srv_rate", 0.0)),
        "dst_host_diff_srv_rate":      float(raw.get("dst_host_diff_srv_rate", 0.0)),
        "dst_host_same_src_port_rate": float(raw.get("dst_host_same_src_port_rate", 0.0)),
        "dst_host_srv_diff_host_rate": float(raw.get("dst_host_srv_diff_host_rate", 0.0)),
        "dst_host_serror_rate":        float(raw.get("dst_host_serror_rate", 0.0)),
        "dst_host_srv_serror_rate":    float(raw.get("dst_host_srv_serror_rate", 0.0)),
        "dst_host_rerror_rate":        float(raw.get("dst_host_rerror_rate", 0.0)),
        "dst_host_srv_rerror_rate":    float(raw.get("dst_host_srv_rerror_rate", 0.0)),
    }

    # Guard: ensure all 41 features are present (no accidental omissions)
    assert set(features.keys()) == set(FEATURE_ORDER), (
        "Feature mismatch — check feature_builder.py vs FEATURE_ORDER"
    )

    # Return in canonical order
    return {k: features[k] for k in FEATURE_ORDER}
