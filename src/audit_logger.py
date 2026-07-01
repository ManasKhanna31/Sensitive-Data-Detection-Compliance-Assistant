"""
audit_logger.py
----------------
Bonus feature: append-only audit log of every document scan.
In a real deployment this would go to a proper log store / SIEM; here it's a
local JSONL file so the assignment is self-contained and reviewable.
"""

import json
import os
import time
from typing import Dict

LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "audit_log.jsonl")


def log_scan(filename: str, risk_level: str, category_counts: Dict[str, int]) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "filename": filename,
        "risk_level": risk_level,
        "category_counts": category_counts,
    }
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_logs(limit: int = 50):
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
    return [json.loads(l) for l in lines]
