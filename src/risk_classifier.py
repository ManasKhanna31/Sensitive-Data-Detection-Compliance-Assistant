"""
risk_classifier.py
-------------------
Turns a list of DetectionResult objects into an overall document risk level.

Approach: weighted scoring.
  score = sum(risk_weight for every detection)
  - normalized lightly by log-scale so one document with 50 emails doesn't
    automatically outrank a document with 2 Aadhaar numbers.

Thresholds are intentionally simple and documented so they're easy to explain
and tune in an interview.
"""

import math
from typing import List, Dict, Tuple
from src.detectors import DetectionResult

HIGH_RISK_CATEGORIES = {
    "Aadhaar Number", "PAN Number", "Credit Card Number",
    "API Key / Secret", "Password", "AWS Access Key", "Bank IFSC Code",
    "Bank Account Number",
}


def compute_risk(results: List[DetectionResult]) -> Tuple[str, float, Dict]:
    if not results:
        return "Low Risk", 0.0, {"reason": "No sensitive data detected."}

    raw_score = sum(r.risk_weight for r in results)
    # log-dampen so volume alone doesn't dominate the signal
    score = round(math.log2(raw_score + 1) * 5, 2)

    has_critical = any(r.category in HIGH_RISK_CATEGORIES for r in results)
    critical_count = sum(1 for r in results if r.category in HIGH_RISK_CATEGORIES)

    if has_critical and critical_count >= 2:
        level = "High Risk"
    elif has_critical or score >= 15:
        level = "Medium Risk" if critical_count <= 1 else "High Risk"
    elif score > 0:
        level = "Low Risk" if score < 8 else "Medium Risk"
    else:
        level = "Low Risk"

    detail = {
        "raw_score": raw_score,
        "normalized_score": score,
        "critical_category_hits": critical_count,
        "total_detections": len(results),
    }
    return level, score, detail
