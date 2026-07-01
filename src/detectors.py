"""
detectors.py
------------
Rule-based / regex sensitive-data detection engine.

Design notes (for your README / interview explanation):
- Each detector is a (name, compiled_regex, validator_fn, risk_weight) tuple.
- validator_fn does an extra structural/checksum check to cut false positives
  (e.g. Luhn check for card numbers, IFSC structure check).
- Detection returns a list of DetectionResult objects so downstream modules
  (risk scoring, summary, redaction) all consume one common data structure.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional


@dataclass
class DetectionResult:
    category: str
    value: str
    start: int
    end: int
    risk_weight: int
    context: str = ""  # a short snippet around the match, useful for QA/summary


# ---------------------------------------------------------------------------
# Validators (reduce false positives beyond plain regex matching)
# ---------------------------------------------------------------------------

def _luhn_check(number: str) -> bool:
    """Standard Luhn checksum used by most card networks."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _aadhaar_check(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    # Aadhaar numbers never start with 0 or 1
    return len(digits) == 12 and digits[0] not in ("0", "1")


def _ifsc_check(code: str) -> bool:
    # IFSC: 4 letters (bank code) + 0 + 6 alphanumeric (branch code)
    return bool(re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", code))


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, Dict] = {
    "Aadhaar Number": {
        "pattern": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
        "validator": _aadhaar_check,
        "weight": 9,
    },
    "PAN Number": {
        "pattern": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        "validator": None,
        "weight": 8,
    },
    "Email Address": {
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "validator": None,
        "weight": 3,
    },
    "Phone Number": {
        "pattern": re.compile(r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)"),
        "validator": None,
        "weight": 4,
    },
    "Credit Card Number": {
        "pattern": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        "validator": _luhn_check,
        "weight": 10,
    },
    "Bank IFSC Code": {
        "pattern": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "validator": _ifsc_check,
        "weight": 7,
    },
    "Bank Account Number": {
        "pattern": re.compile(r"\b\d{9,18}\b"),
        "validator": None,  # deliberately loose; de-duplicated against other categories below
        "weight": 8,
    },
    "API Key / Secret": {
        "pattern": re.compile(
            r"(?i)\b(?:api[_-]?key|secret|access[_-]?key|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}['\"]?"
        ),
        "validator": None,
        "weight": 10,
    },
    "Password": {
        "pattern": re.compile(r"(?i)\bpassword\b\s*[:=]\s*['\"]?\S{4,}['\"]?"),
        "validator": None,
        "weight": 10,
    },
    "AWS Access Key": {
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "validator": None,
        "weight": 10,
    },
    "Employee ID": {
        "pattern": re.compile(r"\b(?:EMP|EID|E)-?\d{3,6}\b"),
        "validator": None,
        "weight": 3,
    },
    "Confidential Business Marker": {
        "pattern": re.compile(
            r"(?i)\b(confidential|internal use only|trade secret|do not distribute|proprietary and confidential|strictly private)\b"
        ),
        "validator": None,
        "weight": 5,
    },
}


def _context(text: str, start: int, end: int, window: int = 25) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    return text[s:e].replace("\n", " ").strip()


def detect(text: str) -> List[DetectionResult]:
    """Run every pattern over `text` and return validated, de-duplicated results."""
    results: List[DetectionResult] = []
    claimed_spans = []  # (start, end) already assigned to a higher-priority category

    # Priority order matters: more specific categories (Aadhaar, PAN, IFSC, cards)
    # should claim a span before the generic "Bank Account Number" catch-all does.
    priority = [
        "Aadhaar Number", "PAN Number", "Bank IFSC Code", "AWS Access Key",
        "Credit Card Number", "API Key / Secret", "Password", "Employee ID",
        "Email Address", "Phone Number", "Confidential Business Marker",
        "Bank Account Number",
    ]

    for category in priority:
        spec = PATTERNS[category]
        for m in spec["pattern"].finditer(text):
            span = (m.start(), m.end())
            # skip if this span overlaps something already claimed
            if any(not (span[1] <= cs or span[0] >= ce) for cs, ce in claimed_spans):
                continue
            value = m.group(0)
            validator: Optional[Callable] = spec["validator"]
            if validator and not validator(value):
                continue
            results.append(
                DetectionResult(
                    category=category,
                    value=value,
                    start=span[0],
                    end=span[1],
                    risk_weight=spec["weight"],
                    context=_context(text, span[0], span[1]),
                )
            )
            claimed_spans.append(span)

    results.sort(key=lambda r: r.start)
    return results


def summarize_counts(results: List[DetectionResult]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in results:
        counts[r.category] = counts.get(r.category, 0) + 1
    return counts
