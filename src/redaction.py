"""
redaction.py
------------
Bonus feature: masks/redacts detected sensitive values in the original text
so a "safe to share" version can be produced.
"""

from typing import List
from src.detectors import DetectionResult


def _mask(value: str, category: str) -> str:
    if category in ("Email Address",):
        name, _, domain = value.partition("@")
        return (name[:2] + "***@" + domain) if len(name) > 2 else "***@" + domain
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def redact_text(text: str, results: List[DetectionResult]) -> str:
    # Replace from the end of the string backwards so earlier spans' indices stay valid.
    redacted = text
    for r in sorted(results, key=lambda r: r.start, reverse=True):
        masked = _mask(r.value, r.category)
        redacted = redacted[: r.start] + masked + redacted[r.end :]
    return redacted
