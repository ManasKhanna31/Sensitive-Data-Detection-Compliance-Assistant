"""
summarizer.py
-------------
Generates a compliance/security summary from detection results.

This is template-driven + extractive rather than calling an external LLM,
so the app works fully offline with zero API cost. If an OPENAI_API_KEY is
present in the environment, `generate_llm_summary` can optionally be used
by the app for a more natural-language write-up (see qa_engine.py for the
same optional-LLM pattern).
"""

from typing import List, Dict
from src.detectors import DetectionResult
from src.risk_classifier import HIGH_RISK_CATEGORIES

REMEDIATION_MAP = {
    "Aadhaar Number": "Mask or tokenize Aadhaar numbers; store only the last 4 digits if retention is required, per UIDAI guidelines.",
    "PAN Number": "Redact PAN numbers in shared copies; restrict access to finance/HR roles only.",
    "Credit Card Number": "Never store raw PAN (card) data; use a PCI-DSS compliant tokenization/payment gateway instead.",
    "Bank Account Number": "Mask account numbers in logs and exports; encrypt at rest.",
    "Bank IFSC Code": "Low sensitivity alone, but combined with account numbers it enables fraud — treat as part of a bank-detail cluster.",
    "API Key / Secret": "Rotate the exposed key immediately and move secrets to a vault (e.g. AWS Secrets Manager, HashiCorp Vault) instead of plaintext files.",
    "Password": "Rotate credentials immediately; never store passwords in plaintext — use a hashed secret store.",
    "AWS Access Key": "Revoke and rotate the key in IAM immediately; audit CloudTrail for unauthorized use.",
    "Email Address": "Low individual risk; mask in bulk exports if the document leaves the organization.",
    "Phone Number": "Mask in externally shared reports; retain only where a legitimate business purpose exists.",
    "Employee ID": "Low risk in isolation; avoid pairing with other PII in the same public/external document.",
    "Confidential Business Marker": "Document is self-labeled confidential — ensure sharing/access controls match its classification.",
}


def build_summary(text: str, results: List[DetectionResult], risk_level: str, risk_detail: Dict) -> Dict:
    counts: Dict[str, int] = {}
    for r in results:
        counts[r.category] = counts.get(r.category, 0) + 1

    observations = []
    if not results:
        observations.append("No sensitive or confidential data patterns were detected in this document.")
    else:
        for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
            observations.append(f"{n} instance(s) of {cat} detected.")

    security_risks = []
    critical_hits = [c for c in counts if c in HIGH_RISK_CATEGORIES]
    if critical_hits:
        security_risks.append(
            "High-sensitivity identifiers found (" + ", ".join(critical_hits) +
            "). Exposure of this document could enable identity theft, financial fraud, or unauthorized system access."
        )
    if "API Key / Secret" in counts or "Password" in counts or "AWS Access Key" in counts:
        security_risks.append(
            "Live credentials appear to be embedded in the document — this is a direct system-compromise risk, not just a privacy risk."
        )
    if not security_risks:
        security_risks.append("No critical security-credential exposure detected; residual risk is limited to personal-data privacy concerns, if any.")

    remediation = []
    for cat in counts:
        if cat in REMEDIATION_MAP:
            remediation.append(REMEDIATION_MAP[cat])
    if not remediation:
        remediation.append("No specific remediation required. Maintain standard data-handling hygiene.")

    return {
        "risk_level": risk_level,
        "risk_detail": risk_detail,
        "category_counts": counts,
        "observations": observations,
        "security_risks": security_risks,
        "remediation": remediation,
    }
