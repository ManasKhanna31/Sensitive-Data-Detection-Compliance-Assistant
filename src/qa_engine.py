"""
qa_engine.py
------------
Question answering over the uploaded document.

Two layers:
1. INTENT LAYER (rule-based): questions like "how many emails" or
   "summarize this document" map directly onto structured data we already
   computed (detections, summary) -> fast, deterministic, zero hallucination
   for compliance-critical facts.
2. RETRIEVAL LAYER (TF-IDF + cosine similarity): for open-ended questions
   that don't match a known intent, we split the document into sentences,
   vectorize with TF-IDF, and return the most relevant sentence(s) as a
   grounded, extractive answer. This is a lightweight "RAG"-style approach
   that needs no external API/embedding calls.

Optional upgrade path: if an OPENAI_API_KEY is set, `llm_answer()` can be
wired in by the app to generate a more fluent answer conditioned on the
same retrieved context (kept optional so the app has zero required API cost).
"""

import os
import re
from typing import List, Dict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from src.detectors import DetectionResult, summarize_counts

# Common phrasing variants -> canonical category name. Keeps the intent layer
# deterministic (no ML/fuzzy matching needed) while covering realistic
# variations a user might actually type instead of the exact category label.
CATEGORY_SYNONYMS: Dict[str, str] = {
    "email": "Email Address", "emails": "Email Address",
    "mail": "Email Address", "mails": "Email Address", "e-mail": "Email Address",
    "phone": "Phone Number", "phones": "Phone Number", "mobile": "Phone Number",
    "contact number": "Phone Number", "mobile number": "Phone Number", "phone number": "Phone Number",
    "aadhaar": "Aadhaar Number", "aadhar": "Aadhaar Number", "adhaar": "Aadhaar Number",
    "pan": "PAN Number",
    "card": "Credit Card Number", "credit card": "Credit Card Number", "cards": "Credit Card Number",
    "account": "Bank Account Number", "bank account": "Bank Account Number",
    "ifsc": "Bank IFSC Code",
    "api key": "API Key / Secret", "apikey": "API Key / Secret", "secret": "API Key / Secret", "key": "API Key / Secret",
    "aws": "AWS Access Key",
    "password": "Password", "passwords": "Password",
    "employee id": "Employee ID", "employee": "Employee ID", "emp id": "Employee ID",
    "confidential": "Confidential Business Marker",
}


# Words too generic to reliably identify a category on their own (they appear
# in multiple category names, e.g. "Number" is in Phone/Aadhaar/PAN/Bank Account).
_GENERIC_TOKENS = {"number", "address", "code"}


def _resolve_category(question: str, counts: Dict[str, int]) -> str:
    """Find which detected category a free-text question is asking about,
    trying exact category-name words first (ignoring generic tokens that
    would match multiple categories), then the synonym map."""
    for category in counts:
        distinctive = [w for w in category.split() if w.lower() not in _GENERIC_TOKENS]
        if distinctive and any(w.lower() in question for w in distinctive):
            return category
    # sort longer phrases first so "credit card" matches before "card"
    for phrase in sorted(CATEGORY_SYNONYMS, key=len, reverse=True):
        if phrase in question and CATEGORY_SYNONYMS[phrase] in counts:
            return CATEGORY_SYNONYMS[phrase]
    return ""


def _split_sentences(text: str) -> List[str]:
    sentences = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [s.strip() for s in sentences if len(s.strip()) > 3]


class QAEngine:
    def __init__(self, text: str, results: List[DetectionResult], summary: Dict):
        self.text = text
        self.results = results
        self.summary = summary
        self.sentences = _split_sentences(text) or [text]
        self.vectorizer = TfidfVectorizer(stop_words="english")
        try:
            self.doc_matrix = self.vectorizer.fit_transform(self.sentences)
        except ValueError:
            self.doc_matrix = None

    # ---------------- Intent layer ----------------

    def _match_intent(self, question: str) -> str:
        q = question.lower()

        if any(k in q for k in ["summarize", "summary", "overview"]):
            obs = "\n".join(f"- {o}" for o in self.summary["observations"])
            return f"**Document Summary**\n\nRisk Level: **{self.summary['risk_level']}**\n\n{obs}"

        if "how many" in q or "count" in q:
            counts = summarize_counts(self.results)
            category = _resolve_category(q, counts)
            if category:
                return f"{counts[category]} instance(s) of {category} were found."
            if counts:
                lines = "\n".join(f"- {c}: {n}" for c, n in counts.items())
                return f"Detected sensitive data counts:\n{lines}"
            return "No sensitive data instances were detected in this document."

        if "what sensitive" in q or "what pii" in q or "what data" in q:
            counts = summarize_counts(self.results)
            if not counts:
                return "No sensitive data was detected in this document."
            lines = "\n".join(f"- {c}: {n} instance(s)" for c, n in counts.items())
            return f"The document contains the following sensitive data categories:\n{lines}"

        if "compliance" in q or "risk" in q:
            risks = "\n".join(f"- {r}" for r in self.summary["security_risks"])
            return f"Risk Level: **{self.summary['risk_level']}**\n\nSecurity Risks:\n{risks}"

        if "remediat" in q or "fix" in q or "recommend" in q:
            steps = "\n".join(f"- {s}" for s in self.summary["remediation"])
            return f"Suggested remediation steps:\n{steps}"

        return ""  # no rule-based intent matched -> fall through to retrieval

    # ---------------- Retrieval layer ----------------

    def _retrieve(self, question: str, top_k: int = 3) -> str:
        if self.doc_matrix is None:
            return "The document doesn't contain enough text to answer that question."
        q_vec = self.vectorizer.transform([question])
        sims = cosine_similarity(q_vec, self.doc_matrix).flatten()
        top_idx = sims.argsort()[::-1][:top_k]
        top_idx = [i for i in top_idx if sims[i] > 0.05]
        if not top_idx:
            return "I couldn't find directly relevant content in the document for that question. Try rephrasing, or ask about detected sensitive data, risk level, or compliance recommendations."
        snippets = [self.sentences[i] for i in sorted(top_idx)]
        return "Based on the document:\n\n" + "\n".join(f"- {s}" for s in snippets)

    # ---------------- Public API ----------------

    def answer(self, question: str) -> str:
        intent_answer = self._match_intent(question)
        if intent_answer:
            return intent_answer
        return self._retrieve(question)


def llm_answer(question: str, context: str) -> str:
    """
    Optional: use an LLM (OpenAI-compatible) for a more fluent answer.
    Only called by the app if OPENAI_API_KEY is set in the environment.
    Kept isolated here so the core app has zero required external dependency.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a compliance assistant. Answer only using the provided document context. Be concise and factual."},
            {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
        ],
        max_tokens=300,
    )
    return resp.choices[0].message.content
