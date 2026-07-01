# 🔐 Sensitive Data Detection & Compliance Assistant

An AI-powered Streamlit application that scans uploaded documents (PDF / TXT / CSV), detects sensitive/confidential information, classifies overall document risk, generates a compliance summary, and lets users ask natural-language questions about the document.

Built as a mini-project assignment — designed to demonstrate approach, problem-solving, and AI/ML understanding rather than production-grade scale.

---

## ✨ Features

- **Multi-format upload**: PDF, TXT, CSV
- **Sensitive data detection**: Aadhaar, PAN, email, phone, credit card, bank account/IFSC, API keys, passwords, AWS keys, employee IDs, confidential-business markers
- **Weighted risk classification**: Low / Medium / High Risk, with a transparent scoring breakdown
- **Compliance summary**: observations, security risks, and concrete remediation steps per detected category
- **Conversational Q&A**: ask about counts, categories, risk, compliance, or general document content
- **Bonus features implemented**:
  - 🕶️ Data masking/redaction (downloadable "safe to share" version)
  - 📝 Audit logging (every scan appended to a local JSONL log, viewable in-app)
  - 🐳 Dockerized
  - 📊 Multi-tab dashboard UI (detected data table + chart, summary, redacted view, chat)

---

## 🏗️ Architecture Overview

```
┌─────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Streamlit  │────▶│ document_loader  │────▶│  raw text       │
│  app.py     │     │ (pdf/txt/csv)    │     │                 │
└─────────────┘     └──────────────────┘     └───────┬─────────┘
                                                       ▼
                                            ┌─────────────────────┐
                                            │  detectors.py        │
                                            │  regex + validators  │
                                            │  (Luhn, Aadhaar,     │
                                            │   IFSC structure)    │
                                            └──────────┬───────────┘
                                                        ▼
                                      ┌──────────────────────────────┐
                                      │  risk_classifier.py           │
                                      │  weighted + log-scaled score  │
                                      └───────────┬───────────────────┘
                                                   ▼
                          ┌───────────────────────────────────────┐
                          │  summarizer.py                          │
                          │  observations / risks / remediation     │
                          └───────────────┬───────────────────────┘
                                           ▼
                     ┌───────────────────────────────────────────┐
                     │  qa_engine.py                                │
                     │  intent layer (rule-based) + TF-IDF retrieval│
                     └───────────────────────────────────────────┘

Bonus modules: redaction.py (masking), audit_logger.py (JSONL scan log)
```

**Data flow:** upload → text extraction → regex detection with validators → weighted risk scoring → template-driven compliance summary → all of the above feed a `QAEngine` that answers questions either from structured detection data (fast path) or via TF-IDF sentence retrieval (fallback for open-ended questions).

---

## 🧠 AI/ML Approach Used

This project intentionally combines **rule-based NLP** with a **lightweight retrieval-based QA approach**, rather than depending on a paid LLM API, so it runs fully offline with zero cost and is easy to demo/evaluate:

1. **Sensitive data detection — regex + structural validation.**
   Each entity type has a regex pattern *plus* a validator function where a checksum or structural rule exists (Luhn algorithm for card numbers, Aadhaar's "never starts with 0/1" rule, IFSC's 4-letter+0+6-alphanumeric structure). This mirrors how real DLP (Data Loss Prevention) tools reduce false positives beyond naive regex matching.

2. **Risk classification — weighted scoring with log-dampening.**
   Each detected category has a hand-assigned severity weight (e.g., a leaked password = 10, an email address = 3). Raw scores are log-scaled (`log2(score+1) * 5`) so that many low-risk detections (e.g. 50 emails) don't outrank a document with a couple of Aadhaar numbers or an exposed API key — reflecting how real compliance risk is dominated by the *most sensitive* item present, not sheer volume.

3. **Question answering — two-layer design:**
   - **Intent layer** (rule-based): common compliance questions ("how many emails", "summarize", "what compliance risks") are matched to intents and answered directly from the structured detection/summary data. This guarantees factual, hallucination-free answers for the questions that matter most in a compliance context.
   - **Retrieval layer** (TF-IDF + cosine similarity): for open-ended questions that don't match a known intent, the document is split into sentences, vectorized with scikit-learn's `TfidfVectorizer`, and the most relevant sentence(s) to the question are returned as an extractive, grounded answer. This is effectively a minimal RAG (Retrieval-Augmented Generation) pipeline without an embedding API.
   - **Optional LLM upgrade path**: `qa_engine.llm_answer()` is a ready-to-wire function that calls an OpenAI-compatible chat model if `OPENAI_API_KEY` is set, so the same retrieved context could be handed to a real LLM for more fluent answers — kept optional so the app has no required paid dependency.

This layered approach was a deliberate design decision: it demonstrates understanding of both classic **rule-based/regex NLP** (still the industry standard for PII/DLP detection because it's auditable and deterministic) and **modern retrieval-based QA** concepts, while keeping the app runnable by anyone with no API key.

---

## ⚙️ Setup Instructions

### 1. Clone and install
```bash
git clone <your-repo-url>
cd sensitive-data-assistant
pip install -r requirements.txt
```

### 2. Run the app
```bash
streamlit run app.py
```
Then open the URL shown in the terminal (typically `http://localhost:8501`).

### 3. Try it
- Use the sample files in `sample_data/` (`sample.txt`, `sample.csv`) — both contain synthetic (fake) PII for demo purposes.
- Upload a file in the sidebar → click **Analyze Document**.
- Explore the four tabs: Detected Data, Compliance Summary, Redacted View, Ask Questions.

### 4. (Optional) Enable LLM-powered answers
```bash
export OPENAI_API_KEY=your_key_here
```
The app works fully without this — it's an optional enhancement wired in `src/qa_engine.py`.

### 5. Run with Docker
```bash
docker build -t sensitive-data-assistant .
docker run -p 8501:8501 sensitive-data-assistant
```

---

## 🧩 Challenges Faced

- **Balancing regex recall vs. false positives**: a naive 12-digit regex will match Aadhaar numbers, some bank account numbers, and even long invoice numbers. Solved partially with structural validators (Luhn, Aadhaar's leading-digit rule, IFSC format) and a priority/overlap system so more specific patterns (e.g. IFSC) claim a span before generic catch-alls (e.g. "Bank Account Number") do. This is still an approximation — a production system would combine regex with a trained NER model for higher precision.
- **CSV/table context**: PII detectors are built for free text; CSVs needed to be flattened row-by-row while preserving enough context for the "context" field in results to still be meaningful.
- **Risk scoring calibration**: a simple sum of weights over-penalizes documents with lots of low-risk items (e.g. many emails). Log-dampening the raw score fixed this, but the thresholds are still heuristic and would benefit from calibration against real labeled examples.
- **Q&A without a guaranteed LLM API key**: designed a two-layer (intent + TF-IDF retrieval) system so the app is fully functional and demoable without any paid API, while leaving a clean integration point for an LLM if available.

---

## 🚀 Future Improvements

- Swap/augment regex detection with a trained NER model (e.g. spaCy custom pipeline or a fine-tuned transformer) for higher-precision entity detection, especially for less structured fields like "Confidential Business Information."
- Add OCR (e.g. Tesseract) to support scanned/image-based PDFs.
- Multi-document / batch upload with cross-document risk aggregation and a portfolio-level compliance dashboard.
- Proper vector-store-backed RAG (FAISS/Chroma) for large multi-page documents where sentence-level TF-IDF may miss cross-sentence context.
- Role-based access control and encrypted storage for the audit log in a real deployment.
- Deploy to Streamlit Community Cloud / Render / HF Spaces for a public demo link.

---

## 📁 Project Structure

```
sensitive-data-assistant/
├── app.py                     # Streamlit UI
├── src/
│   ├── document_loader.py     # PDF/TXT/CSV → text
│   ├── detectors.py           # regex + validators, DetectionResult
│   ├── risk_classifier.py     # weighted risk scoring
│   ├── summarizer.py          # compliance summary generation
│   ├── qa_engine.py           # intent layer + TF-IDF retrieval QA
│   ├── redaction.py           # masking/redaction (bonus)
│   └── audit_logger.py        # scan audit log (bonus)
├── sample_data/
│   ├── sample.txt             # synthetic PII sample
│   └── sample.csv             # synthetic employee records sample
├── logs/                      # audit_log.jsonl written here at runtime
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## ⚠️ Disclaimer

All data in `sample_data/` is synthetic/fake, generated for demonstration purposes only. This tool is a prototype for a technical assignment and is **not** a certified compliance or legal tool — real deployments handling actual PII/PAN/Aadhaar data should undergo a proper security review.
