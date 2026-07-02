"""
Sensitive Data Detection & Compliance Assistant
-------------------------------------------------
Streamlit front-end tying together document loading (with OCR fallback for
scanned PDFs), PII detection, risk classification, compliance summary
generation, redaction, audit logging, and Q&A — with multi-document support.

Run: streamlit run app.py
"""

import streamlit as st
import pandas as pd

from src.document_loader import load_text
from src.detectors import detect, summarize_counts
from src.risk_classifier import compute_risk
from src.summarizer import build_summary
from src.qa_engine import QAEngine
from src.redaction import redact_text
from src.audit_logger import log_scan, read_logs

st.set_page_config(page_title="Sensitive Data & Compliance Assistant", page_icon="🔐", layout="wide")

RISK_COLORS = {"Low Risk": "🟢", "Medium Risk": "🟡", "High Risk": "🔴"}
RISK_ORDER = {"Low Risk": 0, "Medium Risk": 1, "High Risk": 2}

if "documents" not in st.session_state:
    st.session_state.documents = {}   # filename -> processed doc dict
if "active_doc" not in st.session_state:
    st.session_state.active_doc = None
if "active_view" not in st.session_state:
    st.session_state.active_view = "📋 Detected Data"

st.title("🔐 Sensitive Data Detection & Compliance Assistant")
st.caption("Upload one or more PDF / TXT / CSV documents to detect sensitive data, assess compliance risk, and ask questions about them.")


def _process_file(uploaded_file) -> dict:
    file_bytes = uploaded_file.read()
    text = load_text(file_bytes, uploaded_file.name)
    results = detect(text)
    risk_level, risk_score, risk_detail = compute_risk(results)
    summary = build_summary(text, results, risk_level, risk_detail)
    log_scan(uploaded_file.name, risk_level, summary["category_counts"])
    return {
        "text": text,
        "results": results,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_detail": risk_detail,
        "summary": summary,
        "qa_engine": QAEngine(text, results, summary),
        "chat_history": [],
    }


with st.sidebar:
    st.header("Upload Document(s)")
    uploaded_files = st.file_uploader(
        "Choose file(s)", type=["pdf", "txt", "csv"], accept_multiple_files=True
    )
    run_button = st.button("🔍 Analyze Document(s)", type="primary", use_container_width=True)
    st.divider()
    st.caption("Bonus: view local audit log")
    if st.checkbox("Show audit log"):
        logs = read_logs()
        if logs:
            st.dataframe(pd.DataFrame(logs), use_container_width=True, hide_index=True)
        else:
            st.info("No scans logged yet.")

if run_button and uploaded_files:
    progress = st.progress(0.0, text="Starting...")
    errors = []
    for i, uf in enumerate(uploaded_files):
        progress.progress((i) / len(uploaded_files), text=f"Processing {uf.name}...")
        try:
            doc_data = _process_file(uf)
            if not doc_data["text"].strip():
                errors.append(f"{uf.name}: no extractable text found (scanned PDF with OCR unavailable, or empty file).")
                continue
            st.session_state.documents[uf.name] = doc_data
        except ValueError as e:
            errors.append(f"{uf.name}: {e}")
    progress.progress(1.0, text="Done.")
    progress.empty()

    if st.session_state.documents:
        # default active doc = most recently processed
        st.session_state.active_doc = uploaded_files[-1].name if uploaded_files[-1].name in st.session_state.documents else next(iter(st.session_state.documents))
    for err in errors:
        st.warning(err)

# ---------------------------------------------------------------------------
# Portfolio overview (shown whenever 2+ documents have been analyzed)
# ---------------------------------------------------------------------------
if len(st.session_state.documents) > 1:
    st.markdown("## 📁 Portfolio Overview")
    rows = []
    for fname, d in st.session_state.documents.items():
        rows.append({
            "Document": fname,
            "Risk Level": f"{RISK_COLORS.get(d['risk_level'], '⚪')} {d['risk_level']}",
            "Sensitive Items": len(d["results"]),
            "Categories": len(d["summary"]["category_counts"]),
            "Risk Score": d["risk_score"],
        })
    portfolio_df = pd.DataFrame(rows).sort_values("Risk Score", ascending=False)
    st.dataframe(portfolio_df, use_container_width=True, hide_index=True)

    highest = max(
        st.session_state.documents.items(),
        key=lambda kv: (RISK_ORDER.get(kv[1]["risk_level"], 0), kv[1]["risk_score"]),
    )
    st.caption(f"⚠️ Highest-risk document: **{highest[0]}** ({highest[1]['risk_level']})")
    st.divider()

# ---------------------------------------------------------------------------
# Active document detail view
# ---------------------------------------------------------------------------
if st.session_state.documents:
    doc_names = list(st.session_state.documents.keys())
    if st.session_state.active_doc not in doc_names:
        st.session_state.active_doc = doc_names[0]

    if len(doc_names) > 1:
        st.session_state.active_doc = st.selectbox(
            "📄 Select a document to inspect", doc_names,
            index=doc_names.index(st.session_state.active_doc),
        )

    doc = st.session_state.documents[st.session_state.active_doc]
    results = doc["results"]
    summary = doc["summary"]
    risk_level = doc["risk_level"]

    st.markdown(f"## {RISK_COLORS.get(risk_level, '⚪')} {st.session_state.active_doc} — Overall Risk: **{risk_level}**")
    c1, c2, c3 = st.columns(3)
    c1.metric("Sensitive Items Found", len(results))
    c2.metric("Categories Detected", len(summary["category_counts"]))
    c3.metric("Risk Score (weighted)", doc["risk_score"])

    view_options = ["📋 Detected Data", "📝 Compliance Summary", "🕶️ Redacted View", "💬 Ask Questions"]
    if st.session_state.active_view not in view_options:
        st.session_state.active_view = view_options[0]
    active_view = st.radio(
        "View", view_options, horizontal=True, label_visibility="collapsed", key="active_view"
    )
    st.divider()

    if active_view == "📋 Detected Data":
        if results:
            df = pd.DataFrame([{
                "Category": r.category,
                "Detected Value": r.value,
                "Context": r.context,
                "Risk Weight": r.risk_weight,
            } for r in results])
            st.dataframe(df, use_container_width=True, hide_index=True)

            counts = summarize_counts(results)
            st.bar_chart(pd.Series(counts, name="Count"))
        else:
            st.success("No sensitive data patterns detected in this document.")

    elif active_view == "📝 Compliance Summary":
        st.subheader("Compliance Observations")
        for o in summary["observations"]:
            st.markdown(f"- {o}")

        st.subheader("Security Risks")
        for r in summary["security_risks"]:
            st.markdown(f"- {r}")

        st.subheader("Suggested Remediation Steps")
        for r in summary["remediation"]:
            st.markdown(f"- {r}")

        st.download_button(
            "📥 Download Summary Report (Markdown)",
            data=(
                f"# Compliance Report — {st.session_state.active_doc}\n\n"
                f"**Risk Level:** {risk_level}\n\n"
                "## Observations\n" + "\n".join(f"- {o}" for o in summary["observations"]) + "\n\n"
                "## Security Risks\n" + "\n".join(f"- {r}" for r in summary["security_risks"]) + "\n\n"
                "## Remediation\n" + "\n".join(f"- {r}" for r in summary["remediation"])
            ),
            file_name=f"compliance_report_{st.session_state.active_doc}.md",
            mime="text/markdown",
            key=f"download_summary_{st.session_state.active_doc}",
        )

    elif active_view == "🕶️ Redacted View":
        st.caption("Sensitive values masked — safe version for wider sharing.")
        redacted = redact_text(doc["text"], results)
        st.text_area("Redacted Document", redacted, height=400, key=f"redacted_{st.session_state.active_doc}")
        st.download_button(
            "📥 Download Redacted Text", data=redacted,
            file_name=f"redacted_{st.session_state.active_doc}.txt",
            key=f"download_redacted_{st.session_state.active_doc}",
        )

    elif active_view == "💬 Ask Questions":
        st.caption("Ask about detected sensitive data, risk level, compliance, or general content — for the selected document.")
        for role, msg in doc["chat_history"]:
            with st.chat_message(role):
                st.markdown(msg)

        question = st.chat_input("e.g. What sensitive data exists in the document?", key=f"chat_input_{st.session_state.active_doc}")
        if question:
            doc["chat_history"].append(("user", question))
            answer = doc["qa_engine"].answer(question)
            doc["chat_history"].append(("assistant", answer))
            st.rerun()

else:
    st.info("👈 Upload one or more PDF, TXT, or CSV files and click **Analyze Document(s)** to get started.")
    st.markdown("""
    **Try it with the included sample files** in `sample_data/`:
    - `sample_data/sample.txt` — mixed PII (Aadhaar, PAN, emails, phone, API key)
    - `sample_data/sample.csv` — employee records with bank details

    **Multi-document support:** upload several files at once (or analyze more one at a time) to see
    a portfolio-level risk overview across all of them.

    **OCR support:** scanned/image-only PDFs are automatically OCR'd (via Tesseract) if no
    text layer is found — this may take a few extra seconds per page.
    """)
