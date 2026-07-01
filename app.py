"""
Sensitive Data Detection & Compliance Assistant
-------------------------------------------------
Streamlit front-end tying together document loading, PII detection, risk
classification, compliance summary generation, redaction, and Q&A.

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

if "processed" not in st.session_state:
    st.session_state.processed = False

st.title("🔐 Sensitive Data Detection & Compliance Assistant")
st.caption("Upload a PDF / TXT / CSV document to detect sensitive data, assess compliance risk, and ask questions about it.")

with st.sidebar:
    st.header("Upload Document")
    uploaded_file = st.file_uploader("Choose a file", type=["pdf", "txt", "csv"])
    run_button = st.button("🔍 Analyze Document", type="primary", use_container_width=True)
    st.divider()
    st.caption("Bonus: view local audit log")
    if st.checkbox("Show audit log"):
        logs = read_logs()
        if logs:
            st.dataframe(pd.DataFrame(logs), use_container_width=True, hide_index=True)
        else:
            st.info("No scans logged yet.")

if run_button and uploaded_file is not None:
    with st.spinner("Reading document..."):
        file_bytes = uploaded_file.read()
        try:
            text = load_text(file_bytes, uploaded_file.name)
        except ValueError as e:
            st.error(str(e))
            st.stop()

    if not text.strip():
        st.warning("No extractable text was found in this document (it may be a scanned/image PDF — OCR is not enabled in this build).")
        st.stop()

    with st.spinner("Detecting sensitive data..."):
        results = detect(text)
        risk_level, risk_score, risk_detail = compute_risk(results)
        summary = build_summary(text, results, risk_level, risk_detail)
        log_scan(uploaded_file.name, risk_level, summary["category_counts"])

    st.session_state.processed = True
    st.session_state.text = text
    st.session_state.filename = uploaded_file.name
    st.session_state.results = results
    st.session_state.risk_level = risk_level
    st.session_state.risk_score = risk_score
    st.session_state.risk_detail = risk_detail
    st.session_state.summary = summary
    st.session_state.qa_engine = QAEngine(text, results, summary)
    st.session_state.chat_history = []

if st.session_state.processed:
    results = st.session_state.results
    summary = st.session_state.summary
    risk_level = st.session_state.risk_level

    # ---- Top risk banner ----
    st.markdown(f"## {RISK_COLORS.get(risk_level, '⚪')} Overall Risk: **{risk_level}**")
    c1, c2, c3 = st.columns(3)
    c1.metric("Sensitive Items Found", len(results))
    c2.metric("Categories Detected", len(summary["category_counts"]))
    c3.metric("Risk Score (weighted)", st.session_state.risk_score)

    view_options = ["📋 Detected Data", "📝 Compliance Summary", "🕶️ Redacted View", "💬 Ask Questions"]
    if "active_view" not in st.session_state:
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

    with tab2:
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
                f"# Compliance Report — {st.session_state.filename}\n\n"
                f"**Risk Level:** {risk_level}\n\n"
                "## Observations\n" + "\n".join(f"- {o}" for o in summary["observations"]) + "\n\n"
                "## Security Risks\n" + "\n".join(f"- {r}" for r in summary["security_risks"]) + "\n\n"
                "## Remediation\n" + "\n".join(f"- {r}" for r in summary["remediation"])
            ),
            file_name=f"compliance_report_{st.session_state.filename}.md",
            mime="text/markdown",
        )

    with tab3:
        st.caption("Sensitive values masked — safe version for wider sharing.")
        redacted = redact_text(st.session_state.text, results)
        st.text_area("Redacted Document", redacted, height=400)
        st.download_button("📥 Download Redacted Text", data=redacted, file_name=f"redacted_{st.session_state.filename}.txt")

    with tab4:
        st.caption("Ask about detected sensitive data, risk level, compliance, or general document content.")
        for role, msg in st.session_state.chat_history:
            with st.chat_message(role):
                st.markdown(msg)

        question = st.chat_input("e.g. What sensitive data exists in the document?")
        if question:
            st.session_state.chat_history.append(("user", question))
            answer = st.session_state.qa_engine.answer(question)
            st.session_state.chat_history.append(("assistant", answer))
            st.rerun()

else:
    st.info("👈 Upload a PDF, TXT, or CSV file and click **Analyze Document** to get started.")
    st.markdown("""
    **Try it with the included sample files** in `sample_data/`:
    - `sample_data/sample.txt` — mixed PII (Aadhaar, PAN, emails, phone, API key)
    - `sample_data/sample.csv` — employee records with bank details
    """)