import streamlit as st

from ai_analyzer import analyze_email
from email_parser import parse_eml
from rag import add_case, count_cases, retrieve_cases

st.set_page_config(page_title="AI-Powered Phishing Email Analyzer", layout="wide")
st.title("🛡 AI-Powered Phishing Email Analyzer")
st.sidebar.metric("Cases in knowledge base", count_cases())

uploaded = st.file_uploader("Upload EML File", type=["eml"])

if uploaded:
    # Parse once per file; keep results in session_state so button clicks (which rerun the script) don't wipe them.
    file_key = (uploaded.name, uploaded.size)
    if st.session_state.get("file_key") != file_key:
        st.session_state.file_key = file_key
        st.session_state.email = parse_eml(uploaded.getvalue())
        st.session_state.report = None
        st.session_state.similar = []

    email_data = st.session_state.email
    st.subheader("Email Information")
    st.write("**Sender:**", email_data["from"])
    if email_data["reply_to"]:
        st.write("**Reply-To:**", email_data["reply_to"])
    st.write("**Subject:**", email_data["subject"])
    if email_data["auth"]:
        st.write("**Authentication:**", email_data["auth"])

    st.write("**Links found:**")
    for link in email_data["urls"] or ["(none)"]:
        st.write(link)
    for m in email_data["link_mismatches"]:
        st.warning(m)

    if email_data["attachments"]:
        st.write("**Attachments:**")
        for a in email_data["attachments"]:
            st.write(f"- `{a['filename']}` · {a['size']:,} B · sha256 `{a['sha256'][:16]}…` · "
                     f"{'⚠ ' + ', '.join(a['flags']) if a['flags'] else 'no flags'}")

    with st.expander("Email body"):
        st.text(email_data["body"][:5000])

    text_for_rag = "\n".join([f"Subject: {email_data['subject']}", f"From: {email_data['from']}", f"Body: {email_data['body']}"])

    if st.button("Investigate", type="primary"):
        with st.spinner("Searching knowledge base and asking the model…"):
            st.session_state.similar = retrieve_cases(text_for_rag)
            st.session_state.report = analyze_email(email_data, st.session_state.similar)

    if st.session_state.get("report"):
        st.subheader("Investigation")
        st.markdown(st.session_state.report)
        if st.session_state.similar:
            with st.expander(f"Similar past cases used ({len(st.session_state.similar)})"):
                for c in st.session_state.similar:
                    st.markdown(f"**{c['verdict'].upper()}** · distance {c['distance']}")
                    st.text(c["text"][:400])

    st.subheader("Analyst feedback")
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("✅ Confirmed Phishing"):
            add_case(text_for_rag, "phishing"); st.success("Saved as phishing")
    with c2:
        if st.button("❌ Benign"):
            add_case(text_for_rag, "benign"); st.success("Saved as benign")
    with c3:
        if st.button("⚠ Suspicious"):
            add_case(text_for_rag, "suspicious"); st.success("Saved as suspicious")
