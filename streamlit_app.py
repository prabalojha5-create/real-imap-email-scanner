import streamlit as st
import requests

st.set_page_config(page_title="Inbox Phishing & Link Scanner", page_icon="📫", layout="wide")

st.title("📫 Live Email Inbox Fraud & Link Scanner")
st.markdown("Connect your email inbox (Gmail, Outlook) to fetch recent emails, extract links, and analyze fraud risk using ML.")

API_URL = "http://127.0.0.1:8000/api/v1/scan-inbox"

with st.sidebar:
    st.header("⚙️ IMAP Login Settings")
    email_input = st.text_input("Email Address", placeholder="user@gmail.com")
    password_input = st.text_input("App Password", type="password", help="Use 16-character App Password for Gmail")
    imap_server = st.selectbox("IMAP Server", ["imap.gmail.com", "outlook.office365.com", "imap.mail.yahoo.com"])
    max_count = st.slider("Max Emails to Scan", min_value=1, max_value=15, value=5)
    scan_btn = st.button("🚀 Start Inbox Scan", type="primary")

st.info("💡 **Security Tip:** For Gmail, generate a 16-character **App Password** in Google Account -> Security -> 2-Step Verification.")

if scan_btn:
    if not email_input or not password_input:
        st.error("Please provide both Email Address and Password.")
    else:
        with st.spinner("Connecting to IMAP server, fetching emails & scanning links..."):
            payload = {
                "email_address": email_input,
                "password": password_input,
                "imap_server": imap_server,
                "max_emails": max_count
            }
            try:
                res = requests.post(API_URL, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    st.success(f"✅ Successfully scanned {data['total_scanned']} recent emails!")
                    
                    emails = data["scanned_emails"]
                    if not emails:
                        st.warning("No emails found in Inbox.")
                    else:
                        for idx, item in enumerate(emails, 1):
                            with st.expander(f"{'🚨 FRAUD' if item['is_fraud'] else '🟢 SAFE'} - {item['subject']} (From: {item['sender']})"):
                                col1, col2, col3 = st.columns(3)
                                col1.metric("Status", item["prediction"])
                                col2.metric("Fraud Probability", f"{item['fraud_probability']}%")
                                col3.metric("Total Extracted URLs", len(item["extracted_urls"]))

                                st.markdown("---")
                                st.write("**Matched Suspicious Keywords:**")
                                if item["matched_keywords"]:
                                    st.write(", ".join([f"`{kw}`" for kw in item["matched_keywords"]]))
                                else:
                                    st.write("None")

                                st.write("**Extracted Links & Risk Analysis:**")
                                if item["extracted_urls"]:
                                    for link in item["extracted_urls"]:
                                        if link in item["suspicious_links"]:
                                            st.error(f"⚠️ **SUSPICIOUS LINK:** `{link}`")
                                        else:
                                            st.write(f"🔗 `{link}`")
                                else:
                                    st.write("No links found in this email.")
                else:
                    st.error(f"API Error ({res.status_code}): {res.json().get('detail', 'Unknown error')}")
            except Exception as e:
                st.error(f"Could not connect to FastAPI server. Ensure `uvicorn app.main:app --reload` is running on port 8000. Error: {e}")
