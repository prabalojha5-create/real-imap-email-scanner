<<<<<<< HEAD
# real-imap-email-scanner
real-imap-email-scanner
=======
# 🛡️ Real-Time IMAP Email Fraud & Link Scanner

A complete Machine Learning cybersecurity project featuring a **FastAPI backend** and **Streamlit UI** that connects to live email accounts (Gmail, Outlook, Yahoo) via IMAP protocol, fetches recent emails, extracts embedded links/URLs, and scans them using NLP Machine Learning heuristics and CTI link verification.

---

## 📁 Project Structure

```text
├── app/
│   ├── __init__.py
│   ├── imap_scanner.py  # IMAP Connection & URL extraction engine
│   ├── main.py          # FastAPI server endpoints
│   ├── ml_engine.py      # TF-IDF + Classifier & URL threat analysis
│   └── schemas.py       # Pydantic data schemas
├── streamlit_app.py     # Interactive Web UI Frontend
├── requirements.txt     # Dependencies
├── .gitignore           # Git ignore settings
└── README.md            # Documentation
```

---

## 🔑 Note on Email Passwords (Important)

Due to modern email security rules (Google / Microsoft):
1. **Gmail:** Do NOT use your normal Google account password. Go to `Google Account -> Security -> 2-Step Verification -> App Passwords` and generate a 16-character **App Password**. Use that password in the application.
2. **Outlook/Yahoo:** Use your generated App Password or IMAP-enabled access credentials.

---

## 🛠️ How to Run

### 1. Extract & Setup Environment
```bash
unzip real_imap_email_scanner.zip
cd real_imap_email_scanner

python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Run FastAPI Backend (Terminal 1)
```bash
uvicorn app.main:app --reload
```

### 3. Run Streamlit UI (Terminal 2)
```bash
streamlit run streamlit_app.py
```

Open your browser at `http://localhost:8501`.
>>>>>>> 0e68125 (Project)
