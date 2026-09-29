from fastapi import FastAPI, HTTPException, status
from app.schemas import IMAPScanRequest, IMAPScanResponse
from app.imap_scanner import IMAPService

app = FastAPI(
    title="Real-Time IMAP Inbox Fraud & Link Detector API",
    description="Connects to email accounts via IMAP, fetches emails, extracts links, and scans for phishing.",
    version="1.0.0"
)

@app.get("/")
def root():
    return {"status": "online", "message": "IMAP Phishing & Fraud Detector Backend Ready"}

@app.post("/api/v1/scan-inbox", response_model=IMAPScanResponse)
def scan_inbox(request: IMAPScanRequest):
    try:
        results = IMAPService.fetch_and_scan(
            email_address=request.email_address,
            password=request.password,
            imap_server=request.imap_server,
            max_emails=request.max_emails
        )
        return {
            "status": "success",
            "total_scanned": len(results),
            "scanned_emails": results
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
