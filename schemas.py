from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class IMAPScanRequest(BaseModel):
    email_address: str = Field(..., example="your_email@gmail.com")
    password: str = Field(..., example="xxxx xxxx xxxx xxxx")
    imap_server: str = Field(default="imap.gmail.com", example="imap.gmail.com")
    max_emails: int = Field(default=5, ge=1, le=20)

class ScannedEmailResult(BaseModel):
    subject: str
    sender: str
    is_fraud: bool
    prediction: str
    risk_score: float
    fraud_probability: float
    extracted_urls: List[str]
    suspicious_links: List[str]
    matched_keywords: List[str]

class IMAPScanResponse(BaseModel):
    status: str
    total_scanned: int
    scanned_emails: List[ScannedEmailResult]
