import imaplib
import email
from email.header import decode_header
import re
from typing import List, Dict, Any
from app.ml_engine import PhishingDetectorEngine

class IMAPService:
    @staticmethod
    def _extract_body(msg) -> str:
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode("utf-8", errors="ignore")
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Fallback html body plain text extraction
                        html_text = payload.decode("utf-8", errors="ignore")
                        clean_text = re.sub(r'<[^>]+>', ' ', html_text)
                        body += clean_text
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode("utf-8", errors="ignore")
        return body

    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))

    @classmethod
    def fetch_and_scan(cls, email_address: str, password: str, imap_server: str, max_emails: int) -> List[Dict[str, Any]]:
        try:
            mail = imaplib.IMAP4_SSL(imap_server)
            mail.login(email_address, password)
            mail.select("inbox")

            status, messages = mail.search(None, "ALL")
            if status != "OK" or not messages[0]:
                mail.logout()
                return []

            email_ids = messages[0].split()[-max_emails:]
            scanned_results = []

            for e_id in reversed(email_ids):
                res_status, msg_data = mail.fetch(e_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        subject_header = msg.get("Subject", "No Subject")
                        decoded_subject, encoding = decode_header(subject_header)[0]
                        if isinstance(decoded_subject, bytes):
                            subject = decoded_subject.decode(encoding if encoding else "utf-8", errors="ignore")
                        else:
                            subject = str(decoded_subject)

                        sender = msg.get("From", "Unknown Sender")
                        body = cls._extract_body(msg)
                        extracted_urls = cls._extract_urls(body)

                        eval_result = PhishingDetectorEngine.evaluate_email(subject, body, extracted_urls)

                        scanned_results.append({
                            "subject": subject,
                            "sender": sender,
                            "is_fraud": eval_result["is_fraud"],
                            "prediction": eval_result["prediction"],
                            "risk_score": eval_result["risk_score"],
                            "fraud_probability": eval_result["fraud_probability"],
                            "extracted_urls": extracted_urls,
                            "suspicious_links": eval_result["suspicious_links"],
                            "matched_keywords": eval_result["matched_keywords"]
                        })

            mail.logout()
            return scanned_results

        except Exception as e:
            raise Exception(f"IMAP Connection Error: {str(e)}")
