import re
import math
from typing import Dict, Any, List
from urllib.parse import urlparse

class PhishingDetectorEngine:
    SUSPICIOUS_KEYWORDS = {
        "urgent", "verify", "update", "account", "secure", "banking", 
        "webmail", "confirm", "signin", "credential", "password", "suspended",
        "lottery", "winner", "prize", "action required", "locked"
    }

    SUSPICIOUS_TLDS = {".xyz", ".top", ".work", ".gq", ".cf", ".ml", ".ga", ".buzz", ".fit"}

    @classmethod
    def analyze_url(cls, url: str) -> Dict[str, Any]:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        hostname = parsed.hostname or ""
        
        has_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname))
        has_suspicious_tld = any(hostname.lower().endswith(tld) for tld in cls.SUSPICIOUS_TLDS)
        has_at_symbol = "@" in url
        has_kw = any(kw in url.lower() for kw in cls.SUSPICIOUS_KEYWORDS)

        risk_level = 0
        if has_ip: risk_level += 40
        if has_suspicious_tld: risk_level += 35
        if has_at_symbol: risk_level += 25
        if has_kw: risk_level += 20

        return {
            "url": url,
            "is_suspicious": risk_level >= 35,
            "risk_score": min(risk_level, 100)
        }

    @classmethod
    def evaluate_email(cls, subject: str, body: str, urls: List[str]) -> Dict[str, Any]:
        text_content = (subject + " " + body).lower()
        
        matched_kws = [kw for kw in cls.SUSPICIOUS_KEYWORDS if kw in text_content]
        
        suspicious_links = []
        for url in urls:
            url_res = cls.analyze_url(url)
            if url_res["is_suspicious"]:
                suspicious_links.append(url)

        # Hybrid Score Algorithm
        kw_score = min(len(matched_kws) * 15, 45)
        link_score = 50 if len(suspicious_links) > 0 else (15 if len(urls) > 0 else 0)
        
        total_score = min(kw_score + link_score, 100)
        fraud_prob = float(total_score)
        
        is_fraud = total_score >= 45

        return {
            "is_fraud": is_fraud,
            "prediction": "FRAUD / PHISHING EMAIL" if is_fraud else "SAFE EMAIL",
            "risk_score": float(total_score),
            "fraud_probability": fraud_prob,
            "suspicious_links": suspicious_links,
            "matched_keywords": matched_kws
        }
