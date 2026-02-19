import requests
from bs4 import BeautifulSoup
import logging
import textstat
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

TRUST_PAGES = ["privacy", "terms", "contact", "about", "support", "faq"]

# Keywords that imply urgency or pressure (common in scams)
URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspend", "lock", "verify", "action require", 
    "limited time", "expires", "risk", "unauthorized"
]

# Keywords related to sensitive data requests
SENSITIVE_KEYWORDS = [
    "password", "credit card", "social security", "ssn", "bank account", 
    "confirm identity", "login"
]

def check_content_trust(url):
    """
    Analyzes page content for trust signals and scam patterns.
    Returns a dict of analysis results.
    """
    findings = {
        "trust_pages": [],
        "urgency_score": 0,
        "readability_score": 0,
        "external_link_ratio": 0,
        "has_sensitive_keywords": False
    }

    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "ProblySUS-Scanner/1.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        
        # 1. Trust Pages Check
        links = soup.find_all("a", href=True)
        domain = urlparse(url).netloc
        
        internal_links = 0
        external_links = 0

        for link in links:
            href = link["href"].lower()
            text = link.get_text().lower()
            
            # Trust Pages
            for page in TRUST_PAGES:
                if page in href or page in text:
                    if page not in findings["trust_pages"]:
                        findings["trust_pages"].append(page)
            
            # Link Ratio Analysis
            try:
                link_domain = urlparse(link['href']).netloc
                if not link_domain or link_domain == domain:
                    internal_links += 1
                else:
                    external_links += 1
            except:
                pass

        total_links = internal_links + external_links
        if total_links > 0:
            findings["external_link_ratio"] = external_links / total_links

        # 2. Text Analysis (NLP Lite)
        text_content = soup.get_text(" ", strip=True).lower()
        
        # Urgency Detection
        urgency_count = 0
        for keyword in URGENCY_KEYWORDS:
            if keyword in text_content:
                urgency_count += 1
        findings["urgency_score"] = urgency_count

        # Sensitive Keyword Detection
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in text_content:
                findings["has_sensitive_keywords"] = True
                break

        # Readability (Scams often use simple or broken language)
        # textstat.flesch_reading_ease returns 0-100 (100 = very easy/childish)
        # Scams targeting mass audiences often aim for very high ease (simple phrasing)
        # or have very low ease due to "word salad".
        try:
            findings["readability_score"] = textstat.flesch_reading_ease(text_content)
        except:
            pass

        return findings

    except Exception as e:
        logger.error(f"Content check failed: {e}")
        return findings
