import requests
from bs4 import BeautifulSoup
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

TRUST_PAGES = ["privacy", "terms", "contact", "about", "support", "faq"]

# Keywords that imply urgency or pressure (common in scams)
URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspend", "lock", "verify now", "action required",
    "limited time", "expires soon", "unauthorized access", "account at risk",
    "click immediately", "respond now"
]

# Keywords related to sensitive data requests
SENSITIVE_KEYWORDS = [
    "password", "credit card", "social security", "ssn", "bank account",
    "confirm identity", "enter your pin", "billing information"
]

# Realistic browser User-Agent to avoid bot-blocking
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


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
        "has_sensitive_keywords": False,
        "reachable": False,
    }

    try:
        response = requests.get(
            url,
            timeout=8,
            headers=BROWSER_HEADERS,
            verify=True,
            allow_redirects=True,
        )
        findings["reachable"] = True
        soup = BeautifulSoup(response.text, "html.parser")

        # 1. Trust Pages Check
        links = soup.find_all("a", href=True)
        domain = urlparse(url).netloc

        internal_links = 0
        external_links = 0

        for link in links:
            href = link.get("href", "").lower()
            text = link.get_text().lower()

            # Trust Pages
            for page in TRUST_PAGES:
                if page in href or page in text:
                    if page not in findings["trust_pages"]:
                        findings["trust_pages"].append(page)

            # Link Ratio Analysis
            try:
                link_domain = urlparse(link["href"]).netloc
                if not link_domain or link_domain == domain:
                    internal_links += 1
                else:
                    external_links += 1
            except Exception as e:
                logger.debug(f"Could not parse link href: {e}")

        total_links = internal_links + external_links
        if total_links > 0:
            findings["external_link_ratio"] = external_links / total_links

        # 2. Text Analysis
        text_content = soup.get_text(" ", strip=True).lower()

        # Urgency Detection
        urgency_count = sum(1 for kw in URGENCY_KEYWORDS if kw in text_content)
        findings["urgency_score"] = urgency_count

        # Sensitive Keyword Detection
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in text_content:
                findings["has_sensitive_keywords"] = True
                break

        # Readability Score
        try:
            import textstat
            findings["readability_score"] = textstat.flesch_reading_ease(text_content)
        except ImportError:
            logger.debug("textstat not available, skipping readability check")
        except Exception as e:
            logger.debug(f"Readability check failed: {e}")

    except requests.exceptions.SSLError as e:
        logger.warning(f"SSL error fetching content for {url}: {e}")
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logger.info(f"Could not reach {url} for content check: {type(e).__name__}")
    except Exception as e:
        logger.error(f"Content check failed for {url}: {e}")

    return findings
