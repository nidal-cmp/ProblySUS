"""
Privacy Analyzer Module — ProblySUS
=====================================
Analyzes privacy signals: cookies, third-party scripts,
tracking cookies, and browser fingerprinting attempts.
"""

import logging
import re
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Known fingerprinting API patterns in JavaScript
FINGERPRINT_PATTERNS = [
    (r"\.toDataURL\s*\(", "canvas"),
    (r"getContext\s*\(\s*['\"]webgl", "webgl"),
    (r"getContext\s*\(\s*['\"]2d", "canvas"),
    (r"AudioContext", "audio"),
    (r"webkitAudioContext", "audio"),
    (r"navigator\.plugins", "plugins"),
    (r"navigator\.languages", "language"),
    (r"screen\.colorDepth", "screen"),
    (r"navigator\.hardwareConcurrency", "hardware"),
    (r"navigator\.deviceMemory", "hardware"),
    (r"navigator\.getBattery", "battery"),
    (r"RTCPeerConnection", "webrtc"),
    (r"createDataChannel", "webrtc"),
]

# Browser headers for requests
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def analyze_privacy(url, html_content=None):
    """
    Analyze privacy signals from a website.

    Args:
        url: The URL to analyze.
        html_content: Optional pre-fetched HTML. If None, fetches the URL.

    Returns dict with:
    - cookie_count: number of cookies set via Set-Cookie headers
    - third_party_script_count: number of third-party script domains
    - tracking_cookie_names: list of cookie names that look like trackers
    - tracking_cookie_count: number of tracking-like cookies
    - fingerprinting_signals: list of detected fingerprinting techniques
    - fingerprinting_score: 0-5 rating of fingerprinting intensity
    - privacy_grade: "good" | "moderate" | "poor" | "invasive"
    """
    result = {
        "cookie_count": 0,
        "third_party_script_count": 0,
        "tracking_cookie_names": [],
        "tracking_cookie_count": 0,
        "fingerprinting_signals": [],
        "fingerprinting_score": 0,
        "privacy_grade": "good",
    }

    response = None
    parsed_origin = urlparse(url)
    origin_domain = parsed_origin.hostname or ""

    # --- Fetch page if needed (to get headers) ---
    try:
        response = requests.get(
            url,
            timeout=8,
            headers=BROWSER_HEADERS,
            verify=True,
            allow_redirects=True,
        )
        if html_content is None:
            html_content = response.text
    except Exception as e:
        logger.warning(f"Could not fetch {url} for privacy analysis: {e}")
        return result

    # --- 1. Cookie Analysis ---
    if response:
        set_cookie_headers = response.headers.get("Set-Cookie", "")
        # Count cookies from all Set-Cookie headers
        raw_cookies = response.headers
        cookie_names = []
        for key, value in raw_cookies.items():
            if key.lower() == "set-cookie":
                # Extract cookie name (before the = sign)
                cookie_name = value.split("=")[0].strip()
                cookie_names.append(cookie_name)

        # Also check the cookies jar
        if hasattr(response, "cookies"):
            for cookie in response.cookies:
                if cookie.name not in cookie_names:
                    cookie_names.append(cookie.name)

        result["cookie_count"] = len(cookie_names)

        # Identify tracking-like cookie names
        tracking_patterns = [
            "_ga", "_gid", "_gat", "_fbp", "_fbc", "_gcl",
            "__utma", "__utmb", "__utmc", "__utmz", "_hjid",
            "_tt_", "_ttp", "_uetsid", "_uetvid", "_clck", "_clsk",
            "NID", "IDE", "DSID", "FLC", "AID", "TAID",
        ]
        for name in cookie_names:
            name_lower = name.lower()
            for pattern in tracking_patterns:
                if pattern.lower() in name_lower:
                    result["tracking_cookie_names"].append(name)
                    break

        result["tracking_cookie_count"] = len(result["tracking_cookie_names"])

    # --- 2. Third-Party Script Analysis ---
    if html_content:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            third_party_domains = set()

            for script in soup.find_all("script", src=True):
                try:
                    src_parsed = urlparse(script["src"])
                    script_domain = src_parsed.hostname or ""
                    if script_domain:
                        clean_origin = origin_domain.lstrip("www.")
                        clean_script = script_domain.lstrip("www.")
                        if not clean_script.endswith(clean_origin) and clean_script != clean_origin:
                            third_party_domains.add(script_domain)
                except Exception:
                    pass

            result["third_party_script_count"] = len(third_party_domains)

        except ImportError:
            logger.warning("BeautifulSoup not available — third-party script analysis skipped")

    # --- 3. Fingerprinting Detection ---
    if html_content:
        detected_techniques = set()
        for pattern, technique in FINGERPRINT_PATTERNS:
            if re.search(pattern, html_content, re.IGNORECASE):
                detected_techniques.add(technique)

        result["fingerprinting_signals"] = sorted(detected_techniques)
        # Score: each unique technique adds 1 point, max 5
        result["fingerprinting_score"] = min(5, len(detected_techniques))

    # --- 4. Privacy Grade ---
    grade_score = 0
    if result["tracking_cookie_count"] >= 5:
        grade_score += 3
    elif result["tracking_cookie_count"] >= 2:
        grade_score += 1

    if result["third_party_script_count"] >= 10:
        grade_score += 3
    elif result["third_party_script_count"] >= 5:
        grade_score += 2
    elif result["third_party_script_count"] >= 2:
        grade_score += 1

    if result["fingerprinting_score"] >= 4:
        grade_score += 3
    elif result["fingerprinting_score"] >= 2:
        grade_score += 1

    if grade_score >= 7:
        result["privacy_grade"] = "invasive"
    elif grade_score >= 4:
        result["privacy_grade"] = "poor"
    elif grade_score >= 2:
        result["privacy_grade"] = "moderate"
    else:
        result["privacy_grade"] = "good"

    return result
