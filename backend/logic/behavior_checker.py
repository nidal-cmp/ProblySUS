"""
Behavior Analysis Module — ProblySUS
=====================================
Analyzes runtime website behavior using Playwright headless browser.
Tracks redirects, monitors network requests, and detects suspicious domains.

Falls back gracefully if Playwright is unavailable.
"""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# TLDs commonly abused in phishing / malware campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "pw", "cc", "buzz", "surf", "monster", "icu", "fun", "casa",
    "rest", "hair", "beauty", "quest", "sbs", "bond",
}


def _is_suspicious_domain(domain):
    """Check if a domain looks suspicious (IP-based, suspicious TLD, etc.)."""
    if not domain:
        return False

    # IP-based host
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return True

    # Suspicious TLD
    parts = domain.rsplit(".", 1)
    if len(parts) == 2 and parts[1].lower() in SUSPICIOUS_TLDS:
        return True

    # Excessively long subdomain chains (>3 levels) — often phishing
    if domain.count(".") > 3:
        return True

    return False


def _safe_defaults():
    """Return safe default output when analysis cannot run."""
    return {
        "redirect_count": 0,
        "redirect_chain": [],
        "external_request_count": 0,
        "external_requests": [],
        "suspicious_domains": [],
        "page_title": None,
        "final_url": None,
        "error": None,
    }


def analyze_behavior(url):
    """
    Analyze runtime behavior of a website using a headless browser.

    Returns dict with:
    - redirect_count: number of redirects the page triggered
    - redirect_chain: list of URLs in the redirect sequence
    - external_request_count: number of requests to external domains
    - external_requests: list of external domains contacted
    - suspicious_domains: external domains flagged as suspicious
    - page_title: title of the final page
    - final_url: the URL after all redirects
    - error: error message if analysis failed, else None
    """
    result = _safe_defaults()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.warning(
            "Playwright not installed — behavior analysis skipped. "
            "Run: pip install playwright && playwright install chromium"
        )
        result["error"] = "Playwright not installed"
        return result

    parsed_origin = urlparse(url)
    origin_domain = parsed_origin.hostname or ""

    redirect_chain = []
    external_domains = set()
    all_requests = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )
            page = context.new_page()

            # Track redirects
            def on_response(response):
                status = response.status
                if 300 <= status < 400:
                    redirect_chain.append(response.url)

            page.on("response", on_response)

            # Track all network requests
            def on_request(request):
                try:
                    req_url = request.url
                    req_domain = urlparse(req_url).hostname or ""
                    all_requests.append(req_domain)
                    if req_domain and req_domain != origin_domain:
                        # Strip www. for comparison
                        clean_origin = origin_domain.lstrip("www.")
                        clean_req = req_domain.lstrip("www.")
                        if not clean_req.endswith(clean_origin):
                            external_domains.add(req_domain)
                except Exception:
                    pass

            page.on("request", on_request)

            # Navigate with timeout
            page.goto(url, wait_until="domcontentloaded", timeout=8000)

            # Brief wait to capture late-firing requests
            page.wait_for_timeout(1500)

            result["page_title"] = page.title() or None
            result["final_url"] = page.url

            browser.close()

        # Also count the main navigation redirects (URL changed)
        if result["final_url"] and result["final_url"] != url:
            if url not in redirect_chain:
                redirect_chain.insert(0, url)
            if result["final_url"] not in redirect_chain:
                redirect_chain.append(result["final_url"])

        result["redirect_count"] = max(0, len(redirect_chain) - 1)
        result["redirect_chain"] = redirect_chain[:10]  # Cap for sanity

        ext_list = sorted(external_domains)
        result["external_request_count"] = len(ext_list)
        result["external_requests"] = ext_list[:50]  # Cap for sanity

        suspicious = [d for d in ext_list if _is_suspicious_domain(d)]
        result["suspicious_domains"] = suspicious

    except Exception as e:
        logger.error(f"Behavior analysis failed for {url}: {e}", exc_info=True)
        result["error"] = str(e)

    return result
