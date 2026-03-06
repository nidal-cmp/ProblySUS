"""
Tracker Detection Module — ProblySUS
======================================
Detects analytics and advertising trackers in HTML source by scanning
script/iframe/img/link tags against a known tracker database.
"""

import json
import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Load tracker database once at module import
_TRACKER_DB = {}
_TRACKER_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "trackers.json",
)

try:
    with open(_TRACKER_DB_PATH, "r", encoding="utf-8") as f:
        _TRACKER_DB = json.load(f)
    logger.info(f"Loaded {len(_TRACKER_DB)} tracker signatures from {_TRACKER_DB_PATH}")
except FileNotFoundError:
    logger.warning(f"Tracker database not found at {_TRACKER_DB_PATH}")
except json.JSONDecodeError as e:
    logger.error(f"Failed to parse tracker database: {e}")


def _match_tracker(url_or_src):
    """Check if a URL/src matches any known tracker domain. Returns (domain, name) or None."""
    if not url_or_src:
        return None

    src_lower = url_or_src.lower()

    # Try to extract domain from the src attribute
    try:
        parsed = urlparse(url_or_src if "://" in url_or_src else f"https://{url_or_src}")
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    for tracker_domain, tracker_name in _TRACKER_DB.items():
        # Match against hostname
        if hostname and (hostname == tracker_domain or hostname.endswith(f".{tracker_domain}")):
            return tracker_domain, tracker_name
        # Fallback: substring match in full src (catches inline paths like "facebook.com/tr")
        if tracker_domain in src_lower:
            return tracker_domain, tracker_name

    return None


def detect_trackers(html_content):
    """
    Scan HTML content for known analytics and advertising trackers.

    Args:
        html_content: Raw HTML string of the page.

    Returns dict with:
    - trackers_detected: list of tracker names found
    - tracker_count: number of unique trackers
    - tracker_domains: list of matched tracker domains
    - tracker_details: list of {name, domain, element} dicts
    """
    result = {
        "trackers_detected": [],
        "tracker_count": 0,
        "tracker_domains": [],
        "tracker_details": [],
    }

    if not html_content or not _TRACKER_DB:
        return result

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        logger.warning("BeautifulSoup not available — tracker detection skipped")
        return result

    try:
        soup = BeautifulSoup(html_content, "html.parser")
        seen_trackers = {}  # domain -> {name, element}

        # Scan <script src="...">
        for tag in soup.find_all("script", src=True):
            match = _match_tracker(tag["src"])
            if match and match[0] not in seen_trackers:
                seen_trackers[match[0]] = {"name": match[1], "element": "script"}

        # Scan <iframe src="...">
        for tag in soup.find_all("iframe", src=True):
            match = _match_tracker(tag["src"])
            if match and match[0] not in seen_trackers:
                seen_trackers[match[0]] = {"name": match[1], "element": "iframe"}

        # Scan <img src="..."> (tracking pixels)
        for tag in soup.find_all("img", src=True):
            match = _match_tracker(tag["src"])
            if match and match[0] not in seen_trackers:
                seen_trackers[match[0]] = {"name": match[1], "element": "img"}

        # Scan <link href="..."> (prefetch, preconnect to tracker domains)
        for tag in soup.find_all("link", href=True):
            match = _match_tracker(tag["href"])
            if match and match[0] not in seen_trackers:
                seen_trackers[match[0]] = {"name": match[1], "element": "link"}

        # Scan inline <script> content for tracker URLs
        for tag in soup.find_all("script", src=False):
            script_text = tag.string or ""
            if script_text:
                for tracker_domain, tracker_name in _TRACKER_DB.items():
                    if tracker_domain in script_text.lower() and tracker_domain not in seen_trackers:
                        seen_trackers[tracker_domain] = {"name": tracker_name, "element": "inline_script"}

        # Build result
        for domain, info in seen_trackers.items():
            result["trackers_detected"].append(info["name"])
            result["tracker_domains"].append(domain)
            result["tracker_details"].append({
                "name": info["name"],
                "domain": domain,
                "element": info["element"],
            })

        result["tracker_count"] = len(seen_trackers)

    except Exception as e:
        logger.error(f"Tracker detection failed: {e}", exc_info=True)

    return result
