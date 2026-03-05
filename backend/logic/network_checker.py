"""
Network Intelligence Module — ProblySUS
=========================================
Analyzes external domains loaded by a page to identify risk signals:
- Unknown/suspicious TLDs
- IP-based hosts
- Excessive external dependency count
- Domain reputation heuristics
"""

import logging
import re

logger = logging.getLogger(__name__)

# TLDs commonly abused in phishing / malware campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "pw", "cc", "buzz", "surf", "monster", "icu", "fun", "casa",
    "rest", "hair", "beauty", "quest", "sbs", "bond", "cfd",
    "lol", "cam", "bar",
}

# Well-known CDN / infrastructure domains that are generally safe
SAFE_INFRA_DOMAINS = {
    "cloudflare.com", "cloudfront.net", "amazonaws.com", "akamai.net",
    "akamaized.net", "fastly.net", "gstatic.com", "googleapis.com",
    "googlevideo.com", "youtube.com", "ytimg.com", "googleusercontent.com",
    "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net", "bootstrapcdn.com",
    "fontawesome.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "recaptcha.net", "gstatic.com", "sentry.io",
}


def _is_safe_infra(domain):
    """Check if a domain belongs to known safe infrastructure."""
    domain_lower = domain.lower()
    for safe in SAFE_INFRA_DOMAINS:
        if domain_lower == safe or domain_lower.endswith(f".{safe}"):
            return True
    return False


def _is_suspicious_domain(domain):
    """Check if a domain looks suspicious."""
    if not domain:
        return False

    # IP-based host
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return True

    # Suspicious TLD
    parts = domain.rsplit(".", 1)
    if len(parts) == 2 and parts[1].lower() in SUSPICIOUS_TLDS:
        return True

    # Excessively long subdomain chains
    if domain.count(".") > 4:
        return True

    # Domain with excessive hyphens (common phishing pattern)
    main_part = domain.split(".")[0]
    if main_part.count("-") > 3:
        return True

    return False


def analyze_network(behavior_result):
    """
    Analyze external domains loaded by the page for risk signals.

    Args:
        behavior_result: dict from behavior_checker.analyze_behavior()
                         Must contain 'external_requests' list of domains.

    Returns dict with:
    - external_domains: all unique external domains contacted
    - external_domain_count: total number of external domains
    - suspicious_domains: domains flagged as suspicious
    - suspicious_external_count: number of suspicious domains
    - safe_infra_domains: known safe CDN/infrastructure domains
    - unknown_domains: external domains that are neither infra nor suspicious
    - risk_level: "low" | "medium" | "high"
    """
    result = {
        "external_domains": [],
        "external_domain_count": 0,
        "suspicious_domains": [],
        "suspicious_external_count": 0,
        "safe_infra_domains": [],
        "unknown_domains": [],
        "risk_level": "low",
    }

    if not behavior_result:
        return result

    external = behavior_result.get("external_requests", [])
    if not external:
        return result

    # Deduplicate and classify
    unique_domains = sorted(set(external))
    suspicious = []
    safe_infra = []
    unknown = []

    for domain in unique_domains:
        if _is_safe_infra(domain):
            safe_infra.append(domain)
        elif _is_suspicious_domain(domain):
            suspicious.append(domain)
        else:
            unknown.append(domain)

    result["external_domains"] = unique_domains
    result["external_domain_count"] = len(unique_domains)
    result["suspicious_domains"] = suspicious
    result["suspicious_external_count"] = len(suspicious)
    result["safe_infra_domains"] = safe_infra
    result["unknown_domains"] = unknown

    # Determine risk level
    if len(suspicious) >= 3:
        result["risk_level"] = "high"
    elif len(suspicious) >= 1 or len(unique_domains) > 20:
        result["risk_level"] = "medium"
    else:
        result["risk_level"] = "low"

    return result
