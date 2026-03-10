import re
import tldextract

# Keywords that are genuinely suspicious when found IN A DOMAIN NAME.
# Kept tight — only terms that real businesses almost never brand themselves with.
# Removed: "login", "secure", "account", "update", "banking" — all too common in legitimate domains.
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "verify",
    "urgent",
    "claim",
    "free-",
    "winner",
    "prize",
    "paypal-",
    "amazon-",
    "google-",
    "microsoft-",
    "apple-",
    "support-",
]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "pw", "cc"]


def check_patterns(url):
    """
    Checks for suspicious patterns in the URL.
    Returns dict of findings.
    """
    extracted = tldextract.extract(url)
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    subdomain = extracted.subdomain.lower()

    findings = {
        "keywords": [],
        "hyphens": False,
        "suspicious_tld": False,
        "ip_based": False,
    }

    # Check for suspicious keywords in domain or subdomain
    # Only match if the keyword appears WITH its hyphen (e.g., "google-" not just "google")
    for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
        # Check for the keyword WITH hyphen for compound words
        if "-" in keyword:
            if keyword in domain or keyword in subdomain:
                findings["keywords"].append(keyword)
        else:
            # For keywords without hyphens, only match whole word boundaries
            # to avoid false positives like "google" in legitimate domains
            if re.search(r'\b' + re.escape(keyword) + r'\b', domain + '-' + subdomain):
                findings["keywords"].append(keyword)

    # Check for excessive hyphens (more than 2 hyphens is unusual for legitimate domains)
    if domain.count("-") > 2 or subdomain.count("-") > 2:
        findings["hyphens"] = True

    # Check TLD
    if suffix in SUSPICIOUS_TLDS:
        findings["suspicious_tld"] = True

    # Check if IP-based (IPv4 pattern)
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(domain) or ip_pattern.match(f"{domain}.{suffix}"):
        findings["ip_based"] = True

    return findings
