def calculate_risk_score(check_results):
    """
    Calculates the final risk score based on check results.
    Returns (score, label, reasons).

    Scoring philosophy:
    - Blacklist hit → immediate Fraudulent (100), no appeal
    - Other signals add to a risk score (0-100)
    - Labels: Safe (<20), Caution (20-49), Suspicious (50-79), Fraudulent (80+)
    """
    score = 0
    reasons = []

    # Unpack results
    blacklist = check_results.get("blacklist", {})
    domain_age = check_results.get("domain_age", 0)
    https_valid = check_results.get("https_valid", True)
    patterns = check_results.get("patterns", {})
    content_analysis = check_results.get("content_analysis", {})
    dns_analysis = check_results.get("dns_analysis", {})

    # ----------------------------------------------------------------
    # 1. BLACKLIST CHECK — Hard override. No other signals apply.
    # ----------------------------------------------------------------
    is_listed = (
        blacklist.get("listed", False)
        if isinstance(blacklist, dict)
        else blacklist
    )

    if is_listed:
        risk_level = blacklist.get("risk_level", "High")
        category = blacklist.get("category", "Malicious")
        source = blacklist.get("source", "Blocklist")
        if risk_level == "Critical":
            reasons.append(f"⛔ CRITICAL: Domain is blacklisted as {category} (Source: {source})")
        else:
            reasons.append(f"⛔ Domain is on a threat blocklist: {category} (Source: {source})")
        return 100, "Fraudulent", reasons

    # ----------------------------------------------------------------
    # 2. HTTPS CHECK
    # ----------------------------------------------------------------
    if not https_valid:
        score += 20
        reasons.append("⚠️ Not using HTTPS — data sent over this site is not encrypted")
    else:
        reasons.append("✅ Uses HTTPS with a valid SSL certificate")

    # ----------------------------------------------------------------
    # 3. DOMAIN AGE
    # ----------------------------------------------------------------
    if domain_age == -1:
        # WHOIS lookup failed — treat as mildly informational, not heavily penalised
        reasons.append("ℹ️ Domain age could not be determined (WHOIS unavailable)")
    elif domain_age < 30:
        score += 25
        reasons.append(f"⚠️ Domain is extremely new ({domain_age} days old — under 1 month)")
    elif domain_age < 180:
        score += 10
        reasons.append(f"ℹ️ Domain is relatively new ({domain_age} days old — under 6 months)")
    else:
        reasons.append(f"✅ Domain is established ({domain_age} days old)")

    # ----------------------------------------------------------------
    # 4. DNS / EMAIL INFRASTRUCTURE
    # ----------------------------------------------------------------
    if not dns_analysis.get("mx_records", False):
        # Reduced from +30 → +15; personal/hobby sites legitimately lack MX
        score += 15
        reasons.append("⚠️ No email servers (MX records) found — legitimate businesses usually have email")
    else:
        reasons.append("✅ Email infrastructure (MX records) confirmed")

    # ----------------------------------------------------------------
    # 5. SUSPICIOUS URL PATTERNS
    # ----------------------------------------------------------------
    if patterns.get("ip_based"):
        score += 25
        reasons.append("⚠️ URL uses a raw IP address instead of a domain name — common in phishing")

    if patterns.get("suspicious_tld"):
        score += 10
        reasons.append("⚠️ Potentially risky top-level domain (.xyz, .tk, .pw, etc.)")

    if patterns.get("hyphens"):
        score += 8
        reasons.append("⚠️ Domain name contains excessive hyphens — common in impersonation attacks")

    keywords_found = patterns.get("keywords", [])
    if keywords_found:
        keyword_penalty = min(20, len(keywords_found) * 8)
        score += keyword_penalty
        reasons.append(f"⚠️ Suspicious keywords in domain name: {', '.join(keywords_found)}")

    # ----------------------------------------------------------------
    # 6. CONTENT ANALYSIS
    # ----------------------------------------------------------------
    urgency = content_analysis.get("urgency_score", 0)
    sensitive = content_analysis.get("has_sensitive_keywords", False)
    bad_link_ratio = content_analysis.get("external_link_ratio", 0) > 0.8

    if urgency > 2:
        score += 15
        reasons.append(f"⚠️ High-pressure language detected ({urgency} urgency phrases found)")
    elif urgency > 0:
        score += 5
        reasons.append(f"ℹ️ Some urgency language detected ({urgency} phrase(s))")

    if sensitive and not https_valid:
        score += 40
        reasons.append("⛔ CRITICAL: Site requests sensitive info (passwords/cards) without SSL encryption")
    elif sensitive:
        score += 5
        reasons.append("ℹ️ Page requests sensitive information (entered over HTTPS — less risk)")

    if bad_link_ratio:
        score += 10
        reasons.append("⚠️ Suspicious link profile — majority of links point to external domains")

    # ----------------------------------------------------------------
    # FINAL LABEL
    # ----------------------------------------------------------------
    score = min(100, score)

    if score >= 80:
        label = "Fraudulent"
    elif score >= 50:
        label = "Suspicious"
    elif score >= 20:
        label = "Caution"
    else:
        label = "Safe"

    return score, label, reasons
