def calculate_risk_score(check_results):
    """
    Calculates the final risk score based on check results.
    Returns (score, label, reasons).
    """
    score = 0
    reasons = []

    # Unpack results
    blacklist = check_results.get("blacklist", {})
    domain_age = check_results.get("domain_age", 0)
    https_valid = check_results.get("https_valid", True)
    patterns = check_results.get("patterns", {})
    
    # New Signals
    content_analysis = check_results.get("content_analysis", {})
    dns_analysis = check_results.get("dns_analysis", {})
    
    trust_score = 50 # Start neutral

    # --- 1. BLACKLIST CHECK (The Hammer) ---
    is_listed = (
        blacklist.get("listed", False)
        if isinstance(blacklist, dict)
        else blacklist
    )

    if is_listed:
        risk_level = blacklist.get("risk_level", "High")
        if risk_level == "Critical":
            score = 100
            reasons.append(f"⛔ CRITICAL: Domain is blacklisted ({blacklist.get('category', 'Malware')})")
            return score, "Fraudulent", reasons
        else:
            score += 50
            reasons.append(f"⚠️ Domain is on a blocklist ({blacklist.get('category', 'Suspicious')})")

    # --- 2. TECHNICAL DNA (DNS/MX) ---
    # Most legit businesses have MX records.
    if not dns_analysis.get("mx_records", False):
        score += 30
        reasons.append("⚠️ No Email Servers (MX Records) found. Real businesses usually have email.")
    else:
        trust_score += 10 # Legit signal

    # --- 3. DOMAIN AGE ---
    if domain_age != -1:
        if domain_age < 30:
            score += 25
            reasons.append("⚠️ Domain is extremely new (< 1 month)")
        elif domain_age < 180:
            score += 10
            reasons.append("ℹ️ Domain is relatively new (< 6 months)")
        else:
            trust_score += 20 # Aged domain is trustworthy

    # --- 4. CONTENT ANALYSIS (NLP) ---
    urgency = content_analysis.get("urgency_score", 0)
    sensitive = content_analysis.get("has_sensitive_keywords", False)
    bad_link_ratio = content_analysis.get("external_link_ratio", 0) > 0.8 # Mostly external links

    if urgency > 2:
        score += 15
        reasons.append(f"⚠️ High-pressure language detected ({urgency} urgency keywords)")
    
    if sensitive and not https_valid:
        score += 40
        reasons.append("⛔ CRITICAL: Asking for sensitive info (Password/Credit Card) without SSL!")
    elif sensitive:
        score += 5
        reasons.append("ℹ️ Page requests sensitive information")

    if bad_link_ratio:
        score += 10
        reasons.append("⚠️ Suspicious Link Profile (Mostly external/login links)")

    # --- 5. PATTERNS & HTTPS ---
    if not https_valid:
        score += 20
        reasons.append("⚠️ Not using HTTPS")

    if patterns.get("ip_based"):
        score += 20
        reasons.append("⚠️ IP-based URL (Typical for phishing)")
    
    if patterns.get("suspicious_tld"):
        score += 10
        reasons.append("⚠️ Potentially risky TLD (.xyz, .tk, etc.)")

    # --- FINAL CALCULATION ---
    # Cap score
    score = min(100, score)

    # Determine Label
    if score >= 80:
        label = "Fraudulent"
    elif score >= 50:
        label = "Suspicious"
    elif score >= 20:
        label = "Caution"
    else:
        label = "Safe"
    
    return score, label, reasons
