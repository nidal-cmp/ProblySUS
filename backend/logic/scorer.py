"""
Risk Scoring Engine — ProblySUS
=================================
Multi-signal scoring engine with explainable risk assessment.

Scoring philosophy:
- Blacklist hit → immediate Fraudulent (100), no appeal
- 10 signal categories contribute to a composite risk score (0-100)
- Confidence-weighted: high-confidence signals (blacklist, SSL) carry hard
  penalties; low-confidence signals (trackers, privacy) are soft indicators.
- Labels: Safe (<20), Caution (20-49), Suspicious (50-79), Fraudulent (80+)

Weight budget (excluding blacklist override):
    Category          | Max Penalty | Rationale
    ------------------|-------------|--------------------------------------------
    HTTPS/SSL         |  10         | No encryption = real risk, but common on hobby sites
    Domain age        |  20         | Very new domains are high-signal for phishing
    DNS/MX records    |   8         | Missing email infra = mild indicator
    URL patterns      |  18         | IP-based URLs, phishing keywords = strong signal
    Content analysis  |  15         | Urgency language, sensitive data requests
    Behavior          |  15         | Redirects, suspicious runtime requests
    Network           |  10         | External domain risk profile
    Trackers          |   2         | Trackers are normal; excessive = mild privacy concern
    Privacy           |   2         | Fingerprinting, tracking cookies
    Malicious scripts |  10         | Credential stealers, miners, obfuscated code
    ------------------|-------------|
    TOTAL (soft max)  | 100         |

The actual score can exceed individual category limits via compound signals
(e.g. sensitive data + no SSL = extra penalty). Final score is capped at 100.
"""

import re
import logging

logger = logging.getLogger(__name__)


def calculate_risk_score(check_results):
    """
    Calculates the final risk score based on all check results.
    Returns (score, label, reasons).
    """
    score = 0
    reasons = []

    # Unpack existing results
    blacklist = check_results.get("blacklist", {})
    domain_age = check_results.get("domain_age", 0)
    https_valid = check_results.get("https_valid", True)
    patterns = check_results.get("patterns", {})
    content_analysis = check_results.get("content_analysis", {})
    dns_analysis = check_results.get("dns_analysis", {})

    # Unpack new analyzer results
    behavior = check_results.get("behavior", {})
    network = check_results.get("network", {})
    trackers = check_results.get("trackers", {})
    privacy = check_results.get("privacy", {})

    # ================================================================
    # 1. BLACKLIST — Hard override. Instant Fraudulent. No appeal.
    # ================================================================
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

    # ================================================================
    # 2. HTTPS / SSL CHECK  (max: 10)
    # ================================================================
    if not https_valid:
        score += 10
        reasons.append("⚠️ Not using HTTPS — data sent over this site is not encrypted")
    else:
        reasons.append("✅ Uses HTTPS with a valid SSL certificate")

    # ================================================================
    # 3. DOMAIN AGE  (max: 20)
    # ================================================================
    if domain_age == -1:
        score += 3
        reasons.append("ℹ️ Domain age could not be determined (WHOIS unavailable)")
    elif domain_age < 7:
        score += 20
        reasons.append(f"⛔ Domain is brand new ({domain_age} days old — under 1 week)")
    elif domain_age < 30:
        score += 15
        reasons.append(f"⚠️ Domain is extremely new ({domain_age} days old — under 1 month)")
    elif domain_age < 90:
        score += 8
        reasons.append(f"ℹ️ Domain is relatively new ({domain_age} days old — under 3 months)")
    elif domain_age < 180:
        score += 3
        reasons.append(f"ℹ️ Domain is under 6 months old ({domain_age} days)")
    else:
        reasons.append(f"✅ Domain is established ({domain_age} days old)")

    # ================================================================
    # 4. DNS / EMAIL INFRASTRUCTURE  (max: 8)
    # ================================================================
    has_mx = dns_analysis.get("mx_records", False)
    has_spf = dns_analysis.get("spf_record", False)

    if not has_mx and not has_spf:
        score += 8
        reasons.append("⚠️ No email servers or SPF records — legitimate businesses usually have email infrastructure")
    elif not has_mx:
        score += 5
        reasons.append("⚠️ No email servers (MX records) found")
    elif not has_spf:
        score += 2
        reasons.append("ℹ️ No SPF record found — email authentication not configured")
    else:
        reasons.append("✅ Email infrastructure (MX + SPF) confirmed")

    # ================================================================
    # 5. URL PATTERNS  (max: 18)
    # ================================================================
    pattern_score = 0

    if patterns.get("ip_based"):
        pattern_score += 10
        reasons.append("⚠️ URL uses a raw IP address instead of a domain — common in phishing")

    if patterns.get("suspicious_tld"):
        pattern_score += 4
        reasons.append("⚠️ Potentially risky top-level domain (.xyz, .tk, .pw, etc.)")

    if patterns.get("hyphens"):
        pattern_score += 3
        reasons.append("⚠️ Domain name contains excessive hyphens — common in impersonation")

    keywords_found = patterns.get("keywords", [])
    if keywords_found:
        keyword_penalty = min(8, len(keywords_found) * 3)
        pattern_score += keyword_penalty
        reasons.append(f"⚠️ Suspicious keywords in domain: {', '.join(keywords_found)}")

    score += min(18, pattern_score)

    # ================================================================
    # 6. CONTENT ANALYSIS  (max: 15)
    # ================================================================
    content_score = 0
    urgency = content_analysis.get("urgency_score", 0)
    sensitive = content_analysis.get("has_sensitive_keywords", False)
    bad_link_ratio = content_analysis.get("external_link_ratio", 0) > 0.8

    if urgency > 3:
        content_score += 8
        reasons.append(f"⚠️ High-pressure language detected ({urgency} urgency phrases)")
    elif urgency > 1:
        content_score += 4
        reasons.append(f"ℹ️ Some urgency language detected ({urgency} phrase(s))")
    elif urgency > 0:
        content_score += 1
        reasons.append(f"ℹ️ Mild urgency language detected ({urgency} phrase)")

    if sensitive and not https_valid:
        # Compound signal: sensitive data + no encryption = very dangerous
        content_score += 15
        reasons.append("⛔ CRITICAL: Site requests sensitive info (passwords/cards) WITHOUT encryption")
    elif sensitive:
        content_score += 3
        reasons.append("ℹ️ Page requests sensitive information (over HTTPS — lower risk)")

    if bad_link_ratio:
        content_score += 4
        reasons.append("⚠️ Suspicious link profile — majority of links point to external domains")

    score += min(15, content_score)

    # ================================================================
    # 7. BEHAVIOR ANALYSIS  (max: 15)   [NEW]
    # ================================================================
    if behavior and not behavior.get("error"):
        behavior_score = 0
        redirect_count = behavior.get("redirect_count", 0)
        page_title = behavior.get("page_title")
        suspicious_domains = behavior.get("suspicious_domains", [])
        external_count = behavior.get("external_request_count", 0)

        # Redirect analysis
        # Note: 5-6 redirects are normal for legitimate auth flows (Gmail, OAuth, etc)
        # Only heavily penalize if HTTPS is missing or title suggests phishing
        if redirect_count >= 10:
            behavior_score += 8
            reasons.append(f"⚠️ Excessive redirects detected ({redirect_count} redirects) — possible redirect chain attack")
        elif redirect_count >= 7:
            behavior_score += 4
            reasons.append(f"⚠️ Multiple redirects detected ({redirect_count} redirects)")
        elif redirect_count >= 3:
            behavior_score += 1
            reasons.append(f"ℹ️ Page redirects detected ({redirect_count})")
        
        # Redirect without proper page title is suspicious (possible credential harvesting)
        # Consider titles like "Redirecting...", empty, or very short as suspicious
        is_invalid_title = (
            not page_title or 
            page_title.lower() in ("redirecting...", "redirect", "loading", "") or
            len(str(page_title).strip()) < 3
        )
        if redirect_count > 0 and is_invalid_title:
            behavior_score += 6
            reasons.append(f"⚠️ Page redirected but invalid/missing title — possible stealth redirect or credential harvesting")

        # Suspicious domains contacted at runtime
        if len(suspicious_domains) >= 3:
            behavior_score += 7
            reasons.append(f"⛔ Multiple suspicious domains contacted: {', '.join(suspicious_domains[:5])}")
        elif len(suspicious_domains) >= 1:
            behavior_score += 4
            reasons.append(f"⚠️ Suspicious domain contacted: {', '.join(suspicious_domains)}")

        # Excessive external requests
        if external_count > 30:
            behavior_score += 3
            reasons.append(f"⚠️ Heavy external network activity ({external_count} external requests)")

        score += min(18, behavior_score)  # Increased from 15 to 18 to allow for redirect+no-title penalty
    elif behavior and behavior.get("error"):
        # Behavior analysis failed — suspicious, add penalty
        score += 4
        reasons.append("⚠️ Behavior analysis failed — unable to verify runtime behavior")

    # ================================================================
    # 8. NETWORK INTELLIGENCE  (max: 10)   [NEW]
    # ================================================================
    if network:
        network_score = 0
        suspicious_ext_count = network.get("suspicious_external_count", 0)
        risk_level = network.get("risk_level", "low")

        if risk_level == "high":
            network_score += 7
            reasons.append(f"⚠️ High network risk — {suspicious_ext_count} suspicious external domains")
        elif risk_level == "medium":
            network_score += 3
            susp_domains = network.get("suspicious_domains", [])
            if susp_domains:
                reasons.append(f"⚠️ Suspicious external domains: {', '.join(susp_domains[:3])}")
            else:
                reasons.append("ℹ️ Elevated external network activity")

        # Excessive total external dependencies
        ext_domain_count = network.get("external_domain_count", 0)
        if ext_domain_count > 25:
            network_score += 3
            reasons.append(f"ℹ️ Page contacts {ext_domain_count} external domains")

        score += min(10, network_score)

    # ================================================================
    # 9. TRACKER DETECTION  (max: 2)   [NEW]
    # ================================================================
    if trackers:
        tracker_count = trackers.get("tracker_count", 0)
        tracker_names = trackers.get("trackers_detected", [])

        if tracker_count > 8:
            score += 2
            reasons.append(f"ℹ️ Heavy tracking footprint ({tracker_count} trackers: {', '.join(tracker_names[:4])}...)")
        elif tracker_count > 5:
            score += 1
            reasons.append(f"ℹ️ Multiple trackers detected ({tracker_count}: {', '.join(tracker_names[:3])})")
        elif tracker_count > 0:
            reasons.append(f"✅ Standard tracking ({tracker_count} tracker(s) found)")

    # ================================================================
    # 10. PRIVACY SIGNALS  (max: 2)   [NEW]
    # ================================================================
    if privacy:
        privacy_grade = privacy.get("privacy_grade", "good")
        fingerprinting = privacy.get("fingerprinting_signals", [])
        tracking_cookies = privacy.get("tracking_cookie_count", 0)

        if privacy_grade == "invasive":
            score += 2
            reasons.append(f"⚠️ Invasive privacy practices — fingerprinting ({', '.join(fingerprinting)}), {tracking_cookies} tracking cookies")
        elif privacy_grade == "poor":
            score += 1
            if fingerprinting:
                reasons.append(f"ℹ️ Browser fingerprinting detected ({', '.join(fingerprinting)})")
            else:
                reasons.append(f"ℹ️ Elevated tracking cookies ({tracking_cookies})")

    # ================================================================
    # 11. MALICIOUS SCRIPT DETECTION  (max: 10)   [NEW]
    # ================================================================
    script_score = 0
    html_content = check_results.get("html_content", "")
    
    if html_content:
        # Check for credential stealing patterns
        credential_patterns = [
            r'password.*value', r'username.*value', r'email.*value',
            r'document\.cookie', r'localStorage', r'sessionStorage',
            r'XMLHttpRequest.*password', r'fetch.*password'
        ]
        
        credential_matches = sum(1 for pattern in credential_patterns 
                               if re.search(pattern, html_content, re.IGNORECASE))
        if credential_matches > 0:
            script_score += min(4, credential_matches * 2)
            reasons.append(f"⚠️ Potential credential harvesting scripts detected ({credential_matches} patterns)")
        
        # Check for crypto mining patterns
        mining_patterns = [
            r'coinhive', r'cryptonight', r'monero', r'mining',
            r'webminer', r'cryptojacking', r'cpu.*mine'
        ]
        
        mining_matches = sum(1 for pattern in mining_patterns 
                           if re.search(pattern, html_content, re.IGNORECASE))
        if mining_matches > 0:
            script_score += min(3, mining_matches * 2)
            reasons.append(f"⛔ Crypto mining scripts detected ({mining_matches} patterns)")
        
        # Check for obfuscated scripts (suspicious patterns)
        obfuscation_patterns = [
            r'eval\(', r'Function\(', r'setTimeout.*eval',
            r'document\.write.*script', r'fromCharCode',
            r'unescape\(', r'decodeURIComponent.*eval'
        ]
        
        obfuscation_matches = sum(1 for pattern in obfuscation_patterns 
                                if re.search(pattern, html_content, re.IGNORECASE))
        
        # Context-aware obfuscation penalty
        if obfuscation_matches > 0:
            if domain_age != -1 and domain_age < 90:
                # New domain + obfuscation -> Significant penalty
                penalty = min(8, obfuscation_matches * 2)
                script_score += penalty
                reasons.append(f"⛔ Obfuscated scripts on a NEW domain ({obfuscation_matches} patterns) — high risk of malware")
            else:
                # Old/Unknown domain + obfuscation -> Low/No penalty
                if obfuscation_matches > 3:
                    script_score += 2
                    reasons.append(f"ℹ️ Multiple obfuscated script patterns detected ({obfuscation_matches}) — common in minified JS/trackers")
                else:
                    reasons.append(f"✅ Minor script patterns detected ({obfuscation_matches}) — considered normal for established domains")
        
        # Check for redirect scripts
        redirect_patterns = [
            r'window\.location', r'location\.href', r'location\.replace',
            r'<meta.*refresh', r'setTimeout.*location'
        ]
        
        redirect_matches = sum(1 for pattern in redirect_patterns 
                             if re.search(pattern, html_content, re.IGNORECASE))
        if redirect_matches > 0 and redirect_count == 0:
            # If we detect redirect scripts but no redirects were caught, add penalty
            script_score += 2
            reasons.append(f"⚠️ Client-side redirect scripts detected but no redirects observed")
    
    score += min(10, script_score)
    # New domain + suspicious behavior = amplified risk
    if domain_age != -1 and domain_age < 30:
        if behavior and behavior.get("redirect_count", 0) >= 3:
            score += 5
            reasons.append("⛔ COMPOUND: New domain with aggressive redirects — high phishing risk")

        if network and network.get("suspicious_external_count", 0) >= 2:
            score += 5
            reasons.append("⛔ COMPOUND: New domain contacting suspicious servers")

    # No HTTPS + sensitive content + urgency = amplified
    if not https_valid and sensitive and urgency > 1:
        score += 5
        reasons.append("⛔ COMPOUND: Unsafe site pressuring for sensitive data — classic phishing")

    # ================================================================
    # FINAL LABEL
    # ================================================================
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
