from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import threading
import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Logic Modules — Original
from logic.validator import validate_url, check_https_ssl
from logic.whois_checker import check_domain_age
from logic.pattern_checker import check_patterns
from logic.content_checker import check_content_trust
from logic.blacklist_checker import check_blacklist, force_reload_blacklist
from logic.scorer import calculate_risk_score
from logic.dns_checker import check_dns_records
from logic.updater import update_blacklist_source

# Logic Modules — New Analyzers
from logic.behavior_checker import analyze_behavior
from logic.tracker_checker import detect_trackers
from logic.network_checker import analyze_network
from logic.privacy_checker import analyze_privacy

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MAX_URL_LENGTH = 2048

# Performance settings
BEHAVIOR_ANALYSIS_TIMEOUT = 6  # seconds (reduced from ~9.5s)
FAST_MODE_MAX_TIME = 8  # seconds for fast mode


# -----------------------------------------------------------------------
# Background blacklist auto-updater
# Runs once 5 seconds after startup, then repeats every 24 hours.
# This ensures the DB is always fresh without manual intervention.
# -----------------------------------------------------------------------
def _auto_update_blacklist():
    """
    Fetches the latest blacklist in the background and reloads it into memory.
    Reschedules itself every 24 hours.
    """
    try:
        result = update_blacklist_source()
        if result.get("success"):
            force_reload_blacklist()
            logger.info(
                f"[Auto-Update] Blacklist refreshed: "
                f"{result['added_count']} domains indexed "
                f"({result['custom_count']} custom)."
            )
        else:
            logger.warning(f"[Auto-Update] Blacklist update failed: {result.get('error')}")
    except Exception as e:
        logger.error(f"[Auto-Update] Unexpected error during blacklist update: {e}", exc_info=True)
    finally:
        # Reschedule for 24 hours later regardless of success/failure
        timer = threading.Timer(86400, _auto_update_blacklist)
        timer.daemon = True  # Don't block process exit
        timer.start()


# Kick off the first update shortly after startup (non-blocking)
_startup_timer = threading.Timer(5, _auto_update_blacklist)
_startup_timer.daemon = True
_startup_timer.start()


# -----------------------------------------------------------------------
# Global error handler — always return JSON, never HTML stack traces
# -----------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_unexpected_error(e):
    logger.error(f"Unhandled exception: {e}", exc_info=True)
    return jsonify({"error": "An unexpected server error occurred. Please try again."}), 500


@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def handle_405(e):
    return jsonify({"error": "Method not allowed"}), 405


# -----------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "running",
        "service": "Probly URL Scanner",
        "version": "1.1.0"
    }), 200


@app.route("/analyze", methods=["POST"])
def analyze_url():
    """
    Analyze a given URL for scam risk.
    Runs 10 analysis modules and returns a composite risk assessment.

    Optional query parameter: ?fast=true for quicker analysis (skips behavior analysis)
    """
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Request body must be JSON with a 'url' field"}), 400

    url = data["url"]
    fast_mode = request.args.get('fast', 'false').lower() == 'true'

    # --- Input guards ---
    if not isinstance(url, str):
        return jsonify({"error": "URL must be a string"}), 400

    if len(url) > MAX_URL_LENGTH:
        return jsonify({"error": f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"}), 400

    # 1. Validation
    valid_url, error = validate_url(url)
    if not valid_url:
        return jsonify({"error": error}), 400

    # Extract hostname — guard against None (e.g. file:// or malformed URLs)
    parsed = urlparse(valid_url)
    hostname = parsed.hostname
    if not hostname:
        return jsonify({"error": "Could not extract a valid hostname from the URL"}), 400

    # 2. Run original checks (some can be parallelized)
    logger.info(f"Running analysis for {hostname}...")

    # Fast synchronous checks first
    is_https, https_details = check_https_ssl(valid_url)
    patterns = check_patterns(valid_url)
    is_blacklisted = check_blacklist(hostname)

    # 3. Run slower checks in parallel (HTML fetch, WHOIS, DNS, Content, Tracker, Privacy) using ThreadPoolExecutor
    def fetch_html():
        """Fetch HTML content with timeout handling."""
        try:
            import requests as req_lib
            resp = req_lib.get(valid_url, timeout=5, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }, verify=True, allow_redirects=True)
            return resp.text
        except Exception as fetch_err:
            logger.warning(f"Could not fetch HTML: {fetch_err}")
            return None

    # Create a pool with enough workers for all tasks (plus HTML fetching)
    with ThreadPoolExecutor(max_workers=5) as executor:
        whois_future = executor.submit(check_domain_age, hostname)
        dns_future = executor.submit(check_dns_records, hostname)
        html_future = executor.submit(fetch_html)

        # wait for HTML so we can use it for dependent tasks
        try:
            html_content = html_future.result(timeout=6)
        except Exception:
            html_content = None

        # submit analysis tasks that depend on HTML
        content_future = executor.submit(check_content_trust, valid_url, html_content=html_content)
        tracker_future = executor.submit(detect_trackers, html_content or "")
        privacy_future = executor.submit(analyze_privacy, valid_url, html_content=html_content)

        # while the above run in background, perform behavior analysis on main thread
        if fast_mode:
            behavior_result = {
                "redirect_count": 0,
                "redirect_chain": [],
                "external_request_count": 0,
                "external_requests": [],
                "suspicious_domains": [],
                "page_title": None,
                "final_url": None,
                "error": "Skipped in fast mode"
            }
            logger.info("Skipping behavior analysis in fast mode")
        else:
            behavior_result = analyze_behavior(valid_url, html_content=html_content)

        # retrieve remaining results
        age_days, creation_date = whois_future.result(timeout=10)
        dns_results = dns_future.result(timeout=10)
        content_analysis = content_future.result(timeout=10)
        tracker_result = tracker_future.result(timeout=10)
        privacy_result = privacy_future.result(timeout=10)


    # 4. Run analysis modules using fetched content (results from futures already collected above)
    network_result = analyze_network(behavior_result)

    # 4. Combine all results for scoring
    check_results = {
        "blacklist": is_blacklisted,
        "domain_age": age_days,
        "https_valid": is_https,
        "patterns": patterns,
        "content_analysis": content_analysis,
        "dns_analysis": dns_results,
        "behavior": behavior_result,
        "network": network_result,
        "trackers": tracker_result,
        "privacy": privacy_result,
        "html_content": html_content,  # For malicious script detection
    }

    score, label, reasons = calculate_risk_score(check_results)

    # Recommendation text
    if label in ("Suspicious", "Caution"):
        recommendation = "Proceed with caution"
    elif label == "Fraudulent":
        recommendation = "Avoid this site — it has been flagged as dangerous"
    else:
        recommendation = "Safe to visit"

    result = {
        "url": valid_url,
        "hostname": hostname,
        "riskScore": score,
        "label": label,
        "recommendation": recommendation,
        "reasons": reasons,
        # Backward-compatible checks object (existing frontend)
        "checks": {
            "https": is_https,
            "httpsDetails": https_details,
            "domainAgeDays": age_days,
            "suspiciousPatterns": any([
                patterns.get("ip_based"),
                patterns.get("suspicious_tld"),
                patterns.get("hyphens"),
                bool(patterns.get("keywords")),
            ]),
            "blacklisted": (
                is_blacklisted.get("listed", False)
                if isinstance(is_blacklisted, dict)
                else is_blacklisted
            ),
            "blacklistDetails": is_blacklisted,
            "creationDate": creation_date,
            "mxRecords": dns_results.get("mx_records", False),
            "spfRecord": dns_results.get("spf_record", False),
            "urgencyScore": content_analysis.get("urgency_score", 0),
            "trustPages": content_analysis.get("trust_pages", []),
            "contentReachable": content_analysis.get("reachable", False),
        },
        # Extended analysis data (new frontend panels)
        "analysis": {
            "behavior": behavior_result,
            "trackers": tracker_result,
            "network": network_result,
            "privacy": privacy_result,
        },
        "timestamp": datetime.datetime.now().isoformat(),
        "fastMode": fast_mode,
    }

    return jsonify(result), 200


@app.route("/api/blacklist/update", methods=["POST"])
def trigger_blacklist_update():
    """
    Manually triggers a blacklist update from URLhaus.
    """
    try:
        result = update_blacklist_source()

        if result.get("success"):
            force_reload_blacklist()
            return jsonify({
                "message": "Blacklist updated successfully",
                "stats": result
            }), 200
        else:
            return jsonify({
                "error": "Failed to update blacklist",
                "details": result.get("error")
            }), 500
    except Exception as e:
        logger.error(f"Blacklist update error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
