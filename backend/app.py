from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import datetime
from urllib.parse import urlparse

# Logic Modules
from logic.validator import validate_url, check_https_ssl
from logic.whois_checker import check_domain_age
from logic.pattern_checker import check_patterns
from logic.content_checker import check_content_trust
from logic.blacklist_checker import check_blacklist, force_reload_blacklist
from logic.scorer import calculate_risk_score
from logic.dns_checker import check_dns_records
from logic.updater import update_blacklist_source


# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "running",
        "service": "ProblySUS Request Scanner",
        "version": "1.0.0"
    }), 200


@app.route("/analyze", methods=["POST"])
def analyze_url():
    """
    Analyze a given URL for scam risk.
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]

    # 1. Validation
    valid_url, error = validate_url(url)
    if not valid_url:
        return jsonify({"error": error}), 400

    # Extract hostname for blacklist/whois
    parsed = urlparse(valid_url)
    hostname = parsed.hostname  # Handles ports (e.g., example.com:8080 -> example.com)

    # 2. Parallel Checks
    # HTTPS Check
    is_https, https_details = check_https_ssl(valid_url)

    # WHOIS Check
    age_days, creation_date = check_domain_age(hostname)

    # DNS Check (New)
    dns_results = check_dns_records(hostname)

    # Pattern Check
    patterns = check_patterns(valid_url)

    # Content Check (Enhanced)
    content_analysis = check_content_trust(valid_url)

    # Blacklist Check
    is_blacklisted = check_blacklist(hostname)

    # 3. Validation & Scoring
    check_results = {
        "blacklist": is_blacklisted,
        "domain_age": age_days,
        "https_valid": is_https,
        "patterns": patterns,
        "content_analysis": content_analysis,
        "dns_analysis": dns_results,
    }

    score, label, reasons = calculate_risk_score(check_results)

    result = {
        "url": valid_url,
        "hostname": hostname,
        "riskScore": score,
        "label": label,
        "recommendation": (
            "Proceed with caution"
            if label == "Suspicious" or label == "Caution"
            else ("Avoid this site" if label == "Fraudulent" else "Safe to visit")
        ),
        "reasons": reasons,
        "checks": {
            "https": is_https,
            "domainAgeDays": age_days,
            "suspiciousPatterns": any(patterns.values()),
            "blacklisted": (
                is_blacklisted.get("listed", False)
                if isinstance(is_blacklisted, dict)
                else is_blacklisted
            ),
            "blacklistDetails": is_blacklisted,
            "creationDate": creation_date,
            "mxRecords": dns_results.get("mx_records", False),
            "urgencyScore": content_analysis.get("urgency_score", 0),
            "trustPages": content_analysis.get("trust_pages", []),
        },
        "timestamp": datetime.datetime.now().isoformat(),
    }

    return jsonify(result), 200






@app.route("/api/blacklist/update", methods=["POST"])
def trigger_blacklist_update():
    """
    Manually triggers a blacklist update from URLhaus.
    """
    try:
        # Run update synchronously for now (or could use a thread if it takes too long)
        # For a manual trigger, the user might want to wait for confirmation.
        result = update_blacklist_source()
        
        if result.get("success"):
            # Force reload the blacklist in the running app
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
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
