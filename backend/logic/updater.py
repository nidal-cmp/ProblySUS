import requests
import csv
import json
import os
import io
import zipfile
import logging
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

# Configuration
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv/"
BLACKLIST_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "blacklist_sources.json"
)


def update_blacklist_source():
    """
    Fetches the latest blacklist from URLhaus and updates the local JSON file.

    Strategy: REPLACE (not merge) the domain list on every update.
    This ensures stale entries for sites that have cleaned up are removed.
    Custom/manually-added entries are stored under the separate "custom_domains"
    key and are never overwritten by automatic updates.

    Returns a dict with statistics.
    """
    logger.info(f"Starting blacklist update from {URLHAUS_CSV_URL}...")

    try:
        response = requests.get(URLHAUS_CSV_URL, timeout=60)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to fetch blacklist data: {e}")
        return {"success": False, "error": str(e)}

    logger.info("Parsing CSV data...")
    try:
        # The full-archive feed (/csv/) is served as a ZIP file.
        # The recent feed (/csv_recent/) is plain text.
        # Detect by checking the Content-Type or magic bytes.
        content_type = response.headers.get("Content-Type", "")
        is_zip = (
            "zip" in content_type
            or response.content[:2] == b"PK"  # ZIP magic bytes
        )

        if is_zip:
            logger.info("Response is a ZIP archive — extracting CSV...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                # URLhaus ZIP contains a single CSV file
                csv_filename = zf.namelist()[0]
                csv_text = zf.read(csv_filename).decode("utf-8", errors="replace")
        else:
            csv_text = response.text

        f = io.StringIO(csv_text, newline="")
        reader = csv.reader(f)

        new_domains = {}
        skipped_count = 0

        for row in reader:
            # Skip comments and malformed rows
            if not row or row[0].startswith("#") or len(row) < 6:
                continue

            # CSV Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            url = row[2]
            status = row[3]
            threat = row[5]

            # Index BOTH 'online' and 'offline' confirmed-malicious entries.
            # 'online'  = actively serving malware/phishing → Critical
            # 'offline' = taken down but domain was confirmed malicious → High
            # Being temporarily unavailable does NOT make a domain safe.
            if status in ("online", "offline"):
                try:
                    parsed = urlparse(url)
                    if parsed.hostname:
                        hostname = parsed.hostname.lower()

                        if status == "online":
                            risk_level = "Critical"
                            category = f"Active Malware ({threat})"
                        else:
                            risk_level = "High"
                            category = f"Previously Confirmed Malicious ({threat})"

                        # 'online' always wins over 'offline' for the same domain
                        if hostname not in new_domains or status == "online":
                            new_domains[hostname] = {
                                "category": category,
                                "source": "URLHaus",
                                "risk_level": risk_level,
                                "url_status": status,
                                "details": f"Threat: {threat}",
                                "updated_at": datetime.now().isoformat(),
                            }
                except Exception as parse_err:
                    logger.debug(f"Could not parse URL from row: {parse_err}")
                    skipped_count += 1

        logger.info(f"Parsed {len(new_domains)} active domains ({skipped_count} skipped).")

        # Load existing file to preserve custom_domains
        existing_data = {"meta": {}, "domains": {}, "custom_domains": {}}
        if os.path.exists(BLACKLIST_FILE):
            try:
                with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    # Preserve manually-added custom entries
                    existing_data["custom_domains"] = loaded.get("custom_domains", {})
            except Exception as read_err:
                logger.warning(f"Could not read existing blacklist (will overwrite): {read_err}")

        # REPLACE strategy: fresh URLhaus data replaces all auto-indexed domains.
        # Custom domains are never touched.
        existing_data["domains"] = new_domains
        existing_data["meta"]["last_updated"] = datetime.now().isoformat()
        existing_data["meta"]["source_url"] = URLHAUS_CSV_URL
        existing_data["meta"]["domain_count"] = len(new_domains)

        # Save
        os.makedirs(os.path.dirname(BLACKLIST_FILE), exist_ok=True)
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2)

        logger.info("Blacklist updated successfully.")
        return {
            "success": True,
            "added_count": len(new_domains),
            "custom_count": len(existing_data["custom_domains"]),
            "total_count": len(new_domains) + len(existing_data["custom_domains"]),
            "timestamp": existing_data["meta"]["last_updated"],
        }

    except Exception as e:
        logger.error(f"Error processing blacklist update: {e}")
        return {"success": False, "error": str(e)}
