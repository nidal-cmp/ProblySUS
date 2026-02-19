import requests
import csv
import json
import os
import io
import logging
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

# Configuration
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
BLACKLIST_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "blacklist_sources.json")

def update_blacklist_source():
    """
    Fetches the latest blacklist from URLhaus and updates the local JSON file.
    Returns a dict with statistics.
    """
    logger.info(f"Starting blacklist update from {URLHAUS_CSV_URL}...")
    
    try:
        response = requests.get(URLHAUS_CSV_URL, timeout=30)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to fetch blacklist data: {e}")
        return {"success": False, "error": str(e)}

    logger.info("Parsing CSV data...")
    try:
        f = io.StringIO(response.text)
        reader = csv.reader(f)
        
        new_domains = {}
        processed_count = 0
        
        for row in reader:
            # Skip comments and invalid rows
            if not row or row[0].startswith("#") or len(row) < 6:
                continue
                
            # CSV Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            url = row[2]
            status = row[3]
            threat = row[5]

            # We verify 'online' status to keep the list high-confidence? 
            # Or just take everything? URLhaus 'recent' is usually active threats.
            # Let's take 'online' to be safe and precise, or maybe include 'offline' 
            # if we want a history. Using 'online' for active blocking is safer to avoid false positives 
            # on cleaned sites, but 'recent' CSV usually implies relevance.
            # Let's filter for 'online' to match previous logic.
            if status == "online":
                try:
                    parsed = urlparse(url)
                    if parsed.hostname:
                        # Normalize hostname (lowercase, strip ports)
                        hostname = parsed.hostname.lower()
                        
                        new_domains[hostname] = {
                            "category": "Malware",
                            "source": "URLHaus",
                            "risk_level": "Critical",
                            "details": f"Threat: {threat}",
                            "updated_at": datetime.now().isoformat()
                        }
                        processed_count += 1
                except Exception:
                    pass
        
        logger.info(f"Parsed {len(new_domains)} active domains.")

        # Load existing data to merge
        existing_data = {"meta": {}, "domains": {}}
        if os.path.exists(BLACKLIST_FILE):
             try:
                with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
             except Exception:
                 pass
        
        # Merge: Overwrite/Add new domains
        # We might want to keep old domains that are not in the new list if we want a historical blacklist,
        # but for "current threats", replacing or merging is fine.
        # Let's merge: keep old ones, add/update new ones.
        existing_data["domains"].update(new_domains)
        existing_data["meta"]["last_updated"] = datetime.now().isoformat()
        existing_data["meta"]["source_url"] = URLHAUS_CSV_URL
        
        # Save
        os.makedirs(os.path.dirname(BLACKLIST_FILE), exist_ok=True)
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=4)
            
        logger.info("Blacklist updated successfully.")
        return {
            "success": True, 
            "added_count": len(new_domains), 
            "total_count": len(existing_data["domains"]),
            "timestamp": existing_data["meta"]["last_updated"]
        }

    except Exception as e:
        logger.error(f"Error processing blacklist update: {e}")
        return {"success": False, "error": str(e)}
