import json
import os
import tldextract


# Cache the blacklist in memory
BLACKLIST_DB = {}
LAST_LOADED = 0


def load_blacklist():
    """
    Loads the blacklist from the JSON file if it has changed.
    """
    global BLACKLIST_DB, LAST_LOADED
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(current_dir, "..", "data", "blacklist_sources.json")

        if not os.path.exists(data_path):
            return

        # Check modification time
        mtime = os.path.getmtime(data_path)
        if mtime > LAST_LOADED:
            # print(f"Reloading blacklist data (changed at {mtime})")
            with open(data_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Merge both sources: auto-indexed entries take priority over custom.
                # This ensures custom_domains are actually queried at runtime.
                BLACKLIST_DB = {
                    **data.get("custom_domains", {}),
                    **data.get("domains", {}),
                }
                LAST_LOADED = mtime
    except Exception as e:
        print(f"Error loading blacklist: {e}")


# Initial load
load_blacklist()

def force_reload_blacklist():
    """
    Forces a reload of the blacklist data.
    """
    global LAST_LOADED
    LAST_LOADED = 0
    load_blacklist()


def check_blacklist(hostname):
    """
    Checks if the hostname is in the blacklist.
    Returns a dict with status and details.
    """
    # Ensure data is up to date
    load_blacklist()

    # 0. Whitelist Check (Hardcoded safety net)
    WHITELIST = {
        "github.com",
        "google.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "cloudflare.com",
        "gitlab.com",
    }

    if hostname in WHITELIST or (
        hostname.startswith("www.") and hostname[4:] in WHITELIST
    ):
        return {
            "listed": False,
            "category": "Whitelisted",
            "source": "Internal",
            "risk_level": "Safe",
        }

    # Generate variations to check
    # 1. Exact match
    # 2. Root domain (e.g. sub.example.com -> example.com)
    # 3. WWW variation (example.com -> www.example.com)
    # 4. Non-WWW variation (www.example.com -> example.com)
    
    variations = {hostname}
    
    # Handle www
    if hostname.startswith("www."):
        variations.add(hostname[4:])
    else:
        variations.add(f"www.{hostname}")
    
    # Use tldextract to correctly identify the registered root domain.
    # Then walk UP the subdomain chain from the full hostname to the registered root,
    # checking every level. This ensures that if URLhaus indexed any ancestor of
    # the queried hostname (e.g. darkmoon.in.net when user checks
    # hiddenside.darkmoon.in.net), it will still be caught.
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        registered = f"{ext.domain}.{ext.suffix}"
        # Build the chain: full hostname → parent → … → registered root
        # e.g. hiddenside.darkmoon.in.net → darkmoon.in.net → (stop, registered=darkmoon.in.net)
        parts = hostname.split(".")
        registered_parts = registered.split(".")
        # Walk from full hostname down to registered root (inclusive)
        while len(parts) >= len(registered_parts):
            candidate = ".".join(parts)
            variations.add(candidate)
            variations.add(f"www.{candidate}")
            parts = parts[1:]  # Strip leftmost subdomain label


    for variant in variations:
        if variant in BLACKLIST_DB:
            entry = BLACKLIST_DB[variant]
            return {
                "listed": True,
                "category": entry.get("category", "Uncategorized"),
                "source": entry.get("source", "Unknown"),
                "risk_level": entry.get("risk_level", "High"),
                "matched_on": variant
            }

    return {"listed": False, "category": None, "source": None, "risk_level": None}
