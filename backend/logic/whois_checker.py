import whois
from datetime import datetime
import logging
import threading

logger = logging.getLogger(__name__)

# Cache for WHOIS results to avoid repeated lookups
_whois_cache = {}
_cache_lock = threading.Lock()


def check_domain_age(domain):
    """
    Checks the domain age in days with timeout and caching.
    Returns (age_days, creation_date).
    """
    # Check cache first (case-insensitive)
    domain = domain.lower()
    with _cache_lock:
        if domain in _whois_cache:
            return _whois_cache[domain]

    result = (-1, None)

    def _whois_lookup():
        nonlocal result
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if not creation_date:
                result = (-1, None)
                return

            # Ensure creation_date is naive or make now() aware
            if creation_date.tzinfo:
                creation_date = creation_date.replace(tzinfo=None)

            age_days = (datetime.now() - creation_date).days
            result = (age_days, creation_date.isoformat())
        except Exception as e:
            logger.error(f"WHOIS check failed for {domain}: {e}")
            result = (-1, None)

    # Run WHOIS lookup in a thread with timeout
    lookup_thread = threading.Thread(target=_whois_lookup)
    lookup_thread.daemon = True
    lookup_thread.start()
    lookup_thread.join(timeout=5)  # 5 second timeout

    # Cache the result
    with _cache_lock:
        _whois_cache[domain] = result

    return result
