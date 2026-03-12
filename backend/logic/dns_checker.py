import dns.resolver
import logging
import tldextract
import threading

logger = logging.getLogger(__name__)

# Cache for DNS results
_dns_cache = {}
_dns_lock = threading.Lock()


def _resolve_records(domain, rtype):
    """
    Resolves DNS records with fallback to public DNS if system resolver fails.
    """
    # 1. Try system resolver
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        return resolver.resolve(domain, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as e:
        logger.debug(f"System resolver failed for {domain} {rtype}: {e}")
        
    # 2. Try fallback to public DNS (Google/Cloudflare)
    try:
        fallback_resolver = dns.resolver.Resolver(configure=False)
        fallback_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        fallback_resolver.timeout = 3
        fallback_resolver.lifetime = 4
        logger.debug(f"Attempting fallback DNS for {domain} {rtype}")
        return fallback_resolver.resolve(domain, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as e:
        logger.warning(f"Fallback DNS resolution failed for {domain} {rtype}: {e}")
        return []


def check_dns_records(domain):
    """
    Checks for MX and SPF records with timeout, caching, and robust fallbacks.
    Returns a dict with results.
    """
    # Check cache first (case-insensitive)
    domain = domain.lower()
    with _dns_lock:
        if domain in _dns_cache:
            return _dns_cache[domain]

    results = {
        "mx_records": False,
        "spf_record": False,
        "details": []
    }

    # Extract registered domain (e.g., "youtube.com" from "www.youtube.com")
    extracted = tldextract.extract(domain)
    registered_domain = f"{extracted.domain}.{extracted.suffix}"

    # Fallback to original domain if extraction fails
    target_domain = (
        registered_domain
        if registered_domain and "." in registered_domain
        else domain
    )

    # 1. MX Record Check
    mx_records = _resolve_records(target_domain, "MX")
    if mx_records:
        results["mx_records"] = True
        results["details"].append(f"Found {len(mx_records)} MX record(s)")
        logger.debug(f"MX records found for {target_domain}")
    else:
        results["details"].append("No MX records found")

    # 2. SPF Record Check (TXT)
    txt_records = _resolve_records(target_domain, "TXT")
    for record in txt_records:
        record_text = record.to_text()
        if "v=spf1" in record_text:
            results["spf_record"] = True
            results["details"].append("SPF record found")
            logger.debug(f"SPF record found for {target_domain}")
            break
    
    if not results["spf_record"]:
        results["details"].append("No SPF record found")

    # Cache the result
    with _dns_lock:
        _dns_cache[domain] = results

    return results
