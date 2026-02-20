import dns.resolver
import logging
import tldextract

logger = logging.getLogger(__name__)


def check_dns_records(domain):
    """
    Checks for MX and SPF records to validate email infrastructure.
    Returns a dict with results.
    """
    results = {
        "mx_records": False,
        "spf_record": False,
        "details": []
    }

    # Extract registered domain (e.g., "youtube.com" from "www.youtube.com")
    # Both MX and SPF records live on the registered root domain, not subdomains.
    extracted = tldextract.extract(domain)
    registered_domain = f"{extracted.domain}.{extracted.suffix}"

    # Fallback to original domain if extraction fails (e.g. localhost, IP)
    target_domain = (
        registered_domain
        if registered_domain and "." in registered_domain
        else domain
    )

    try:
        # 1. MX Record Check
        # Real businesses need to receive email. Scams often don't set this up.
        mx_records = dns.resolver.resolve(target_domain, "MX")
        if mx_records:
            results["mx_records"] = True
            results["details"].append(f"Found {len(mx_records)} MX record(s) for {target_domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        results["details"].append(f"No MX records found for {target_domain}")
    except Exception as e:
        logger.error(f"MX check failed for {domain}: {e}")

    try:
        # 2. SPF Record Check (TXT) — always on the registered root domain
        txt_records = dns.resolver.resolve(target_domain, "TXT")
        for record in txt_records:
            if "v=spf1" in record.to_text():
                results["spf_record"] = True
                results["details"].append("Valid SPF record found")
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        pass
    except Exception as e:
        logger.error(f"SPF check failed for {domain}: {e}")

    return results
