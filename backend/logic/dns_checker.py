import dns.resolver
import logging

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

    try:
        # 1. MX Record Check
        # Real businesses need to receive email. Scams often don't set this up.
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            results["mx_records"] = True
            results["details"].append(f"Found {len(mx_records)} MX records")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        results["details"].append("No MX records found (Suspicious: Cannot receive email)")
    except Exception as e:
        logger.error(f"MX check failed for {domain}: {e}")

    try:
        # 2. SPF Record Check (TXT)
        # Checks if the domain has authorized senders to prevent spoofing.
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if "v=spf1" in record.to_text():
                results["spf_record"] = True
                results["details"].append("Valid SPF record found")
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        logger.error(f"SPF check failed for {domain}: {e}")

    return results
