from urllib.parse import urlparse
import requests
import logging

logger = logging.getLogger(__name__)


def validate_url(url):
    """
    Validates the URL and adds https if missing.
    Returns (valid_url, error_message).
    """
    if not url:
        return None, "URL is empty"

    # Strip whitespace and lowercase
    url = url.strip().lower()
    
    # Strip trailing slash(es)
    url = url.rstrip('/')

    # Max length guard
    if len(url) > 2048:
        return None, "URL is too long (max 2048 characters)"

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc]):
            # hostname should not contain spaces
            if " " in result.netloc:
                return None, "Invalid URL format: Hostname contains spaces"
            # Must have a valid-looking hostname (at least one dot, no path-only)
            if "." not in result.netloc and result.netloc != "localhost":
                return None, "Invalid URL: Not a valid hostname"
            return url, None
        return None, "Invalid URL format"
    except Exception:
        return None, "Invalid URL format"


def check_https_ssl(url):
    """
    Checks if the URL uses HTTPS and if the SSL certificate is valid.
    Returns (is_https, details).

    NOTE: If the site is simply unreachable (timeout, connection refused) but
    the URL starts with https://, we still consider HTTPS as 'present' to avoid
    punishing valid HTTPS sites that are temporarily down.
    """
    if not url.startswith("https://"):
        return False, "Not using HTTPS"

    try:
        # Use a realistic browser User-Agent to avoid bot-blocking false negatives
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        requests.get(url, timeout=7, headers=headers, verify=True, allow_redirects=True)
        return True, "Valid HTTPS and SSL certificate"

    except requests.exceptions.SSLError as e:
        # Genuine SSL problem — invalid/expired/self-signed cert
        logger.warning(f"SSL error for {url}: {e}")
        return False, f"SSL Certificate Error: {str(e)[:120]}"

    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects) as e:
        # Site unreachable, but URL *does* use HTTPS — don't penalise HTTPS score.
        # The site being down is a separate concern.
        logger.info(f"HTTPS site unreachable (not an SSL error) for {url}: {type(e).__name__}")
        return True, "HTTPS present but site is currently unreachable"

    except Exception as e:
        logger.warning(f"Unexpected error in HTTPS check for {url}: {e}")
        return True, "HTTPS present; could not fully verify connectivity"
