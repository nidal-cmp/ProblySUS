from urllib.parse import urlparse
import requests


def validate_url(url):
    """
    Validates the URL and adds https if missing.
    Returns (valid_url, error_message).
    """
    if not url:
        return None, "URL is empty"

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc]):
             # hostname should not contain spaces
            if " " in result.netloc:
                 return None, "Invalid URL format: Hostname contains spaces"
            
            return url, None
        return None, "Invalid URL format"
    except Exception:
        return None, "Invalid URL format"


def check_https_ssl(url):
    """
    Checks if the URL uses HTTPS and if the SSL certificate is valid.
    Returns (is_https, details).
    """
    try:
        if not url.startswith("https://"):
            return False, "Not using HTTPS"

        # Simple request to check SSL (verify=True checks cert)
        requests.get(url, timeout=5)
        return True, "Valid HTTPS and SSL"
    except requests.exceptions.SSLError:
        return False, "SSL Error"
    except Exception as e:
        # Check if it was a connection error but URL started with https
        return False, f"Connection Failed: {str(e)}"
