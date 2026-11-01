"""Input validation and safe normalization for URL analysis."""
from urllib.parse import urlsplit
import ipaddress


def normalize_url(raw_url: str) -> str:
    """Normalize a user-entered URL without making a network request."""
    if not isinstance(raw_url, str):
        raise ValueError("Enter a URL as text.")
    value = raw_url.strip()
    if not value:
        raise ValueError("Enter a URL first.")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("The URL contains invalid control characters.")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    if len(value) > 4096:
        raise ValueError("The URL is too long (maximum 4,096 characters).")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing .port catches malformed port values.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL format is invalid.") from exc
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValueError("Enter a valid web address, such as example.com.")
    if " " in value:
        raise ValueError("URLs cannot contain unescaped spaces.")
    # Reject malformed hostnames, but allow IP literals including localhost.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if hostname.lower() != "localhost":
            if "." not in hostname or hostname.startswith(".") or hostname.endswith("."):
                raise ValueError("Enter a valid domain name or IP address.")
    return value
