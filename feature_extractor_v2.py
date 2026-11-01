
from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update", "secure",
    "signin", "banking", "password", "confirm", "wallet",
    "authenticate", "recover", "suspend"
]


def extract_features_v2(url):
    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # Basic URL structure
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # Domain information
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    subdomain_count = max(len(hostname.split(".")) - 2, 0)

    # Character information
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)

    letter_ratio = letters / url_length if url_length else 0
    digit_ratio = digits / url_length if url_length else 0

    # URL structure and symbols
    special_chars = sum(not c.isalnum() for c in url)

    at_count = url.count("@")
    hyphen_count = hostname.count("-")
    dot_count = hostname.count(".")
    slash_count = url.count("/")

    # Security-related URL indicators
    has_https = int(parsed.scheme == "https")
    suspicious_word_count = sum(
        word in url.lower() for word in SUSPICIOUS_WORDS
    )

    return {
        "URLLength": url_length,
        "HostnameLength": hostname_length,
        "PathLength": path_length,
        "QueryLength": query_length,
        "IsIP": is_ip,
        "SubdomainCount": subdomain_count,
        "HasHTTPS": has_https,
        "LetterCount": letters,
        "LetterRatio": letter_ratio,
        "DigitCount": digits,
        "DigitRatio": digit_ratio,
        "SpecialCharCount": special_chars,
        "AtSymbolCount": at_count,
        "HyphenCount": hyphen_count,
        "DotCount": dot_count,
        "SuspiciousWordCount": suspicious_word_count
    }
