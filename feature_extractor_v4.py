"""V4 feature extractor: HOST-ONLY.

Why: in the PhiUSIIL dataset every legitimate URL is a bare homepage
(no path, no query), so path/query/length features only teach the model
"homepage = legitimate". V4 therefore looks only at the hostname, which is
the part of the URL the dataset can genuinely teach.

  * A leading "www." is removed (normalization for every URL, not an allowlist).
  * Path, query and fragment are ignored completely.
"""
from urllib.parse import urlsplit
import ipaddress


SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update", "secure",
    "signin", "banking", "password", "confirm", "wallet",
    "authenticate", "recover", "suspend"
]

# Common two-part public suffixes, so that "bbc.co.uk" counts as a domain
# with 0 subdomains. Simplified list: a full solution would use the Public
# Suffix List (e.g. the tldextract package).
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "co.id", "my.id",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "co.kr", "or.kr", "go.kr",
    "co.nz", "org.nz", "co.za", "org.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "com.tr", "org.tr", "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
    "com.pk", "com.bd", "com.vn", "com.ua", "com.ng", "com.eg", "com.sa",
}

FEATURE_NAMES_V4 = [
    "HostLength", "SubdomainCount", "HyphenCount", "DigitCount",
    "DigitRatio", "LetterRatio", "IsIP", "SuspiciousWordCount",
    "MaxLabelLength", "TLDLength",
]


def get_host(url):
    """Lower-case hostname without a leading 'www.' (empty string if none)."""
    url = str(url).strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registered_domain(host):
    """Approximate registered domain, e.g. 'a.b.bbc.co.uk' -> 'bbc.co.uk'."""
    if not host or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def extract_features_v4(url):
    host = get_host(url)
    is_ip = _is_ip(host)
    labels = host.split(".") if host else []

    if is_ip or not labels:
        subdomains = 0
        tld_len = 0
    else:
        reg_labels = len(registered_domain(host).split("."))
        subdomains = max(len(labels) - reg_labels, 0)
        tld_len = len(labels[-1])

    host_len = len(host)
    digits = sum(c.isdigit() for c in host)
    letters = sum(c.isalpha() for c in host)

    return {
        "HostLength": host_len,
        "SubdomainCount": subdomains,
        "HyphenCount": host.count("-"),
        "DigitCount": digits,
        "DigitRatio": digits / host_len if host_len else 0,
        "LetterRatio": letters / host_len if host_len else 0,
        "IsIP": int(is_ip),
        "SuspiciousWordCount": sum(w in host for w in SUSPICIOUS_WORDS),
        "MaxLabelLength": max((len(l) for l in labels), default=0),
        "TLDLength": tld_len,
    }
