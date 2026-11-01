import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from feature_extractor_v4 import (
    FEATURE_NAMES_V4,
    extract_features_v4,
    get_host,
    registered_domain,
)


def test_feature_names_and_order():
    feats = extract_features_v4("https://example.com")
    assert list(feats.keys()) == FEATURE_NAMES_V4
    assert len(FEATURE_NAMES_V4) == 10


def test_www_prefix_is_removed():
    assert get_host("https://www.github.com") == "github.com"
    assert get_host("https://github.com") == "github.com"


def test_www_and_non_www_give_identical_features():
    assert extract_features_v4("https://github.com") == extract_features_v4(
        "https://www.github.com"
    )


def test_path_query_and_fragment_are_ignored():
    base = extract_features_v4("https://github.com")
    deep = extract_features_v4(
        "https://github.com/Akshat-coder9964/phishing-url-detector?tab=readme#top"
    )
    assert base == deep


def test_missing_scheme_is_handled():
    assert extract_features_v4("github.com") == extract_features_v4("https://github.com")


def test_host_is_case_insensitive():
    assert extract_features_v4("HTTPS://GitHub.COM") == extract_features_v4("https://github.com")


def test_ip_host():
    feats = extract_features_v4("http://192.168.10.55/banking/login.php")
    assert feats["IsIP"] == 1
    assert feats["SubdomainCount"] == 0
    assert feats["TLDLength"] == 0
    assert feats["HostLength"] == len("192.168.10.55")


def test_subdomain_counting():
    assert extract_features_v4("https://example.com")["SubdomainCount"] == 0
    assert extract_features_v4("https://a.example.com")["SubdomainCount"] == 1
    assert extract_features_v4("https://a.b.example.com")["SubdomainCount"] == 2


def test_two_part_suffix_is_not_counted_as_subdomain():
    assert extract_features_v4("https://www.bbc.co.uk")["SubdomainCount"] == 0
    assert extract_features_v4("https://news.bbc.co.uk")["SubdomainCount"] == 1


def test_registered_domain():
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("news.bbc.co.uk") == "bbc.co.uk"
    assert registered_domain("192.168.10.55") == "192.168.10.55"


def test_hyphens_and_digits_are_counted_in_host_only():
    feats = extract_features_v4("https://a-b-1.example.com/path-with-9-digits-123")
    assert feats["HyphenCount"] == 2
    assert feats["DigitCount"] == 1


def test_suspicious_words_counted_in_host_not_path():
    in_host = extract_features_v4("https://login-verify.example.com")
    in_path = extract_features_v4("https://example.com/login/verify")
    assert in_host["SuspiciousWordCount"] == 2
    assert in_path["SuspiciousWordCount"] == 0


def test_label_and_tld_lengths():
    feats = extract_features_v4("https://example.co.uk")
    assert feats["TLDLength"] == 2
    assert feats["MaxLabelLength"] == len("example")


@pytest.mark.parametrize("bad", ["", "   ", "http://", "http://[bad"])
def test_garbage_input_does_not_crash(bad):
    feats = extract_features_v4(bad)
    assert feats["HostLength"] == 0
    assert list(feats.keys()) == FEATURE_NAMES_V4


def test_ratios_are_between_zero_and_one():
    feats = extract_features_v4("https://abc123-def.example.com")
    assert 0 <= feats["DigitRatio"] <= 1
    assert 0 <= feats["LetterRatio"] <= 1
