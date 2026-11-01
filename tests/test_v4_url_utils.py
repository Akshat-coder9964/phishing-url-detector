import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from url_utils import normalize_url


def test_adds_https_when_scheme_missing():
    assert normalize_url("example.com") == "https://example.com"


def test_keeps_existing_scheme():
    assert normalize_url("http://example.com/a") == "http://example.com/a"


def test_strips_surrounding_whitespace():
    assert normalize_url("  https://example.com  ") == "https://example.com"


@pytest.mark.parametrize("bad", ["", "   ", "hello", "https://nodot", "https://.example.com"])
def test_rejects_invalid_input(bad):
    with pytest.raises(ValueError):
        normalize_url(bad)


def test_rejects_non_string():
    with pytest.raises(ValueError):
        normalize_url(None)
    with pytest.raises(ValueError):
        normalize_url(123)


def test_rejects_unescaped_spaces():
    with pytest.raises(ValueError):
        normalize_url("https://example.com/signin (about 100%)")


def test_rejects_control_characters():
    with pytest.raises(ValueError):
        normalize_url("https://example.com/\x00")


def test_rejects_too_long_url():
    with pytest.raises(ValueError):
        normalize_url("https://" + "a" * 5000 + ".com")


def test_accepts_ip_and_localhost():
    assert normalize_url("http://192.168.1.1/x") == "http://192.168.1.1/x"
    assert normalize_url("http://localhost:8501") == "http://localhost:8501"


def test_uppercase_scheme_is_accepted():
    assert normalize_url("HTTPS://Example.com") == "HTTPS://Example.com"
