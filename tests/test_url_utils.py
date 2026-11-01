import pytest
from url_utils import normalize_url

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com"),
    ("https://example.com/a?x=1", "https://example.com/a?x=1"),
    ("http://192.168.1.3:8501", "http://192.168.1.3:8501"),
    ("localhost:8501", "https://localhost:8501"),
])
def test_normalize_valid_urls(raw, expected):
    assert normalize_url(raw) == expected

@pytest.mark.parametrize("raw", ["", "   ", "https://", "not a url", "https://example.com:bad", "https://.bad.com"])
def test_reject_invalid_urls(raw):
    with pytest.raises(ValueError):
        normalize_url(raw)
