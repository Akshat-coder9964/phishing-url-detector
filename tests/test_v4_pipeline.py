import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
import pandas as pd
import pytest

from feature_extractor_v4 import FEATURE_NAMES_V4, extract_features_v4
from url_utils import normalize_url

MODEL_PATH = ROOT / "phishing_detector_v4.pkl"

pytestmark = pytest.mark.skipif(
    not MODEL_PATH.exists(), reason="phishing_detector_v4.pkl not found"
)


@pytest.fixture(scope="module")
def bundle():
    return joblib.load(MODEL_PATH)


def phishing_probability(bundle, url):
    """Same steps as app.py: normalize -> features -> DataFrame -> predict."""
    url = normalize_url(url)
    features = extract_features_v4(url)
    order = bundle["feature_names"]
    row = pd.DataFrame([[features[name] for name in order]], columns=order)
    model = bundle["model"]
    probs = model.predict_proba(row)[0]
    return dict(zip(model.classes_, probs))[0]


def test_bundle_structure(bundle):
    assert {"model", "feature_names", "classes"} <= set(bundle.keys())


def test_feature_names_match_extractor(bundle):
    assert bundle["feature_names"] == FEATURE_NAMES_V4


def test_label_mapping_is_unchanged(bundle):
    # 0 = phishing, 1 = legitimate (verified from dataset samples)
    assert list(bundle["model"].classes_) == [0, 1]


def test_probability_is_valid(bundle):
    p = phishing_probability(bundle, "https://example.com")
    assert 0.0 <= p <= 1.0


def test_www_path_and_query_do_not_change_the_score(bundle):
    a = phishing_probability(bundle, "https://github.com")
    b = phishing_probability(bundle, "https://www.github.com/some/deep/path?x=1")
    assert a == pytest.approx(b)


def test_obvious_synthetic_phishing_host_is_flagged(bundle):
    # Made-up URL with typical phishing structure (not a real site).
    url = "http://paypal-secure-login.verify-account-update.example-xyz.com/signin"
    assert phishing_probability(bundle, url) > 0.5


def test_ip_address_input_works(bundle):
    p = phishing_probability(bundle, "http://192.168.10.55/banking/confirm.php")
    assert 0.0 <= p <= 1.0
