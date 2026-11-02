from pathlib import Path
import joblib
import pandas as pd
import streamlit as st

from feature_extractor_v2 import extract_features_v2
from feature_extractor_v4 import extract_features_v4, get_host
from url_utils import normalize_url


BASE_DIR = Path(__file__).resolve().parent

# Models are tried in this order. V4 is the primary model; V2 is only a
# legacy fallback if the V4 file is missing or cannot be loaded.
MODEL_CANDIDATES = [
    {
        "version": "V4",
        "path": BASE_DIR / "phishing_detector_v4.pkl",
        "extractor": extract_features_v4,
        "host_only": True,
    },
    {
        "version": "V2",
        "path": BASE_DIR / "phishing_detector_v2.pkl",
        "extractor": extract_features_v2,
        "host_only": False,
    },
]

st.set_page_config(
    page_title="AI Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)

st.markdown("""
<style>
.block-container {
    max-width: 900px;
    padding-top: 2.2rem;
}
.hero {
    padding: 1.4rem;
    border: 1px solid #334155;
    border-radius: 16px;
    background: linear-gradient(120deg, #111827, #1e293b);
}
.muted {
    color: #94a3b8;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class='hero'>
    <h1>🛡️ AI Phishing URL Detector</h1>
    <p class='muted'>Machine-learning-assisted URL risk screening</p>
</div>
""", unsafe_allow_html=True)

st.write(
    "Enter a URL to analyze its structural characteristics. "
    "The app does not visit the website or guarantee that a site is safe."
)


# Load the first model that works, together with its feature configuration
@st.cache_resource
def load_model():
    errors = []

    for candidate in MODEL_CANDIDATES:
        path = candidate["path"]

        if not path.exists():
            errors.append(f"{path.name}: file not found")
            continue

        try:
            bundle = joblib.load(path)
            return {
                "version": candidate["version"],
                "model": bundle["model"],
                "feature_order": bundle["feature_names"],
                "extractor": candidate["extractor"],
                "host_only": candidate["host_only"],
            }
        except Exception as exc:
            errors.append(f"{path.name}: {exc}")

    raise RuntimeError("; ".join(errors))


try:
    loaded = load_model()
except Exception as exc:
    st.error(f"Could not load a model: {exc}")
    st.stop()

model = loaded["model"]
feature_order = loaded["feature_order"]
extract_features = loaded["extractor"]
model_version = loaded["version"]
host_only = loaded["host_only"]

if model_version != "V4":
    st.warning(
        "The V4 model could not be loaded, so the older V2 model is being "
        "used. V2 is known to be biased by dataset artifacts and may "
        "wrongly flag legitimate URLs."
    )


# URL analysis form
with st.form("url_check"):
    raw_url = st.text_input(
        "Website URL",
        placeholder="https://example.com/login"
    )

    submitted = st.form_submit_button(
        "Analyze URL",
        type="primary",
        use_container_width=True
    )


if submitted:
    try:
        url = normalize_url(raw_url)

        features = extract_features(url)

        input_data = pd.DataFrame(
            [[features[name] for name in feature_order]],
            columns=feature_order
        )

        prediction = int(model.predict(input_data)[0])
        probabilities = model.predict_proba(input_data)[0]

        class_probabilities = {
            int(label): float(probability)
            for label, probability in zip(
                model.classes_, probabilities
            )
        }

        phishing_probability = (
            class_probabilities.get(0, 0.0) * 100
        )

        predicted_probability = (
            class_probabilities[prediction] * 100
        )

        st.divider()
        st.subheader("Analysis result")
        st.code(url, language=None)

        if host_only:
            st.caption(
                f"Host analyzed: {get_host(url)} — the V4 model scores the "
                "domain name only. The path, query string and a leading "
                "'www.' are ignored."
            )

        if prediction == 0:
            st.error("⚠️ Model classification: Potential phishing URL")
        else:
            st.success("✅ Model classification: Likely legitimate URL")

        st.metric(
            "Phishing probability",
            f"{phishing_probability:.2f}%"
        )

        st.caption(
            f"Model confidence in its predicted class: "
            f"{predicted_probability:.2f}%"
        )

        if 35 <= phishing_probability <= 65:
            st.info(
                "This score is close to the decision boundary, so the "
                "model is uncertain about this URL. Do not rely on it alone."
            )

        if host_only and features.get("SubdomainCount", 0) >= 1:
            st.warning(
                "This address uses a subdomain. The training data contained "
                "very few legitimate examples of this kind, so the score "
                "may be unreliable. Legitimate services such as mail or "
                "documentation sites can be wrongly scored as risky."
            )

        st.caption(
            "These are model probabilities, not calibrated guarantees "
            "of real-world safety. Treat unfamiliar links cautiously."
        )

        with st.expander(
            f"View the {len(feature_order)} features sent to the model"
        ):
            st.dataframe(
                pd.DataFrame({
                    "Feature": feature_order,
                    "Value": [features[name] for name in feature_order]
                }),
                hide_index=True,
                use_container_width=True
            )

        st.info(
            "Privacy note: This application performs local feature "
            "extraction and model inference. It does not open, crawl, "
            "or submit the entered URL to a remote website."
        )

    except ValueError as exc:
        st.warning(str(exc))

    except Exception as exc:
        st.error(f"Analysis failed: {exc}")


st.subheader("How this detector works")

st.markdown(f"""
1. The entered URL is normalized and validated.

2. **{len(feature_order)} features** are extracted from the host (domain name) only.

3. A trained Random Forest classifier predicts:
   - `0` = Phishing
   - `1` = Legitimate

4. The model's phishing probability is displayed.

---

**Why host-only?**

In the training dataset, every legitimate URL was a bare homepage, so path-based features taught the model that "has a path" means phishing. V4 therefore ignores the path and query.

**Limitations:**

This URL-only model cannot inspect page content, redirects, certificates, domain reputation, or live threat intelligence. In grouped cross-validation, V4 flagged about 7% of legitimate domains and missed about 35% of phishing domains. Host subdomains are especially unreliable, and phishing pages on trusted domains cannot be detected.

It is an educational screening tool, not a replacement for browser protections or security analysis.
""")

st.caption(
    f"Educational cybersecurity project • Random Forest {model_version} • "
    "PhiUSIIL-derived training workflow"
)
