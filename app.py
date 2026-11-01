
from pathlib import Path
import joblib
import pandas as pd
import streamlit as st

from feature_extractor_v2 import extract_features_v2
from url_utils import normalize_url


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_detector_v2.pkl"

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


# Load V2 model and its feature configuration
@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found: {MODEL_PATH.name}"
        )

    bundle = joblib.load(MODEL_PATH)

    return bundle["model"], bundle["feature_names"]


try:
    model, feature_order = load_model()
except Exception as exc:
    st.error(f"Could not load V2 model: {exc}")
    st.stop()


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

        features = extract_features_v2(url)

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

        st.caption(
            "These are model probabilities, not calibrated guarantees "
            "of real-world safety. Treat unfamiliar links cautiously."
        )

        with st.expander("View the 14 features sent to the model"):
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


with st.expander("How this detector works"):
    st.markdown("""
    1. The entered URL is normalized and validated.
    2. Fourteen URL-structure features are extracted.
    3. A trained Random Forest classifier predicts:
       - `0` = Phishing
       - `1` = Legitimate
    4. The model's phishing probability is displayed.

    **Limitations:** This URL-only model cannot inspect page content,
    redirects, certificates, domain reputation, or live threat
    intelligence. It is an educational screening tool, not a
    replacement for browser protections or security analysis.
    """)

st.caption(
    "Educational cybersecurity project • Random Forest V2 • "
    "PhiUSIIL-derived training workflow"
)
