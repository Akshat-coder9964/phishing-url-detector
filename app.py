import streamlit as st
import joblib
import pandas as pd

from feature_extractor import extract_features


# Load the trained AI model
model = joblib.load("phishing_detector_model.pkl")


# Page title
st.title("🛡️ AI Phishing URL Detector")

st.write(
    "Enter a website URL to check whether it is legitimate or phishing."
)


# URL input
url = st.text_input("Enter URL:")


# Check button
if st.button("Check URL"):

    if url.strip() == "":
        st.warning("Please enter a URL.")

    else:
        # Add HTTPS if the user did not provide a protocol
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Extract URL features
        features = extract_features(url)

        # Convert features to DataFrame
        input_data = pd.DataFrame([features])

        # Make prediction
        prediction = model.predict(input_data)[0]

        # Get confidence
        probabilities = model.predict_proba(input_data)[0]
        confidence = max(probabilities) * 100

        # Show result
        if prediction == 0:
            st.error("⚠️ Phishing Website")
        else:
            st.success("✅ Legitimate Website")

        st.write(f"Confidence: **{confidence:.2f}%**")