# AI Phishing URL Detector

An educational URL screening application using Python, Streamlit and a Random Forest classifier.

## Run on Windows

1. Install a compatible Python version.
2. Open PowerShell in this folder.
3. Create a virtual environment:

   `python -m venv .venv`

4. Activate it:

   `.\.venv\Scripts\Activate.ps1`

5. Install dependencies:

   `python -m pip install -r requirements.txt`

6. Run:

   `python -m streamlit run app.py`

7. Open `http://localhost:8501`.

## Main files

- `app.py` - Streamlit application.
- `feature_extractor_v2.py` - Extracts 14 URL features.
- `phishing_detector_v2.pkl` - Trained Random Forest model.
- `url_utils.py` - URL normalization and validation.
- `train_model_v2.py` - Model training script.
- `tests/` - Project tests.
- `docs/` - Project documentation.

## Retraining

The training script expects the PhiUSIIL CSV dataset at:

`data/PhiUSIIL_Phishing_URL_Dataset.csv`

The dataset is not included in this submission ZIP. Obtain it separately from the UCI Machine Learning Repository before retraining.

## Limitations

This application analyses URL structure only. It does not visit websites, inspect page content, follow redirects, validate TLS certificates or query live threat-intelligence services.

Model scores are not calibrated guarantees of safety. A legitimate classification does not prove that a website is safe.
