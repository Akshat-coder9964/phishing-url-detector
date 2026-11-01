# Project completion notes

## Preserved from the original project

- The original `feature_extractor.py` and its 16 feature names/calculations.
- The original `phishing_detector_model.pkl` model artifact.
- The original command-line prediction utility.

## Improvements in this package

- URL input normalization and validation before feature extraction.
- Explicit feature ordering before model inference.
- Streamlit form-based interface with result explanation and feature inspection.
- Honest wording around model probability and the limitations of URL-only detection.
- Local automated tests for URL validation and feature schema.
- Clean dependency file and Git ignore rules; the bundled virtual environment is intentionally excluded.

## Remaining validation before calling it production-ready

1. Run the app in the user's Windows environment using the pinned package versions.
2. Verify the model's label mapping against the exact training target values.
3. Run the original feature-validation script against the same PhiUSIIL source and compare all 16 feature values on a representative sample, not only five rows.
4. Re-evaluate using a time-separated or domain-separated holdout to reduce duplicate/domain leakage.
5. Calibrate probability outputs if they will be presented as confidence; otherwise keep the current disclaimer.
6. Add threat-intelligence lookups only with an explicit privacy decision because doing so sends URLs to an external service.
