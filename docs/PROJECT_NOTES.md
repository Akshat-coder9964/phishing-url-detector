# Project notes

## Update: V4 host-only model (current)

After the original package was assembled, the model was investigated and rebuilt. Full evidence is in [`MODEL_EVALUATION.md`](MODEL_EVALUATION.md).

### What changed

- The original model (V2, whole-URL features) flagged legitimate sites such as `github.com` as phishing.
- Dataset inspection found three artifacts: every legitimate URL starts with `www.`, no legitimate URL has a path or query, and legitimate hosts with subdomains are almost absent.
- A host-only model (V4, 10 features) was trained with de-duplication by host, removal of hosts with conflicting labels, a split grouped by registered domain, and 5-fold grouped cross-validation.
- `app.py` now loads V4, with V2 as a fallback that shows a warning. It displays the analyzed host, an uncertainty notice near the decision boundary, and a low-confidence warning for hosts with a subdomain.
- Uppercase URL schemes (for example `HTTPS://...`) are now handled in `url_utils.py` and the feature extractor.
- Tests were added for the V4 extractor, URL validation and the model pipeline.

### Honest result

Grouped cross-validation: ROC-AUC about 0.84, about 7% of legitimate domains flagged, about 35% of phishing domains missed. The earlier 99% accuracy figures were inflated by the dataset artifacts above.

### Status of the original validation checklist

1. Run the app in the user's Windows environment using the pinned package versions: **done** (Python 3.13, pinned versions match the local environment).
2. Verify the model's label mapping against the training target values: **done**. `0` = phishing, `1` = legitimate, checked from sample URLs in the dataset.
3. Compare the original 16 feature values against the dataset: **not applicable to V4**. V4 uses its own 10 host-only features, covered by unit tests. The original 16-feature extractor is only relevant to the legacy files.
4. Re-evaluate with a domain-separated holdout: **done** (split and cross-validation grouped by registered domain). A time-separated evaluation has not been done.
5. Calibrate probability outputs: **not done**. The app keeps the "not calibrated" disclaimer.
6. Threat-intelligence lookups: **not added**. This would send URLs to an external service and needs an explicit privacy decision.

### Known limitations and next steps

- Hosts with subdomains are unreliable because the training data has very few legitimate examples.
- Phishing pages on trusted or compromised domains cannot be detected from the host alone.
- Next steps: add legitimate hosts with subdomains and recent phishing feeds, use the Public Suffix List, calibrate probabilities, and evaluate on a newer dataset.

---

## Original package notes (historical)

### Preserved from the original project

- The original `feature_extractor.py` and its 16 feature names/calculations.
- The original `phishing_detector_model.pkl` model artifact.
- The original command-line prediction utility.

### Improvements in the original package

- URL input normalization and validation before feature extraction.
- Explicit feature ordering before model inference.
- Streamlit form-based interface with result explanation and feature inspection.
- Honest wording around model probability and the limitations of URL-only detection.
- Local automated tests for URL validation and feature schema.
- Clean dependency file and Git ignore rules; the bundled virtual environment is intentionally excluded.

### Remaining validation listed at that time

1. Run the app in the user's Windows environment using the pinned package versions.
2. Verify the model's label mapping against the exact training target values.
3. Run the original feature-validation script against the same PhiUSIIL source and compare all 16 feature values on a representative sample, not only five rows.
4. Re-evaluate using a time-separated or domain-separated holdout to reduce duplicate/domain leakage.
5. Calibrate probability outputs if they will be presented as confidence; otherwise keep the current disclaimer.
6. Add threat-intelligence lookups only with an explicit privacy decision because doing so sends URLs to an external service.
