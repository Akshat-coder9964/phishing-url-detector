# AI-Based Phishing URL Detector

A local Streamlit application that scores the **host (domain name)** of a URL with a pre-trained Random Forest classifier and labels it as potentially phishing (`0`) or likely legitimate (`1`). The current model (V4) uses 10 host-only features. The path, query string and a leading `www.` are ignored on purpose (see "Why host-only?").

This is an educational cybersecurity project. It is a screening aid, not a security product.

## Honest performance summary

On the PhiUSIIL dataset, using 5-fold cross-validation grouped by registered domain:

| Metric | V4 (current) |
|---|---:|
| ROC-AUC | 0.844 (+/- 0.002) |
| Legitimate domains flagged as phishing | about 6.7% |
| Phishing domains missed | about 34.9% |

Earlier versions (V2, V3) reported about 99% accuracy, but that figure was inflated by dataset artifacts and **should not be trusted**. Details are in [`docs/MODEL_EVALUATION.md`](docs/MODEL_EVALUATION.md).

## Why host-only?

Investigation of the dataset showed that:

- **Every** legitimate URL starts with `www.`, and every URL without it is phishing.
- **No** legitimate URL has a path or a query string; all are bare homepages.
- Legitimate hosts with subdomains (for example `mail.google.com`) are almost absent.

Models that used the full URL learned these collection artifacts instead of real phishing behaviour, for example "has a path means phishing". V4 therefore scores only the domain name, which is the part of the URL this dataset can genuinely teach.

## Run locally (Windows)

1. Install **Python 3.13** (the project was developed and tested on 3.13). Other recent versions may work, but the pinned package versions in `requirements.txt` must be installable.
2. Extract this project folder.
3. Open PowerShell in the `PhishingDetector` folder.
4. Create and activate a virtual environment:

   ```powershell
   py -3.13 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. Start the application:

   ```powershell
   streamlit run app.py
   ```

6. Open the local address Streamlit prints (normally `http://localhost:8501`).

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal and activate again.

## Run tests

```powershell
python -m pytest -q
```

The tests cover the V4 feature extractor, URL validation, and the model loading and prediction pipeline.

## Retrain the model (optional)

The training dataset is not included in this repository. Download the PhiUSIIL Phishing URL Dataset and place the CSV at `data/PhiUSIIL_Phishing_URL_Dataset.csv`, then run:

```powershell
python train_model_v4.py
```

This de-duplicates by host, removes hosts that carry both labels, splits by registered domain, prints held-out and cross-validated results, and saves `phishing_detector_v4.pkl`.

## Project files

- `app.py` - Streamlit user interface and inference flow. Loads V4 and falls back to V2 (with a visible warning) if V4 cannot be loaded.
- `feature_extractor_v4.py` - host-only feature extractor used by the current model.
- `train_model_v4.py` - training and grouped-validation script for V4.
- `phishing_detector_v4.pkl` - current trained Random Forest model (10 features).
- `url_utils.py` - input normalization and validation; does not make network requests.
- `feature_extractor_v2.py`, `train_model_v2.py`, `phishing_detector_v2.pkl` - earlier whole-URL version (V2), kept for reference and as a fallback. Known to be biased by dataset artifacts.
- `feature_extractor_v3.py`, `train_model_v3.py`, `phishing_detector_v3.pkl` - intermediate experiment (V3), kept for reference.
- `diagnose_www.py`, `diagnose_path.py`, `diagnose_subdomain.py`, `compare_v4_variants.py` - scripts that produced the dataset-bias evidence.
- `tests/` - automated tests.
- `docs/` - project notes and the model evaluation report.

Files from the original project (such as `feature_extractor.py`, `predict.py` and `phishing_detector_model.pkl`), if still present, are not used by the current app.

## Model and reproducibility notes

The model files were created with scikit-learn **1.9.0**. The dependency file pins that version because scikit-learn pickle/joblib artifacts are not guaranteed to be compatible across versions. Only load model files from this trusted project source.

When loading the model you may see a NumPy deprecation warning coming from joblib. It is harmless and does not affect predictions.

## Important limitations

- This is a URL-feature classifier, not a browser or website scanner. It looks at the domain name only.
- It does not fetch pages, follow redirects, inspect HTML/JavaScript, validate TLS certificates, or query domain-reputation or threat-intelligence services.
- **Phishing on trusted domains cannot be detected.** A phishing page hosted on a legitimate or compromised domain has a legitimate-looking host.
- **Hosts with subdomains are unreliable.** The training data contained very few legitimate examples, so services such as `mail.google.com` or `docs.python.org` are often over-flagged. The app shows a warning for these.
- **Many phishing domains are missed** (about 35% in cross-validation), especially ones that look like ordinary domain names.
- The legitimate class in the dataset consists of popular homepages, so unusual but legitimate domains may be scored as risky.
- The displayed probability is **not calibrated** and is not the probability that a site is truly safe.
- A `likely legitimate` result is not a safety guarantee. Do not enter passwords or payment details on unfamiliar sites.
- The dataset is a fixed snapshot, and phishing techniques change over time.

## Label convention

Class `0` means phishing and class `1` means legitimate. This mapping was checked against sample URLs from the dataset (label `0` samples are clearly phishing-style hosts, label `1` samples are ordinary websites).
