# Model Evaluation Report

This document records how the phishing detector was investigated and why the final model (V4) scores only the host of a URL. All numbers come from scripts in this repository, run on the PhiUSIIL Phishing URL Dataset.

Label convention: `0` = phishing, `1` = legitimate.

## 1. The original problem

The first model (V2, 14 whole-URL features) classified `https://github.com` and the author's own GitHub repository URL as phishing, while `https://www.github.com` was classified as legitimate. A feature experiment showed that changing only the dot count from 1 to 2 moved the prediction close to the decision boundary.

## 2. Dataset artifacts found

### 2.1 The `www.` artifact (`diagnose_www.py`)

| Hostname starts with `www.` | Phishing | Legitimate |
|---|---:|---:|
| No | 58,802 | 0 |
| Yes | 41,718 | 134,850 |

Every legitimate URL has `www.`. The model learned "no www means phishing". This also explains the high importance of hostname length, dot count and subdomain count.

### 2.2 The homepage-only artifact (`diagnose_path.py`)

| | Phishing | Legitimate |
|---|---:|---:|
| URLs with a path | 27,284 | 0 |
| URLs with a query string | 6,071 | 0 |

No legitimate URL has a path or a query. Any feature related to path, length or slashes therefore teaches "has a path means phishing", and real deep links (for example a GitHub repository page) are misjudged.

### 2.3 Subdomain bias (`diagnose_subdomain.py`)

Host-level counts after removing `www.` and de-duplicating hosts:

| Subdomains | Phishing | Legitimate |
|---:|---:|---:|
| 0 | 37,440 | 127,190 |
| 1 | 35,796 | 6,654 |
| 2 | 8,684 | 947 |
| 3 | 1,620 | 24 |
| 4 or more | 739 | 0 |

Only about 6% of legitimate hosts have a subdomain, because the legitimate class consists of `www.` homepages. Service hosts such as `mail.google.com` or `docs.python.org` are systematically missing. Three or more subdomains is, however, a genuine phishing indicator in this data. A small share of the "legitimate subdomains" are multi-part domain suffixes (for example `wa.gov.au`, `k12.va.us`) that the built-in suffix list does not cover.

## 3. Model versions

| Version | Features | Description |
|---|---:|---|
| V2 | 14 | whole-URL features, dropped HasHTTPS and PathLength |
| V3 | 13 | V2 with `www.` removed from the URL and DotCount dropped |
| V4 | 10 | **host only**: path, query and `www.` ignored |

V4 features: HostLength, SubdomainCount, HyphenCount, DigitCount, DigitRatio, LetterRatio, IsIP, SuspiciousWordCount, MaxLabelLength, TLDLength.

### 3.1 Results

| | V2 | V3 | V4 |
|---|---:|---:|---:|
| Held-out accuracy | 99.41% | 99.32% | 82.45% |
| Held-out ROC-AUC | 0.9979 | 0.9965 | 0.8412 |
| Legitimate flagged as phishing | 0.40% | 0.36% | 7.14% |
| Phishing missed | 0.84% | 1.12% | 34.59% |

**Important:** V2 and V3 were evaluated on the original URL-level data and split. V4 uses a stricter pipeline (host de-duplication, removal of 58 hosts with conflicting labels, split by registered domain), so the columns are not an exact like-for-like comparison. The high V2/V3 scores should not be read as better models: their test sets contain the same artifacts as their training sets, so the scores measure how well the shortcuts transfer, not how well real phishing is detected. V3 still misjudged 5 of 10 legitimate spot-check URLs, all with a path or subdomain.

### 3.2 V4 validation details

- 219,036 unique hosts (84,244 phishing, 134,792 legitimate).
- Train/test split grouped by registered domain, with zero domain overlap.
- 5-fold grouped cross-validation:

| Metric | Mean | Std. dev. |
|---|---:|---:|
| ROC-AUC | 0.8435 | 0.0022 |
| Legitimate flagged as phishing | 6.69% | 0.28 |
| Phishing missed | 34.88% | 0.39 |

### 3.3 Subdomain variants (`compare_v4_variants.py`)

| Variant | AUC | Legit flagged % | Phishing missed % |
|---|---:|---:|---:|
| A: all 10 features (V4) | 0.8435 | 6.69 | 34.88 |
| B: no SubdomainCount | 0.8424 | 6.79 | 34.98 |
| C: flag for 3+ subdomains | 0.8425 | 6.78 | 34.95 |

The variants perform almost identically, and subdomain hosts such as `mail.google.com` remained over-flagged in all of them, because host length and label length carry the same signal. The bias comes from the dataset, not from one feature. Variant A was kept.

## 4. V4 spot checks

Phishing probability from the model (threshold 50%):

| URL host | Probability | Note |
|---|---:|---|
| github.com (any path) | about 29% | legitimate, correct |
| google.com | about 29% | legitimate, correct; host is in the training data |
| microsoft.com | about 27% | legitimate, correct |
| bbc.co.uk | about 8% | legitimate, correct |
| mail.google.com, docs.python.org | about 77% | legitimate, **wrongly flagged** |
| learn.microsoft.com | about 88% | legitimate, **wrongly flagged** |
| developer.mozilla.org | about 85% | legitimate, **wrongly flagged** |
| en.wikipedia.org | about 52% | legitimate, borderline |

Six synthetic phishing-style hosts (made up for testing, not real sites) were all flagged at 94% to 100%.

## 5. What this does and does not show

- The dataset can only teach the model what legitimate and phishing **domain names** look like, so V4 scores the host only.
- About 82% accuracy and AUC 0.84 is the realistic level for a domain-name-only model on this dataset.
- A URL-only model cannot detect phishing pages on trusted or compromised domains, and cannot see page content, certificates or reputation.

## 6. Future work

- Add legitimate hosts that include subdomains (for example from a popularity-ranked domain list; check its format and license) and recent phishing feeds (OpenPhish, PhishTank). Re-run the same grouped cross-validation to confirm a genuine improvement.
- Use the full Public Suffix List (for example the `tldextract` package) instead of the small built-in suffix list.
- Calibrate probabilities and tune the decision threshold, reporting false positives and false negatives separately.
- Evaluate on a separate, more recent dataset.
