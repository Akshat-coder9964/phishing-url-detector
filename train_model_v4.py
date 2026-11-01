"""Train V4 (host-only) with stricter, more honest validation.

Compared with V2/V3:
  * Features come only from the hostname (path/query ignored).
  * Rows are de-duplicated by HOST (many phishing URLs share one host).
  * Hosts that appear with both labels are dropped (label conflicts).
  * Train/test split is grouped by REGISTERED DOMAIN, so e.g. every
    *.repl.co host lands on the same side of the split.
  * 5-fold grouped cross-validation gives a more stable estimate.

V2 and V3 files are not touched. Output: phishing_detector_v4.pkl
"""
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, roc_auc_score
)

from feature_extractor_v4 import (
    FEATURE_NAMES_V4, extract_features_v4, get_host, registered_domain
)

print("===== PHISHING DETECTOR V4 (HOST-ONLY) TRAINING =====")

# 1. Load and clean
df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")
df = df.dropna(subset=["URL", "label"])
df = df.drop_duplicates(subset=["URL"])
df["label"] = df["label"].astype(int)
df["Host"] = df["URL"].map(get_host)
df = df[df["Host"] != ""]
print("\nRows after URL de-duplication:", len(df))

# Hosts seen with both labels are ambiguous -> drop them
label_counts = df.groupby("Host")["label"].nunique()
conflict_hosts = label_counts[label_counts > 1].index
print("Hosts with conflicting labels (dropped):", len(conflict_hosts))
df = df[~df["Host"].isin(conflict_hosts)]

# One row per host
df = df.drop_duplicates(subset=["Host"]).reset_index(drop=True)
print("Unique hosts kept:", len(df))
print("Label counts (0=phishing, 1=legitimate):")
print(df["label"].value_counts().sort_index().to_string())

# 2. Features
print("\nExtracting host-only features...")
X = pd.DataFrame([extract_features_v4(h) for h in df["Host"]])[FEATURE_NAMES_V4]
y = df["label"]
groups = df["Host"].map(registered_domain)
print("Features used:", list(X.columns))
print("Distinct registered domains (groups):", groups.nunique())


def make_model():
    return RandomForestClassifier(
        n_estimators=100,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )


def metrics(model, X_te, y_te):
    pred = model.predict(X_te)
    proba = model.predict_proba(X_te)[:, list(model.classes_).index(1)]
    cm = confusion_matrix(y_te, pred, labels=[0, 1])
    phish_missed = cm[0, 1]      # phishing predicted as legitimate
    legit_flagged = cm[1, 0]     # legitimate predicted as phishing
    return {
        "pred": pred, "cm": cm,
        "auc": roc_auc_score(y_te, proba),
        "fp_rate": legit_flagged / cm[1].sum() * 100,   # legit flagged
        "fn_rate": phish_missed / cm[0].sum() * 100,    # phishing missed
        "legit_flagged": legit_flagged, "phish_missed": phish_missed,
    }


# 3. Single grouped split (80/20)
splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups=groups))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
print("\nTraining records:", len(X_train), "| Testing records:", len(X_test))
print("Registered domains shared by train and test:",
      len(set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])), "(should be 0)")

model = make_model()
start = time.time()
model.fit(X_train, y_train)
print("Training time:", round(time.time() - start, 2), "seconds")

m = metrics(model, X_test, y_test)
print("\n===== V4 HELD-OUT RESULTS =====")
print("Accuracy:", round(accuracy_score(y_test, m["pred"]) * 100, 2), "%")
print("ROC-AUC :", round(m["auc"], 4))
print(classification_report(
    y_test, m["pred"],
    target_names=["Phishing (0)", "Legitimate (1)"], zero_division=0
))
print("Confusion matrix [rows=true, cols=predicted] (0=phish, 1=legit):")
print(m["cm"])
print(f"LEGITIMATE flagged as phishing : {m['legit_flagged']}  ({m['fp_rate']:.2f}%)")
print(f"PHISHING passed as legitimate  : {m['phish_missed']}  ({m['fn_rate']:.2f}%)")

# 4. 5-fold grouped cross-validation
print("\n===== 5-FOLD GROUPED CROSS-VALIDATION =====")
rows = []
for fold, (tr, te) in enumerate(GroupKFold(n_splits=5).split(X, y, groups=groups), 1):
    fold_model = make_model().fit(X.iloc[tr], y.iloc[tr])
    r = metrics(fold_model, X.iloc[te], y.iloc[te])
    rows.append((r["auc"], r["fp_rate"], r["fn_rate"]))
    print(f"Fold {fold}: AUC {r['auc']:.4f} | legit flagged {r['fp_rate']:.2f}% "
          f"| phishing missed {r['fn_rate']:.2f}%")
arr = np.array(rows)
print(f"Mean   : AUC {arr[:, 0].mean():.4f} | legit flagged {arr[:, 1].mean():.2f}% "
      f"| phishing missed {arr[:, 2].mean():.2f}%")
print(f"Std dev: AUC {arr[:, 0].std():.4f} | legit flagged {arr[:, 1].std():.2f}% "
      f"| phishing missed {arr[:, 2].std():.2f}%")

# 5. Feature importance
print("\n===== V4 FEATURE IMPORTANCE =====")
imp = pd.Series(model.feature_importances_, index=FEATURE_NAMES_V4)
print(imp.sort_values(ascending=False).round(4).to_string())

# 6. Spot checks. Phishing-style URLs are SYNTHETIC (made up for structure).
legit_tests = [
    "https://github.com",
    "https://www.github.com",
    "https://github.com/Akshat-coder9964/phishing-url-detector",
    "https://www.google.com",
    "https://mail.google.com/mail/u/0/",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://stackoverflow.com/questions/tagged/python",
    "https://docs.python.org/3/",
    "https://pypi.org/project/scikit-learn/",
    "https://www.microsoft.com",
    "https://www.amazon.in",
    "https://www.bbc.co.uk/news",
]
phish_tests = [
    "http://paypal-secure-login.verify-account-update.example-xyz.com/signin",
    "http://192.168.10.55/banking/confirm/password-reset.php",
    "http://secure-update-account.login-verify.co.xx/wallet/authenticate",
    "http://amaz0n-support-recover.suspend-alert-1234.info/login.php",
    "https://williamsyahoomailboxupdate213.weebly.com/",
    "http://2001453526565.20331064515.my.id/failure.php",
]


def spot_check(title, urls, expect_label):
    print(f"\n----- Spot check: {title} -----")
    wrong = 0
    for u in urls:
        row = pd.DataFrame([extract_features_v4(u)])[FEATURE_NAMES_V4]
        p_phish = model.predict_proba(row)[0][list(model.classes_).index(0)]
        label = 0 if p_phish >= 0.5 else 1
        mark = "OK " if label == expect_label else "BAD"
        wrong += label != expect_label
        print(f"[{mark}] phishing prob {p_phish * 100:5.1f}%  {u}")
    print(f"Wrong: {wrong}/{len(urls)}")


spot_check("legitimate URLs (should be class 1)", legit_tests, 1)
spot_check("synthetic phishing-style URLs (should be class 0)", phish_tests, 0)

# 7. Save (same bundle layout as V2, so app.py can load it)
joblib.dump(
    {
        "model": model,
        "feature_names": list(FEATURE_NAMES_V4),
        "classes": list(model.classes_),
        "host_only": True,
    },
    "phishing_detector_v4.pkl",
)
print("\nV4 MODEL SAVED as phishing_detector_v4.pkl (V2 and V3 untouched).")
