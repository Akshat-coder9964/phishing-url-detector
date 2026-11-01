
import time
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)

from feature_extractor_v2 import extract_features_v2


print("===== PHISHING DETECTOR V2 TRAINING =====")

# 1. Load dataset
print("\nLoading dataset...")

df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")
df = df.dropna(subset=["URL", "label"])
df = df.drop_duplicates(subset=["URL"])

y = df["label"].astype(int)

# 2. Extract features
print("Extracting features...")

X = pd.DataFrame(
    [extract_features_v2(url) for url in df["URL"]]
)

# Remove the two highly dataset-biased features
X = X.drop(columns=["HasHTTPS", "PathLength"])

print("Features used:", list(X.columns))
print("Total features:", X.shape[1])

# 3. Split by domain
print("\nSplitting dataset...")

groups = df["Domain"].fillna(df["URL"]).astype(str)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]
y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

print("Training records:", len(X_train))
print("Testing records:", len(X_test))

# 4. Train 100-tree Random Forest
print("\nTraining 100-tree Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    max_features="sqrt",
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

start = time.time()
model.fit(X_train, y_train)
training_time = time.time() - start

# 5. Evaluate
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)

print("\n===== EVALUATION RESULTS =====")

print("Accuracy:", round(
    accuracy_score(y_test, predictions) * 100, 2
), "%")

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Phishing (0)", "Legitimate (1)"],
    zero_division=0
))

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

print("ROC-AUC:", round(
    roc_auc_score(y_test, probabilities[:, 1]), 4
))

print("Training time:", round(training_time, 2), "seconds")

# 6. Save V2 model separately
joblib.dump(
    {
        "model": model,
        "feature_names": list(X.columns),
        "classes": list(model.classes_)
    },
    "phishing_detector_v2.pkl"
)

print("\nV2 MODEL SAVED SUCCESSFULLY!")
