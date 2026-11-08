
from pathlib import Path

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from lightgbm import LGBMClassifier

# Locate the project folder
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data" / "processed"

# Load historical datasets
train = pd.read_parquet(
    DATA_DIR / "training_2024.parquet"
)

valid = pd.read_parquet(
    DATA_DIR / "validation_2025.parquet"
)

print("Training rows:", len(train))
print("Validation rows:", len(valid))
print("Training positives:", train["target"].sum())
print("Validation positives:", valid["target"].sum())


# Features available at the historical snapshot
features = [
    "epss",
    "exploitdb",
    "metasploit",
    "nuclei",
    "poc_github",
    "epss_missing",
    "exploitdb_missing",
    "metasploit_missing",
    "nuclei_missing",
    "poc_github_missing"
]

# Model inputs
X_train = train[features]
X_valid = valid[features]

# Correct historical outcomes
y_train = train["target"]
y_valid = valid["target"]

print("\nFeatures:", features)
print("Training shape:", X_train.shape)
print("Validation shape:", X_valid.shape)


# Train Logistic Regression
logistic_model = LogisticRegression(
    class_weight="balanced",
    max_iter=2000,
    random_state=42
)

logistic_model.fit(X_train, y_train)

# Generate validation ranking scores
logistic_scores = logistic_model.predict_proba(
    X_valid
)[:, 1]

print("\nLogistic Regression trained successfully!")


# Train a conservative LightGBM model
lightgbm_model = LGBMClassifier(
    n_estimators=100,
    learning_rate=0.05,
    num_leaves=7,
    max_depth=3,
    min_child_samples=50,
    reg_lambda=5.0,
    class_weight="balanced",
    random_state=42,
    verbosity=-1
)

lightgbm_model.fit(X_train, y_train)

# Predict validation ranking scores
lightgbm_scores = lightgbm_model.predict_proba(
    X_valid
)[:, 1]

print("LightGBM trained successfully!")



# Evaluate ranking performance on 2025
def evaluate_model(name, scores):
    results = valid[["cve_id", "target"]].copy()
    results["score"] = scores

    # Sort by predicted score
    results = results.sort_values(
        by=["score", "cve_id"],
        ascending=[False, True]
    )

    print(f"\n--- {name} ---")

    for budget in [100, 250, 500]:
        hits = int(results.head(budget)["target"].sum())
        precision = hits / budget

        print(
            f"Hits@{budget}: {hits} "
            f"| Precision: {precision:.2%}"
        )

    pr_auc = average_precision_score(
        y_valid, scores
    )

    print(f"Average Precision (AP): {pr_auc:.6f}")


evaluate_model(
    "Logistic Regression",
    logistic_scores
)

evaluate_model(
    "LightGBM",
    lightgbm_scores
)



# STEP 47: Export ML evaluation metrics

RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def get_metrics(name, scores):
    ranked_results = valid[["cve_id", "target"]].copy()
    ranked_results["score"] = scores

    ranked_results = ranked_results.sort_values(
        ["score", "cve_id"],
        ascending=[False, True]
    )

    metrics = {"model": name}

    for k in [100, 250, 500]:
        metrics[f"hits_{k}"] = int(
            ranked_results.head(k)["target"].sum()
        )

    metrics["average_precision"] = average_precision_score(
        valid["target"], scores
    )

    return metrics

ml_metrics = [
    get_metrics("Logistic Regression", logistic_scores),
    get_metrics("LightGBM", lightgbm_scores)
]

pd.DataFrame(ml_metrics).to_csv(
    RESULTS_DIR / "ml_metrics.csv",
    index=False
)

print("\nML metrics exported successfully!")
print(pd.DataFrame(ml_metrics).to_string(index=False))
