"""
Tell Platform - ML Training, Evaluation, and Top-500 Prediction
Author: Member 1 (Data Science & Prediction)

Implements:
1. Zero-leakage time-safe feature extraction
2. Standard baselines (CVSS, EPSS alone, Exploit+EPSS)
3. Supervised classifiers: Logistic Regression & LightGBM Ranker
4. Rigorous evaluation on 2025 held-out cohort (Hits@100/250/500, Precision, Recall, AUC)
5. Top-500 KEV risk prediction for the 72,670 eligible 2026 CVEs
6. Exports agreed inter-team contract files:
   - results/predictions.csv (cve_id, rank, prediction_score, epss, ...)
   - results/metrics.csv (model, hits_100, hits_250, hits_500, ...)
   - results/top500.csv (cve_id, exactly 500 rows)
"""

import os
import sys
import logging
import pickle
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score
import lightgbm as lgb

from src.data.cohort_builder import CohortBuilder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Tell.ML")


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Constructs time-safe features from the 5 available snapshot signals.
    Does NOT use any forward-looking NIST attributes.
    """
    feats = pd.DataFrame(index=df.index)
    feats["epss"] = df["epss"].astype(float)
    feats["epss_log"] = np.log1p(feats["epss"] * 10.0)
    feats["exploitdb"] = df["exploitdb"].astype(float)
    feats["metasploit"] = df["metasploit"].astype(float)
    feats["nuclei"] = df["nuclei"].astype(float)
    feats["poc_github"] = df["poc_github"].astype(float)

    # Derived interaction features
    feats["has_any_exploit"] = (
        (feats["exploitdb"] > 0) |
        (feats["metasploit"] > 0) |
        (feats["nuclei"] > 0) |
        (feats["poc_github"] > 0)
    ).astype(float)

    feats["exploit_count"] = (
        feats["exploitdb"] + feats["metasploit"] + feats["nuclei"] + feats["poc_github"]
    )
    feats["weaponized"] = ((feats["metasploit"] > 0) | (feats["nuclei"] > 0)).astype(float)
    feats["multi_exploit"] = (feats["exploit_count"] > 1).astype(float)
    feats["epss_x_exploit"] = feats["epss"] * feats["has_any_exploit"]
    feats["epss_x_weaponized"] = feats["epss"] * feats["weaponized"]

    return feats


def calculate_metrics(model_name: str, scores: np.ndarray, targets: np.ndarray) -> dict:
    """Calculates Hits@K, Precision@K, Recall@K, and AUC metrics."""
    order = np.argsort(-scores)
    total_positives = int(targets.sum())

    results = {"model": model_name}
    for k in [100, 250, 500]:
        top_k_targets = targets[order[:k]]
        hits = int(top_k_targets.sum())
        prec = hits / k
        rec = hits / total_positives if total_positives > 0 else 0.0
        results[f"hits_{k}"] = hits
        results[f"precision_{k}"] = round(prec, 4)
        results[f"recall_{k}"] = round(rec, 4)

    try:
        results["roc_auc"] = round(roc_auc_score(targets, scores), 4)
        results["pr_auc"] = round(average_precision_score(targets, scores), 4)
    except Exception:
        results["roc_auc"] = 0.5
        results["pr_auc"] = 0.0

    return results


def run_pipeline():
    base_dir = Path(__file__).resolve().parents[2]
    results_dir = base_dir / "results"
    models_dir = base_dir / "models"
    results_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    # 1. Ingest Data
    logger.info("Initializing CohortBuilder...")
    builder = CohortBuilder()
    train_2024, val_2025, scoreboard_2026 = builder.get_datasets()

    logger.info(f"Extracting features for 2024 Train ({len(train_2024)} rows)...")
    X_train = extract_features(train_2024)
    y_train = train_2024["target"].values

    logger.info(f"Extracting features for 2025 Val ({len(val_2025)} rows)...")
    X_val = extract_features(val_2025)
    y_val = val_2025["target"].values

    logger.info(f"Extracting features for 2026 Scoreboard ({len(scoreboard_2026)} rows)...")
    X_test_2026 = extract_features(scoreboard_2026)

    # 2. Evaluate Baselines on 2025 Held-Out
    logger.info("Evaluating Baselines on 2025 Held-Out Data...")
    metrics_list = []

    # Baseline A: CVSS Score
    cvss_val_scores = val_2025["cvss3_score"].fillna(0.0).values
    metrics_list.append(calculate_metrics("CVSS 3.1 Severity Baseline", cvss_val_scores, y_val))

    # Baseline B: EPSS Alone
    epss_val_scores = val_2025["epss"].values
    metrics_list.append(calculate_metrics("EPSS Point-in-Time Baseline", epss_val_scores, y_val))

    # Baseline C: Exploit Signals + EPSS
    exploit_epss_scores = (
        (val_2025["exploitdb"] + val_2025["metasploit"] + val_2025["nuclei"] + val_2025["poc_github"]) * 10.0 +
        val_2025["epss"]
    ).values
    metrics_list.append(calculate_metrics("Public Exploit + EPSS Heuristic", exploit_epss_scores, y_val))

    # 3. Supervised Model 1: Logistic Regression
    logger.info("Training Logistic Regression Model...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test_2026)

    lr_model = LogisticRegression(class_weight="balanced", C=0.5, max_iter=1000, random_state=42)
    lr_model.fit(X_train_scaled, y_train)
    lr_val_preds = lr_model.predict_proba(X_val_scaled)[:, 1]
    metrics_list.append(calculate_metrics("Logistic Regression (Balanced)", lr_val_preds, y_val))

    # 4. Supervised Model 2: LightGBM Classifier
    logger.info("Training LightGBM Ranking Classifier...")
    pos_count = max(int(y_train.sum()), 1)
    neg_count = len(y_train) - pos_count
    scale_weight = min(neg_count / pos_count, 100.0)  # Bound weight to avoid instability

    lgb_model = lgb.LGBMClassifier(
        n_estimators=120,
        max_depth=4,
        num_leaves=15,
        learning_rate=0.03,
        min_child_samples=15,
        subsample=0.8,
        colsample_bytree=0.85,
        scale_pos_weight=scale_weight,
        random_state=42,
        verbose=-1
    )
    lgb_model.fit(X_train, y_train)
    lgb_val_preds = lgb_model.predict_proba(X_val)[:, 1]
    metrics_list.append(calculate_metrics("LightGBM GBDT Classifier", lgb_val_preds, y_val))

    # 5. Tell Ensemble Ranker (Multi-Signal Blended Scoring)
    # Calibrated fusion combining:
    # 1) Weaponized signal weights (Metasploit +4.5, Nuclei +3.8, ExploitDB +3.5, PoC +2.8)
    # 2) EPSS log-odds magnitude
    # 3) Supervised GBDT decision surface
    logger.info("Evaluating Tell Multi-Signal Ensemble Ranker...")
    val_weapon_score = (
        4.5 * val_2025["metasploit"] +
        3.8 * val_2025["nuclei"] +
        3.5 * val_2025["exploitdb"] +
        2.8 * val_2025["poc_github"] +
        2.5 * np.log1p(val_2025["epss"] * 10.0) +
        1.5 * (X_val["exploit_count"] > 1).astype(float)
    ).values
    tell_val_scores = 0.65 * val_weapon_score + 0.35 * (lgb_val_preds / max(lgb_val_preds.max(), 1e-6) * 10.0)
    metrics_list.append(calculate_metrics("Tell Ensemble Ranker (Production)", tell_val_scores, y_val))

    # Convert metrics to DataFrame & save
    df_metrics = pd.DataFrame(metrics_list)
    metrics_path = results_dir / "metrics.csv"
    df_metrics.to_csv(metrics_path, index=False)
    logger.info(f"Saved metrics to {metrics_path}:\n{df_metrics.to_string()}")

    # 6. Fit Production Model on Combined Historical Data & Score 2026 Scoreboard
    logger.info("Refitting production scoring pipeline on historical cohort...")
    combined_X = pd.concat([X_train, X_val], ignore_index=True)
    combined_y = np.concatenate([y_train, y_val])

    prod_lgb = lgb.LGBMClassifier(
        n_estimators=150,
        max_depth=4,
        num_leaves=15,
        learning_rate=0.03,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.85,
        scale_pos_weight=min((len(combined_y) - combined_y.sum()) / max(combined_y.sum(), 1), 100.0),
        random_state=42,
        verbose=-1
    )
    prod_lgb.fit(combined_X, combined_y)

    # Save model artifact
    model_artifact_path = models_dir / "tell_ranker.pkl"
    with open(model_artifact_path, "wb") as f:
        pickle.dump(prod_lgb, f)
    logger.info(f"Saved trained model to {model_artifact_path}")

    # Predict on 2026 Scoreboard
    logger.info("Scoring 72,670 eligible 2026 CVEs...")
    test_lgb_preds = prod_lgb.predict_proba(X_test_2026)[:, 1]
    test_weapon_score = (
        4.5 * scoreboard_2026["metasploit"] +
        3.8 * scoreboard_2026["nuclei"] +
        3.5 * scoreboard_2026["exploitdb"] +
        2.8 * scoreboard_2026["poc_github"] +
        2.5 * np.log1p(scoreboard_2026["epss"] * 10.0) +
        1.5 * (X_test_2026["exploit_count"] > 1).astype(float)
    ).values
    final_2026_scores = 0.65 * test_weapon_score + 0.35 * (test_lgb_preds / max(test_lgb_preds.max(), 1e-6) * 10.0)

    # Build predictions dataframe
    predictions_df = scoreboard_2026.copy()
    predictions_df["prediction_score"] = np.round(final_2026_scores, 5)
    # Sort descending by prediction_score, then epss
    predictions_df = predictions_df.sort_values(
        by=["prediction_score", "epss", "poc_github"], 
        ascending=[False, False, False]
    ).reset_index(drop=True)
    predictions_df["rank"] = predictions_df.index + 1

    # Contract file 1: predictions.csv
    # Required columns: cve_id, rank, prediction_score, epss (+ exploit flags for transparency)
    contract_pred_cols = [
        "cve_id", "rank", "prediction_score", "epss", 
        "exploitdb", "metasploit", "nuclei", "poc_github", 
        "published", "snapshot_month"
    ]
    pred_path = results_dir / "predictions.csv"
    predictions_df[contract_pred_cols].to_csv(pred_path, index=False)
    logger.info(f"Saved predictions to {pred_path} ({len(predictions_df)} rows)")

    # Contract file 2: top500.csv
    # Official submission requirement: single column cve_id, exactly 500 rows, unique IDs
    top500_df = predictions_df.head(500)[["cve_id"]].copy()
    assert len(top500_df) == 500, f"Expected 500 rows, got {len(top500_df)}"
    assert top500_df["cve_id"].nunique() == 500, "Duplicate CVE IDs detected in top 500!"

    top500_path = results_dir / "top500.csv"
    top500_df.to_csv(top500_path, index=False)
    logger.info(f"Saved official submission to {top500_path} (exactly {len(top500_df)} unique IDs)")

    # Log distribution of Top 500
    top500_full = predictions_df.head(500)
    logger.info(f"Top 500 exploit signals distribution:")
    logger.info(f"  Metasploit: {(top500_full['metasploit'] > 0).sum()} / 15 available in 2026")
    logger.info(f"  Nuclei:     {(top500_full['nuclei'] > 0).sum()} / 167 available in 2026")
    logger.info(f"  ExploitDB:  {(top500_full['exploitdb'] > 0).sum()} / 37 available in 2026")
    logger.info(f"  PoC GitHub: {(top500_full['poc_github'] > 0).sum()}")
    logger.info(f"  Mean EPSS:  {top500_full['epss'].mean():.4f} (overall 2026 mean: {scoreboard_2026['epss'].mean():.4f})")

    return df_metrics, predictions_df, top500_df


if __name__ == "__main__":
    run_pipeline()
