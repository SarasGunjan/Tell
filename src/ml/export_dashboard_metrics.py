
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT / "results"
DATA_DIR = ROOT / "data" / "processed"

# Load 2025 validation records
df = pd.read_parquet(
    DATA_DIR / "validation_2025.parquet"
)

# Load actual ML results
ml_metrics = pd.read_csv(
    RESULTS_DIR / "ml_metrics.csv"
)

# Define baseline ranking methods
baseline_rankings = {
    "EPSS": df.sort_values(
        ["epss", "cve_id"],
        ascending=[False, True]
    ),
    "Public Code + EPSS": df.assign(
        public_code=df[
            ["exploitdb", "metasploit",
             "nuclei", "poc_github"]
        ].max(axis=1)
    ).sort_values(
        ["public_code", "epss", "cve_id"],
        ascending=[False, False, True]
    )
}

# Calculate baseline metrics from actual records
rows = []

for name, ranked in baseline_rankings.items():
    row = {"model": name}

    for k in [100, 250, 500]:
        row[f"hits_{k}"] = int(
            ranked.head(k)["target"].sum()
        )

    row["average_precision"] = None
    rows.append(row)

# Combine baselines with trained ML metrics
metrics = pd.concat(
    [pd.DataFrame(rows), ml_metrics],
    ignore_index=True
)

# Save full model comparison
metrics.to_csv(
    RESULTS_DIR / "model_metrics.csv",
    index=False
)

# Create patch-budget data for Plotly
budget_rows = []

for _, row in metrics.iterrows():
    for budget in [100, 250, 500]:
        budget_rows.append({
            "model": row["model"],
            "budget": budget,
            "hits": int(row[f"hits_{budget}"])
        })

patch_budget = pd.DataFrame(budget_rows)

patch_budget.to_csv(
    RESULTS_DIR / "patch_budget.csv",
    index=False
)

print("\n--- MODEL METRICS ---")
print(metrics.to_string(index=False))

print("\n--- PATCH BUDGET ---")
print(patch_budget.to_string(index=False))

print("\nDashboard files exported successfully!")
