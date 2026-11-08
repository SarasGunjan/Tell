
from pathlib import Path
import pandas as pd

# Locate the main project folder
ROOT = Path(__file__).resolve().parents[2]

# Load IBM's official 2026 scoreboard
df = pd.read_csv(
    ROOT / "data" / "scoreboard_2026.csv"
)

print("Total scoreboard CVEs:", len(df))

# Public code and detection indicators
exploit_columns = [
    "exploitdb",
    "metasploit",
    "nuclei",
    "poc_github"
]

# Follow the same preprocessing as our baseline
df["epss"] = df["epss"].fillna(0)

for column in exploit_columns:
    df[column] = df[column].fillna(0)

# Give priority to CVEs with public-code indicators
df["has_public_exploit"] = (
    df[exploit_columns].max(axis=1)
)

# Rank public-code indicators first, then EPSS
ranked = df.sort_values(
    by=["has_public_exploit", "epss", "cve_id"],
    ascending=[False, False, True]
)

# Select 500 highest-ranked vulnerabilities
top500 = ranked.head(500)[["cve_id"]]

# Validate IBM submission requirements
assert len(df) == 72670, "Unexpected scoreboard size"
assert df["cve_id"].is_unique, "Duplicate scoreboard CVEs"
assert len(top500) == 500, "Incorrect number of rows"
assert top500["cve_id"].is_unique, "Duplicate CVEs"
assert top500["cve_id"].notna().all(), "Missing CVE IDs"
assert top500["cve_id"].isin(df["cve_id"]).all(), "Invalid CVE IDs"

# Save official submission file
output_file = ROOT / "top500.csv"

top500.to_csv(output_file, index=False)

print("\nSUCCESS: top500.csv created!")
print("Total ranked CVEs:", len(top500))
print("Unique CVEs:", top500["cve_id"].nunique())
print("Columns:", top500.columns.tolist())
print("Saved to:", output_file)

print("\nFirst 10 ranked CVEs:")
print(top500.head(10).to_string(index=False))


# STEP 46: Export full vulnerability rankings

RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Create a separate table for the dashboard
predictions = ranked[
    [
        "cve_id",
        "published",
        "snapshot_month",
        "epss",
        "has_public_exploit",
        "exploitdb",
        "metasploit",
        "nuclei",
        "poc_github"
    ]
].copy()

# Add ranking position
predictions.insert(
    1,
    "rank",
    range(1, len(predictions) + 1)
)

# Our current ranking uses public-code priority,
# followed by EPSS. It does not produce a
# calibrated probability.
predictions["ranking_method"] = "public_code_then_epss"

# Save for the dashboard
output_path = RESULTS_DIR / "predictions.csv"

predictions.to_csv(
    output_path,
    index=False
)

print("\n--- DASHBOARD EXPORT ---")
print("Rows exported:", len(predictions))
print("Unique CVEs:", predictions["cve_id"].nunique())
print("Saved to:", output_path)
print("\nFirst 5 rankings:")
print(predictions.head().to_string(index=False))
