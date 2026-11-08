
from pathlib import Path
import pandas as pd

# Find the ThreatRank project folder
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"

# Load vulnerability publication dates
vulnerabilities = pd.read_csv(
    DATA_DIR / "vulnerabilities.csv",
    usecols=["cve_id", "published"]
)

# Load 2025 historical exploit signals
signals = pd.read_csv(
    DATA_DIR / "exploit_signals_2025.csv"
)

# Load CISA KEV records
kev = pd.read_csv(
    DATA_DIR / "known_exploited.csv",
    usecols=["cve_id", "date_added"]
)

print("Vulnerabilities:", len(vulnerabilities))
print("2025 signals:", len(signals))
print("KEV records:", len(kev))


# Convert publication dates to datetime
vulnerabilities["published"] = pd.to_datetime(
    vulnerabilities["published"],
    errors="coerce"
)

# Select January–September 2025 vulnerabilities
vulns_2025 = vulnerabilities[
    (vulnerabilities["published"] >= "2025-01-01")
    & (vulnerabilities["published"] < "2025-10-01")
].copy()

# Identify the snapshot month
vulns_2025["snapshot_month"] = (
    vulns_2025["published"].dt.strftime("%Y-%m")
)

print("\n2025 published vulnerabilities:", len(vulns_2025))

# Make the column name consistent
signals = signals.rename(columns={
    "month": "snapshot_month"
})

# Merge using CVE ID and snapshot month
validation_2025 = vulns_2025.merge(
    signals,
    on=["cve_id", "snapshot_month"],
    how="left",
    validate="one_to_one"
)

print("\nRows after merging:", len(validation_2025))

print("\nMissing monthly signal records:")
print(validation_2025["in_kev"].isna().sum())

print("\nMissing EPSS scores:")
print(validation_2025["epss"].isna().sum())

# Check which months have missing signal records
missing_by_month = (
    validation_2025[
        validation_2025["in_kev"].isna()
    ]
    .groupby("snapshot_month")
    .size()
)

print("\nMissing signal records by month:")
print(missing_by_month.to_string())


# Convert KEV dates into datetime
kev["date_added"] = pd.to_datetime(
    kev["date_added"],
    errors="coerce"
)

# Add KEV dates to validation records
validation_2025 = validation_2025.merge(
    kev,
    on="cve_id",
    how="left",
    validate="many_to_one"
)

# Calculate the last day of each prediction month
validation_2025["snapshot_date"] = (
    pd.to_datetime(validation_2025["snapshot_month"])
    + pd.offsets.MonthEnd(0)
)

# Identify CVEs already in KEV at prediction time
already_kev = (
    validation_2025["date_added"].notna()
    & (validation_2025["date_added"]
       <= validation_2025["snapshot_date"])
)

# Remove already-known exploited vulnerabilities
validation_2025 = validation_2025.loc[
    ~already_kev
].copy()

# Label future KEV additions during 2025
validation_2025["target"] = (
    (validation_2025["date_added"]
     > validation_2025["snapshot_date"])
    & (validation_2025["date_added"]
       <= pd.Timestamp("2025-12-31"))
).astype(int)

print("\n--- 2025 VALIDATION RESULTS ---")
print("Eligible CVEs:", len(validation_2025))
print("Positive labels:", validation_2025["target"].sum())
print("Negative labels:", (validation_2025["target"] == 0).sum())

# Check unique CVE identifiers
print("Duplicate CVE IDs:",
      validation_2025["cve_id"].duplicated().sum())

# Check disagreements in recorded KEV status
disagreements = validation_2025[
    (validation_2025["in_kev"] == 1)
    & (
        validation_2025["date_added"].isna()
        | (validation_2025["date_added"]
           > validation_2025["snapshot_date"])
    )
]

print("Potential KEV disagreements:", len(disagreements))


# STEP 32: Inspect KEV disagreement

print("\n--- KEV DISAGREEMENT DETAILS ---")

print(
    disagreements[
        [
            "cve_id",
            "published",
            "snapshot_month",
            "snapshot_date",
            "in_kev",
            "date_added"
        ]
    ].to_string(index=False)
)



# STEP 33: Remove inconsistent KEV records

# Record the number before filtering
before = len(validation_2025)

# Exclude CVEs identified as KEV disagreements
validation_2025 = validation_2025[
    ~validation_2025["cve_id"].isin(
        disagreements["cve_id"]
    )
].copy()

print("\n--- AFTER KEV CONSISTENCY FILTER ---")
print("Rows removed:", before - len(validation_2025))
print("Final validation rows:", len(validation_2025))
print("Positive labels:", validation_2025["target"].sum())
print("Negative labels:", (validation_2025["target"] == 0).sum())



# STEP 34: Prepare 2025 validation features

features = [
    "epss",
    "exploitdb",
    "metasploit",
    "nuclei",
    "poc_github"
]

# Handle missing values consistently with 2024
for feature in features:

    # Record whether the original value was missing
    validation_2025[f"{feature}_missing"] = (
        validation_2025[feature].isna().astype(int)
    )

    # Fill missing values with zero for initial modeling
    validation_2025[feature] = (
        validation_2025[feature].fillna(0)
    )

# Create output folder
OUTPUT_DIR = ROOT / "data" / "processed"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Save dataset
output_file = OUTPUT_DIR / "validation_2025.parquet"

validation_2025.to_parquet(
    output_file,
    index=False
)

# Verify results
print("\n--- FINAL VALIDATION CHECK ---")
print("Rows:", len(validation_2025))
print("Positive labels:", validation_2025["target"].sum())
print("Missing model features:",
      validation_2025[features].isna().sum().sum())
print("Duplicate CVEs:",
      validation_2025["cve_id"].duplicated().sum())
print("Saved to:", output_file)
