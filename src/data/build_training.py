
from pathlib import Path
import pandas as pd

# Locate our IBM data folder
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"

# Load only the columns we need from NVD
vulnerabilities = pd.read_csv(
    DATA_DIR / "vulnerabilities.csv",
    usecols=["cve_id", "published"]
)

# Load the 2024 monthly exploit signals
signals = pd.read_csv(
    DATA_DIR / "exploit_signals_2024.csv"
)

# Load KEV records and their addition dates
kev = pd.read_csv(
    DATA_DIR / "known_exploited.csv",
    usecols=["cve_id", "date_added"]
)

# Check the number of records loaded
print("Vulnerabilities:", len(vulnerabilities))
print("2024 signal records:", len(signals))
print("Known exploited:", len(kev))



# Convert publication dates from text to datetime
vulnerabilities["published"] = pd.to_datetime(
    vulnerabilities["published"],
    errors="coerce"
)

# Select vulnerabilities published Jan-Sep 2024
vulns_2024 = vulnerabilities[
    (vulnerabilities["published"] >= "2024-01-01") &
    (vulnerabilities["published"] < "2024-10-01")
].copy()

# Find the publication month
vulns_2024["snapshot_month"] = (
    vulns_2024["published"].dt.strftime("%Y-%m")
)

print("\n2024 vulnerabilities:", len(vulns_2024))

print("\nSample records:")
print(vulns_2024.head().to_string(index=False))


# Rename month so it matches our vulnerability dataset
signals = signals.rename(columns={
    "month": "snapshot_month"
})

# Select the historical signal columns
signal_columns = [
    "cve_id",
    "snapshot_month",
    "epss",
    "in_kev",
    "exploitdb",
    "metasploit",
    "nuclei",
    "poc_github"
]

# Join using CVE ID and snapshot month
training_2024 = vulns_2024.merge(
    signals[signal_columns],
    on=["cve_id", "snapshot_month"],
    how="left",
    validate="one_to_one"
)

print("\nRows after merging:", len(training_2024))

print("\nMissing historical EPSS values:")
print(training_2024["epss"].isna().sum())

print("\nSample merged data:")
print(training_2024.head().to_string(index=False))



# Convert KEV addition dates to datetime
kev["date_added"] = pd.to_datetime(
    kev["date_added"],
    errors="coerce"
)

# Add KEV dates to our historical dataset
training_2024 = training_2024.merge(
    kev,
    on="cve_id",
    how="left",
    validate="many_to_one"
)

# Determine the final day of each snapshot month
training_2024["snapshot_date"] = (
    pd.to_datetime(training_2024["snapshot_month"])
    + pd.offsets.MonthEnd(0)
)

# Flag vulnerabilities already in KEV at the snapshot
already_exploited = (
    training_2024["date_added"].notna()
    & (training_2024["date_added"] <= training_2024["snapshot_date"])
)

# Exclude vulnerabilities already known to be exploited
training_2024 = training_2024.loc[
    ~already_exploited
].copy()

# Create the target: added to KEV after the snapshot,
# but no later than December 31, 2024
training_2024["target"] = (
    (training_2024["date_added"] > training_2024["snapshot_date"])
    & (training_2024["date_added"] <= pd.Timestamp("2024-12-31"))
).astype(int)

print("\nFinal eligible training rows:", len(training_2024))
print("Positive examples:", training_2024["target"].sum())
print("Negative examples:", (training_2024["target"] == 0).sum())



# STEP 23: Check data quality

features = [
    "epss",
    "exploitdb",
    "metasploit",
    "nuclei",
    "poc_github"
]

print("\n--- DATA QUALITY REPORT ---")

# Missing values in model features
print("\nMissing feature values:")
print(training_2024[features].isna().sum())

# Check for duplicate vulnerabilities
print("\nDuplicate CVE IDs:")
print(training_2024["cve_id"].duplicated().sum())

# Compare snapshot KEV status with KEV addition dates
kev_disagreements = training_2024[
    (training_2024["in_kev"] == 1)
    & (
        training_2024["date_added"].isna()
        | (training_2024["date_added"]
           > training_2024["snapshot_date"])
    )
]

print("\nPotential KEV status disagreements:", len(kev_disagreements))


# STEP 24: Prepare model features

for feature in features:
    # Remember which values were originally missing
    training_2024[f"{feature}_missing"] = (
        training_2024[feature].isna().astype(int)
    )

    # Fill missing values for initial modeling
    training_2024[feature] = (
        training_2024[feature].fillna(0)
    )

print("\n--- AFTER PREPROCESSING ---")

print("Remaining missing feature values:")
print(training_2024[features].isna().sum())

print("\nMissing EPSS indicators:")
print(training_2024["epss_missing"].sum())


# STEP 25: Save processed data

OUTPUT_DIR = ROOT / "data" / "processed"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

output_file = OUTPUT_DIR / "training_2024.parquet"

training_2024.to_parquet(
    output_file,
    index=False
)

print("\nTraining dataset saved successfully!")
print("File:", output_file)

print("\nFinal dataset shape:")
print(training_2024.shape)

print("\nTarget distribution:")
print(training_2024["target"].value_counts())



# STEP 25: Save processed data

OUTPUT_DIR = ROOT / "data" / "processed"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

output_file = OUTPUT_DIR / "training_2024.parquet"

training_2024.to_parquet(
    output_file,
    index=False
)

print("\nTraining dataset saved successfully!")
print("File:", output_file)

print("\nFinal dataset shape:")
print(training_2024.shape)

print("\nTarget distribution:")
print(training_2024["target"].value_counts())

