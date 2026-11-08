
from pathlib import Path

import pandas as pd

# Find the main ThreatRank project folder
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Locate the IBM datasets
DATA_DIR = PROJECT_ROOT / "data"

print("ThreatRank Data Inspection")
print("--------------------------")

# Check which CSV files are available
csv_files = sorted(DATA_DIR.glob("*.csv"))

print(f"CSV files found: {len(csv_files)}")

for file in csv_files:
    print(file.name)





# Read only the first 5 rows to inspect the dataset
file_path = DATA_DIR / "vulnerabilities.csv"

df = pd.read_csv(file_path, nrows=5)

# Display the first 5 records
print("\nFirst 5 vulnerability records:")
print(df.to_string(index=False))

# Display all column names
print("\nColumn names:")
for column in df.columns:
    print(column)

# Display the number of columns
print("\nTotal columns:", len(df.columns))


# Load the complete vulnerabilities dataset
df_full = pd.read_csv(file_path, low_memory=False)

# Check the number of rows and columns
print("\nDataset shape:")
print(df_full.shape)

# Check the data type of each column
print("\nColumn data types:")
print(df_full.dtypes.to_string())

# Count missing values in each column
print("\nMissing values per column:")
print(df_full.isnull().sum().to_string())

# Check duplicate CVE IDs
print("\nDuplicate CVE IDs:")
print(df_full["cve_id"].duplicated().sum())
