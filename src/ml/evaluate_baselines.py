
from pathlib import Path
import pandas as pd

# Locate our processed validation dataset
ROOT = Path(__file__).resolve().parents[2]

df = pd.read_parquet(
    ROOT / "data" / "processed" / "validation_2025.parquet"
)

# Rank vulnerabilities by highest EPSS score first
ranked = df.sort_values(
    by=["epss", "cve_id"],
    ascending=[False, True]
)

print("\n--- EPSS BASELINE RESULTS ---")

# Evaluate different investigation budgets
for budget in [100, 250, 500]:
    top = ranked.head(budget)

    hits = int(top["target"].sum())
    precision = hits / budget

    print(
        f"Top {budget}: {hits} KEV hits "
        f"| Precision: {precision:.2%}"
    )

print("\nTotal positive cases:", int(df["target"].sum()))


# STEP 37: Public Exploit + EPSS Baseline

exploit_columns = [
    "exploitdb",
    "metasploit",
    "nuclei",
    "poc_github"
]

# Check whether any public exploit indicator exists
df["has_public_exploit"] = (
    df[exploit_columns].max(axis=1)
)

# Rank public exploit indicators first, then EPSS
exploit_ranked = df.sort_values(
    by=["has_public_exploit", "epss", "cve_id"],
    ascending=[False, False, True]
)

print("\n--- PUBLIC EXPLOIT + EPSS RESULTS ---")

for budget in [100, 250, 500]:
    top = exploit_ranked.head(budget)

    hits = int(top["target"].sum())
    precision = hits / budget

    print(
        f"Top {budget}: {hits} KEV hits "
        f"| Precision: {precision:.2%}"
    )
