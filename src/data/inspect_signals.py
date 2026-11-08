
from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).resolve().parents[2] / "data"

files = [
    "exploit_signals_2024.csv",
    "exploit_signals_2025.csv",
    "known_exploited.csv",
    "scoreboard_2026.csv"
]

for filename in files:
    print(f"\n{'=' * 50}")
    print(f"DATASET: {filename}")

    # Read a small sample first
    df = pd.read_csv(DATA_DIR / filename, nrows=5)

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nFirst 5 rows:")
    print(df.to_string(index=False))
