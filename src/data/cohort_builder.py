"""
Tell Platform - Cohort Builder & Time-Safe Data Ingestion
Author: Member 1 (Data Science & Prediction)

Constructs time-safe historical training (2024) and held-out validation (2025) cohorts
strictly adhering to the datathon's zero-leakage boundaries.

Leakage Controls:
- Snapshots are taken at the month of CVE publication.
- CVEs already in KEV at or prior to the publication snapshot are excluded.
- Target is defined strictly as: CISA date_added > snapshot AND date_added <= Dec 31 of cohort year.
- Only time-safe signals available at the snapshot month are retained for modeling:
  [epss, exploitdb, metasploit, nuclei, poc_github].
"""

import os
import logging
import pandas as pd
import numpy as np
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Tell.CohortBuilder")


class CohortBuilder:
    def __init__(self, data_dir: str = None):
        if data_dir is None:
            # Default to scratch/tell/data
            base_dir = Path(__file__).resolve().parents[2]
            self.data_dir = base_dir / "data"
        else:
            self.data_dir = Path(data_dir)

        self.vulns_path = self.data_dir / "vulnerabilities.csv"
        self.kev_path = self.data_dir / "known_exploited.csv"
        self.signals_2024_path = self.data_dir / "exploit_signals_2024.csv"
        self.signals_2025_path = self.data_dir / "exploit_signals_2025.csv"
        self.scoreboard_2026_path = self.data_dir / "scoreboard_2026.csv"
        self.weakness_types_path = self.data_dir / "weakness_types.csv"

    def load_kev_lookup(self) -> dict:
        """Loads CISA KEV date_added mapping."""
        logger.info(f"Loading KEV lookup from {self.kev_path}...")
        df_kev = pd.read_csv(self.kev_path, usecols=["cve_id", "date_added"])
        df_kev["date_added_dt"] = pd.to_datetime(df_kev["date_added"], errors="coerce")
        return dict(zip(df_kev["cve_id"], df_kev["date_added_dt"]))

    def load_vulnerabilities_metadata(self) -> pd.DataFrame:
        """Loads publication dates and CVSS scores from vulnerabilities.csv."""
        logger.info(f"Loading vulnerabilities metadata from {self.vulns_path}...")
        cols = ["cve_id", "published", "cvss3_score", "attack_vector", "cwe_ids"]
        vulns = pd.read_csv(self.vulns_path, usecols=cols)
        vulns["pub_dt"] = pd.to_datetime(vulns["published"], errors="coerce")
        vulns["pub_month"] = vulns["pub_dt"].dt.strftime("%Y-%m")
        return vulns

    def build_historical_cohort(self, year: int, vulns_df: pd.DataFrame, kev_dict: dict) -> pd.DataFrame:
        """
        Builds a time-safe historical cohort for Jan-Sep of the given year.
        
        Rules:
        - Published between {year}-01-01 and {year}-09-30
        - Snapshot month = pub_month (YYYY-MM)
        - Exclude CVEs already in KEV by snapshot month
        - Target = 1 if KEV date_added > snapshot AND date_added <= {year}-12-31, else 0
        """
        logger.info(f"Building historical cohort for Jan-Sep {year}...")
        start_date = f"{year}-01-01"
        end_date = f"{year}-09-30"
        cutoff_date = f"{year}-12-31"

        # 1. Filter publications in Jan-Sep of year
        cohort = vulns_df[
            (vulns_df["pub_dt"] >= start_date) & (vulns_df["pub_dt"] <= end_date)
        ].copy().reset_index(drop=True)
        logger.info(f"Total CVEs published in Jan-Sep {year}: {len(cohort)}")

        # 2. Load matching exploit signals file
        signals_path = self.signals_2024_path if year == 2024 else self.signals_2025_path
        logger.info(f"Loading monthly exploit signals from {signals_path}...")
        signals_df = pd.read_csv(signals_path)

        # 3. Join on cve_id and snapshot month
        merged = pd.merge(
            cohort,
            signals_df,
            left_on=["cve_id", "pub_month"],
            right_on=["cve_id", "month"],
            how="left"
        )

        # 4. Filter already in KEV at snapshot
        merged["snapshot_dt"] = pd.to_datetime(merged["pub_month"] + "-01")
        merged["kev_date"] = merged["cve_id"].map(kev_dict)

        # Prior KEV exclusion
        is_prior_kev = (merged["in_kev"] == 1) | (merged["kev_date"] < merged["snapshot_dt"])
        clean_cohort = merged[~is_prior_kev].copy().reset_index(drop=True)
        logger.info(f"Candidates remaining after prior-KEV exclusion: {len(clean_cohort)}")

        # 5. Impute missing exploit signals safely with zeros
        signal_cols = ["epss", "exploitdb", "metasploit", "nuclei", "poc_github"]
        for col in signal_cols:
            clean_cohort[col] = clean_cohort[col].fillna(0.0)

        # 6. Assign target
        clean_cohort["target"] = (
            (clean_cohort["kev_date"] >= clean_cohort["snapshot_dt"]) &
            (clean_cohort["kev_date"] <= cutoff_date)
        ).astype(int)

        logger.info(f"Year {year} cohort ready: {len(clean_cohort)} rows, {clean_cohort['target'].sum()} positive KEV labels.")
        return clean_cohort

    def get_datasets(self):
        """Loads and prepares 2024 train, 2025 validation, and 2026 scoreboard datasets."""
        kev_dict = self.load_kev_lookup()
        vulns_df = self.load_vulnerabilities_metadata()

        train_2024 = self.build_historical_cohort(2024, vulns_df, kev_dict)
        val_2025 = self.build_historical_cohort(2025, vulns_df, kev_dict)

        logger.info(f"Loading 2026 scoreboard from {self.scoreboard_2026_path}...")
        scoreboard_2026 = pd.read_csv(self.scoreboard_2026_path)
        logger.info(f"2026 Scoreboard candidates loaded: {len(scoreboard_2026)}")

        # Ensure signal cols are clean in 2026
        signal_cols = ["epss", "exploitdb", "metasploit", "nuclei", "poc_github"]
        for col in signal_cols:
            scoreboard_2026[col] = scoreboard_2026[col].fillna(0.0)

        return train_2024, val_2025, scoreboard_2026


if __name__ == "__main__":
    builder = CohortBuilder()
    train_df, val_df, test_df = builder.get_datasets()
    print("Train 2024 shape:", train_df.shape, "Positives:", train_df["target"].sum())
    print("Val 2025 shape:", val_df.shape, "Positives:", val_df["target"].sum())
    print("Test 2026 shape:", test_df.shape)
