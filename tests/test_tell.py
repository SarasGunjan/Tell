"""
Tell Platform - Comprehensive Test Suite
Validates all inter-team file contracts, submission formats, and grounding logic.
"""

import os
import sys
import unittest
from pathlib import Path
import pandas as pd

# Add root directory to sys.path
root_dir = Path(__file__).resolve().parents[1]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from src.ai.evidence_grounding import EvidenceGroundingEngine


class TestTellSubmissionAndContracts(unittest.TestCase):
    def setUp(self):
        self.results_dir = root_dir / "results"
        self.data_dir = root_dir / "data"

    def test_top500_format_and_validity(self):
        """Validates official top500.csv submission requirements."""
        top500_path = self.results_dir / "top500.csv"
        self.assertTrue(top500_path.exists(), "results/top500.csv does not exist!")

        df_top500 = pd.read_csv(top500_path)
        
        # 1. Column requirement
        self.assertEqual(list(df_top500.columns), ["cve_id"], "top500.csv must have exactly one column: 'cve_id'")

        # 2. Row count requirement
        self.assertEqual(len(df_top500), 500, f"Expected exactly 500 rows, found {len(df_top500)}")

        # 3. No duplicates
        self.assertEqual(df_top500["cve_id"].nunique(), 500, "top500.csv contains duplicate CVE IDs!")

        # 4. Valid scoreboard candidates
        df_sb = pd.read_csv(self.data_dir / "scoreboard_2026.csv", usecols=["cve_id"])
        valid_cves = set(df_sb["cve_id"])
        top500_cves = set(df_top500["cve_id"])
        self.assertTrue(top500_cves.issubset(valid_cves), "top500.csv contains CVE IDs not in the 2026 scoreboard!")

    def test_predictions_contract(self):
        """Validates predictions.csv inter-team contract."""
        pred_path = self.results_dir / "predictions.csv"
        self.assertTrue(pred_path.exists(), "results/predictions.csv does not exist!")

        df_pred = pd.read_csv(pred_path)
        required_cols = ["cve_id", "rank", "prediction_score", "epss"]
        for col in required_cols:
            self.assertIn(col, df_pred.columns, f"Required column '{col}' missing from predictions.csv")

        self.assertEqual(len(df_pred), 72670, f"Expected 72670 rows in predictions.csv, got {len(df_pred)}")
        self.assertEqual(df_pred["rank"].iloc[0], 1, "Top rank should be 1")
        self.assertEqual(df_pred["rank"].iloc[-1], 72670, "Final rank should be 72670")

    def test_metrics_contract(self):
        """Validates metrics.csv inter-team contract."""
        metrics_path = self.results_dir / "metrics.csv"
        self.assertTrue(metrics_path.exists(), "results/metrics.csv does not exist!")

        df_metrics = pd.read_csv(metrics_path)
        required_cols = ["model", "hits_100", "hits_250", "hits_500"]
        for col in required_cols:
            self.assertIn(col, df_metrics.columns, f"Required column '{col}' missing from metrics.csv")

        for _, row in df_metrics.iterrows():
            self.assertLessEqual(row["hits_100"], row["hits_250"], f"Hits@100 > Hits@250 for {row['model']}")
            self.assertLessEqual(row["hits_250"], row["hits_500"], f"Hits@250 > Hits@500 for {row['model']}")

    def test_granite_features_contract(self):
        """Validates granite_features.csv inter-team contract."""
        feat_path = self.results_dir / "granite_features.csv"
        self.assertTrue(feat_path.exists(), "results/granite_features.csv does not exist!")

        df_feat = pd.read_csv(feat_path)
        required_cols = ["cve_id", "family_id", "remote_local", "auth_required"]
        for col in required_cols:
            self.assertIn(col, df_feat.columns, f"Required column '{col}' missing from granite_features.csv")

        self.assertEqual(len(df_feat), 72670, f"Expected 72670 rows, got {len(df_feat)}")
        self.assertTrue(set(df_feat["remote_local"]).issubset({"REMOTE", "LOCAL", "UNKNOWN"}))
        self.assertTrue(set(df_feat["auth_required"]).issubset({"NONE", "REQUIRED", "UNKNOWN"}))

    def test_family_summary_contract(self):
        """Validates family_summary.csv inter-team contract."""
        summary_path = self.results_dir / "family_summary.csv"
        self.assertTrue(summary_path.exists(), "results/family_summary.csv does not exist!")

        df_sum = pd.read_csv(summary_path)
        required_cols = ["family_id", "family_name", "family_size"]
        for col in required_cols:
            self.assertIn(col, df_sum.columns, f"Required column '{col}' missing from family_summary.csv")

        self.assertEqual(df_sum["family_size"].sum(), 72670, "Family sizes do not sum to 72,670!")

    def test_evidence_grounding_engine(self):
        """Tests hallucination detection and grounding scoring."""
        sample_df = pd.DataFrame([{
            "cve_id": "CVE-2026-10002",
            "rank": 10,
            "epss": 0.4500,
            "metasploit": 1,
            "nuclei": 1,
            "exploitdb": 0,
            "poc_github": 1
        }])
        engine = EvidenceGroundingEngine(data_cache=sample_df)

        # 1. Grounded response test
        valid_text = "CVE-2026-10002 has an EPSS of 0.4500 with a Metasploit module and Nuclei template."
        res1 = engine.verify_response(valid_text, context_cve="CVE-2026-10002")
        self.assertTrue(res1["is_grounded"])
        self.assertGreaterEqual(res1["grounding_score"], 80)

        # 2. Hallucinated EPSS test
        hallucinated_text = "CVE-2026-10002 has an EPSS of 0.9999 and is already in CISA KEV."
        res2 = engine.verify_response(hallucinated_text, context_cve="CVE-2026-10002")
        self.assertFalse(res2["is_grounded"])
        self.assertGreaterEqual(len(res2["hallucinations"]), 1)


if __name__ == "__main__":
    unittest.main()
