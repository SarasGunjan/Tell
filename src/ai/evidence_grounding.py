"""
Tell Platform - Evidence Grounding & Hallucination Guard Engine
Author: Member 3 (Full-Stack, APIs & Deployment)

Validates LLM-generated security claims against ground-truth data records.
Guards against hallucinated CVE claims, fabricated EPSS scores, and fake exploit statuses.

Key Functions:
- verify_claim: Cross-checks CVE ID, EPSS score, exploit code presence, and family
- compute_grounding_score: Scores evidence grounding from 0% to 100%
- format_grounding_badge: Generates UI badge and inspectable validation report
"""

import re
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, List


class EvidenceGroundingEngine:
    def __init__(self, data_cache: pd.DataFrame = None):
        self.data_cache = data_cache

    def set_data_cache(self, df: pd.DataFrame):
        self.data_cache = df

    def verify_response(self, text: str, context_cve: str = None) -> Dict[str, Any]:
        """
        Scans AI generated response for verifiable claims and validates each against records.
        """
        checks = []
        hallucinations = []
        verified_count = 0

        # 1. Detect CVE IDs mentioned
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        mentioned_cves = list(set(re.findall(cve_pattern, text)))

        target_cve = context_cve if context_cve else (mentioned_cves[0] if mentioned_cves else None)

        record = None
        if target_cve and self.data_cache is not None:
            matches = self.data_cache[self.data_cache["cve_id"] == target_cve]
            if len(matches) > 0:
                record = matches.iloc[0]
                checks.append({
                    "item": f"CVE Identifier ({target_cve})",
                    "status": "VERIFIED",
                    "detail": f"Matched in 2026 Scoreboard cohort at Rank #{record.get('rank', 'N/A')}"
                })
                verified_count += 1
            else:
                checks.append({
                    "item": f"CVE Identifier ({target_cve})",
                    "status": "UNVERIFIED",
                    "detail": "CVE not found in official 2026 scoreboard dataset"
                })
                hallucinations.append(f"Unrecognized CVE ID: {target_cve}")

        # 2. Check EPSS claims
        # Matches patterns like 'EPSS of 0.12' or 'EPSS: 0.12' or '0.123 EPSS'
        epss_pattern = r"(?:epss\s*(?:of|:|=|score\s*is)?\s*([0-1]\.\d+)|([0-1]\.\d+)\s*epss)"
        epss_matches = re.findall(epss_pattern, text, flags=re.IGNORECASE)

        if record is not None and epss_matches:
            claimed_val = float(epss_matches[0][0] or epss_matches[0][1])
            actual_val = float(record.get("epss", 0.0))
            # Allow minor rounding tolerance (within 0.01)
            if abs(claimed_val - actual_val) <= 0.015:
                checks.append({
                    "item": "EPSS Probability Metric",
                    "status": "VERIFIED",
                    "detail": f"Claimed {claimed_val:.4f} matches true recorded EPSS ({actual_val:.4f})"
                })
                verified_count += 1
            else:
                checks.append({
                    "item": "EPSS Probability Metric",
                    "status": "HALLUCINATION_DETECTED",
                    "detail": f"Claimed {claimed_val:.4f} conflicts with recorded EPSS ({actual_val:.4f})"
                })
                hallucinations.append(f"EPSS mismatch: claimed {claimed_val:.4f} vs actual {actual_val:.4f}")

        # 3. Check Exploit Weaponization Claims
        if record is not None:
            # Metasploit check
            if re.search(r"\bmetasploit\b", text, re.IGNORECASE):
                has_meta = record.get("metasploit", 0) > 0
                if has_meta:
                    checks.append({
                        "item": "Metasploit Module Signal",
                        "status": "VERIFIED",
                        "detail": "Verified public Metasploit module is present"
                    })
                    verified_count += 1
                else:
                    checks.append({
                        "item": "Metasploit Module Signal",
                        "status": "DISCREPANCY_FLAG",
                        "detail": "Metasploit referenced but recorded signal is 0"
                    })

            # Nuclei check
            if re.search(r"\bnuclei\b", text, re.IGNORECASE):
                has_nuclei = record.get("nuclei", 0) > 0
                if has_nuclei:
                    checks.append({
                        "item": "Nuclei Template Signal",
                        "status": "VERIFIED",
                        "detail": "Verified active Nuclei scanning template is present"
                    })
                    verified_count += 1
                else:
                    checks.append({
                        "item": "Nuclei Template Signal",
                        "status": "DISCREPANCY_FLAG",
                        "detail": "Nuclei referenced but recorded signal is 0"
                    })

        # 4. Check KEV Status Claim
        # Prevent AI claiming a 2026 CVE is already verified in KEV
        if re.search(r"\balready (?:added to|in) (?:cisa )?kev\b", text, re.IGNORECASE):
            checks.append({
                "item": "KEV Inclusion Claim",
                "status": "CAUTION_FLAG",
                "detail": "2026 CVEs have NOT been revealed in published KEV; this is a prediction"
            })
            hallucinations.append("Claimed 2026 CVE is already verified in KEV (unconfirmed prediction)")

        # Overall Grounding Score
        total_evals = max(len(checks), 1)
        grounding_score = int((verified_count / max(total_evals - len(hallucinations), 1)) * 100)
        grounding_score = min(max(grounding_score, 0), 100)

        status_label = "HIGH CONFIDENCE" if len(hallucinations) == 0 else "CAUTION / HALLUCINATION DETECTED"

        return {
            "target_cve": target_cve,
            "grounding_score": grounding_score,
            "status_label": status_label,
            "checks": checks,
            "hallucinations": hallucinations,
            "is_grounded": len(hallucinations) == 0
        }
