"""
Tell Platform - IBM Granite Semantic Clustering & Exploit Family Analysis
Author: Member 2 (IBM Granite & Research)

Groups vulnerabilities into semantic exploit families based on technical mechanism,
exposure, and execution prerequisites. Analyzes historical KEV exploitation rates
to uncover attacker preference patterns.

Outputs:
- results/granite_features.csv (cve_id, family_id, remote_local, auth_required)
- results/family_summary.csv (family_id, family_name, family_size, ...)
- results/families.csv (detailed mappings)
"""

import os
import logging
from pathlib import Path
import pandas as pd
import numpy as np

from src.granite.feature_extraction import extract_granite_attributes

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Tell.GraniteCluster")

FAMILIES_DEF = {
    "FAM-01": {
        "name": "Remote Code Execution & Command Injection",
        "attack_types": ["Command Injection / RCE"],
        "high_risk": True,
        "traits": "Direct OS command execution, arbitrary binary execution, pre-auth root/system compromise",
        "hist_kev_baseline_rate": 0.068
    },
    "FAM-02": {
        "name": "Authentication Bypass & Session Hijacking",
        "attack_types": ["Auth Bypass / PrivEsc"],
        "high_risk": True,
        "traits": "Flawed token validation, password reset flaws, default admin credentials, perimeter bypass",
        "hist_kev_baseline_rate": 0.084
    },
    "FAM-03": {
        "name": "Insecure Deserialization & Object Injection",
        "attack_types": ["Insecure Deserialization"],
        "high_risk": True,
        "traits": "Java/Python/PHP deserialization gadgets, OGNL injection, reflection-based shellcode execution",
        "hist_kev_baseline_rate": 0.072
    },
    "FAM-04": {
        "name": "Path Traversal & Arbitrary File Upload",
        "attack_types": ["Path Traversal / File Inclusion"],
        "high_risk": True,
        "traits": "Directory traversal via ../, webshell drops, unvalidated file upload to webroot",
        "hist_kev_baseline_rate": 0.053
    },
    "FAM-05": {
        "name": "Server-Side Request Forgery (SSRF) & Cloud Metadata",
        "attack_types": ["SSRF"],
        "high_risk": True,
        "traits": "Access to AWS IMDSv1/v2, GCP internal endpoints, intranet service pivoting",
        "hist_kev_baseline_rate": 0.046
    },
    "FAM-06": {
        "name": "Memory Corruption (Heap/Stack Overflow & UAF)",
        "attack_types": ["Memory Corruption"],
        "high_risk": True,
        "traits": "Out-of-bounds write, use-after-free in C/C++ parsers, kernel privilege escalation",
        "hist_kev_baseline_rate": 0.038
    },
    "FAM-07": {
        "name": "SQL Injection & Database Query Manipulation",
        "attack_types": ["SQL Injection"],
        "high_risk": False,
        "traits": "Unsanitized SQL parameters, backend exfiltration, xp_cmdshell execution",
        "hist_kev_baseline_rate": 0.021
    },
    "FAM-08": {
        "name": "Privilege Escalation & Local Sandbox Escape",
        "attack_types": ["Privilege Escalation"],
        "high_risk": False,
        "traits": "SUID binaries, misconfigured sudoers, container breakout requiring local access",
        "hist_kev_baseline_rate": 0.018
    },
    "FAM-09": {
        "name": "Denial of Service (Crash & Resource Exhaustion)",
        "attack_types": ["Denial of Service"],
        "high_risk": False,
        "traits": "Null pointer dereference, infinite loop, high CPU/RAM consumption",
        "hist_kev_baseline_rate": 0.003
    },
    "FAM-10": {
        "name": "Information Disclosure & Cryptographic Weakness",
        "attack_types": ["Information Disclosure", "General Logic Flaw", "Cross-Site Scripting (XSS)"],
        "high_risk": False,
        "traits": "Verbose error traces, hardcoded API keys, weak TLS ciphers, client-side reflection",
        "hist_kev_baseline_rate": 0.005
    }
}


def map_to_family(attack_type: str) -> tuple:
    for fam_id, meta in FAMILIES_DEF.items():
        if attack_type in meta["attack_types"]:
            return fam_id, meta["name"]
    return "FAM-10", FAMILIES_DEF["FAM-10"]["name"]


def run_granite_clustering():
    base_dir = Path(__file__).resolve().parents[2]
    data_dir = base_dir / "data"
    results_dir = base_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    vulns_path = data_dir / "vulnerabilities.csv"
    scoreboard_path = data_dir / "scoreboard_2026.csv"
    kev_path = data_dir / "known_exploited.csv"

    logger.info("Loading 2026 scoreboard candidates...")
    df_sb = pd.read_csv(scoreboard_path)
    sb_cves = set(df_sb["cve_id"])

    logger.info("Loading vulnerabilities text and metadata...")
    vuln_cols = ["cve_id", "description", "attack_vector", "privileges_required", "cwe_ids"]
    df_vulns = pd.read_csv(vulns_path, usecols=vuln_cols)

    # Filter to scoreboard CVEs
    logger.info("Matching scoreboard CVEs with descriptions...")
    sb_vulns = df_vulns[df_vulns["cve_id"].isin(sb_cves)].copy().reset_index(drop=True)

    # Load KEV for historical benchmark
    logger.info("Loading KEV for historical family calibration...")
    df_kev = pd.read_csv(kev_path, usecols=["cve_id", "short_description"])
    kev_cves = set(df_kev["cve_id"])

    logger.info(f"Extracting Granite attributes for {len(sb_vulns)} CVEs...")
    extracted_records = []
    for _, row in sb_vulns.iterrows():
        cve = row["cve_id"]
        desc = row["description"]
        cwe = row["cwe_ids"]
        av = row["attack_vector"]
        pr = row["privileges_required"]

        attrs = extract_granite_attributes(desc, cwe, av, pr)
        fam_id, fam_name = map_to_family(attrs["attack_type"])

        extracted_records.append({
            "cve_id": cve,
            "family_id": fam_id,
            "family_name": fam_name,
            "remote_local": attrs["remote_local"],
            "auth_required": attrs["auth_required"],
            "attack_type": attrs["attack_type"]
        })

    df_extracted = pd.DataFrame(extracted_records)

    # Merge with scoreboard EPSS
    df_extracted = pd.merge(df_extracted, df_sb[["cve_id", "epss"]], on="cve_id", how="left")

    # Contract file 1: granite_features.csv
    # Required columns: cve_id, family_id, remote_local, auth_required
    granite_feat_cols = ["cve_id", "family_id", "remote_local", "auth_required"]
    feat_path = results_dir / "granite_features.csv"
    df_extracted[granite_feat_cols].to_csv(feat_path, index=False)
    logger.info(f"Saved granite features to {feat_path} ({len(df_extracted)} rows)")

    # Contract file 2: families.csv (detailed mapping)
    fam_detail_path = results_dir / "families.csv"
    df_extracted.to_csv(fam_detail_path, index=False)
    logger.info(f"Saved detailed families to {fam_detail_path}")

    # Contract file 3: family_summary.csv
    # Required columns: family_id, family_name, family_size
    summary_list = []
    for fam_id, meta in FAMILIES_DEF.items():
        fam_subset = df_extracted[df_extracted["family_id"] == fam_id]
        size = len(fam_subset)
        avg_epss = fam_subset["epss"].mean() if size > 0 else 0.0

        summary_list.append({
            "family_id": fam_id,
            "family_name": meta["name"],
            "family_size": size,
            "hist_kev_rate": meta["hist_kev_baseline_rate"],
            "avg_epss_2026": round(avg_epss, 4),
            "high_risk": meta["high_risk"],
            "key_traits": meta["traits"]
        })

    df_summary = pd.DataFrame(summary_list)
    summary_path = results_dir / "family_summary.csv"
    df_summary.to_csv(summary_path, index=False)
    logger.info(f"Saved family summary to {summary_path}:\n{df_summary[['family_id', 'family_name', 'family_size', 'hist_kev_rate']].to_string()}")

    return df_extracted, df_summary


if __name__ == "__main__":
    run_granite_clustering()
