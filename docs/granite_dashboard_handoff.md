# ThreatRank Member 3 Dashboard Handoff — IBM Granite Intelligence & Research

This document provides Member 3 (Full-Stack & Streamlit Dashboard) with exact file locations, column schemas, join keys, historical vs. benchmark semantics, metric display rules, and recommended visualizations for integrating Member 2's IBM Granite outputs into the ThreatRank dashboard.

---

## 1. File Locations & Cohort Distinction

Member 2 exports two distinct sets of deliverables. **Never mix or concatenate these two directories without filtering by cohort**, as they represent different time windows and sampling regimes:

| Cohort | Directory | CVE Count | Time Window & Purpose |
| :--- | :--- | :---: | :--- |
| **1. Historical Research Cohort (2024–2025)** | [`outputs/granite/`](file:///c:/Users/johnj/OneDrive/Documentos/Datathon%202026/ThreatRank/outputs/granite) | **2,500** (`317` KEV + `2,183` non-KEV) | Case-control enriched 2024–2025 cohort used to fit the 10 IBM Granite semantic families, evaluate CWE fragmentation, compare baselines, and compute historical KEV exploitation rates. |
| **2. 2026 Target Benchmark Cohort** | [`outputs/granite/benchmark_2026/`](file:///c:/Users/johnj/OneDrive/Documentos/Datathon%202026/ThreatRank/outputs/granite/benchmark_2026) | **72,670** (`0` KEV labels; future benchmark) | Full 2026 competition scoreboard (`scoreboard_2026.csv`) assigned to the **frozen** historical 10-family K-Means centroids (`fitted_kmeans_k10_seed42.pkl`) without refitting. Join this table with Member 1's `predictions.csv` and `top500.csv`. |

### Complete File Manifest

- **Historical Research Files (`outputs/granite/`)**:
  - `outputs/granite/granite_features.csv` (`2,500` rows, `10` columns)
  - `outputs/granite/families.csv` (`2,500` rows, `2` columns)
  - `outputs/granite/family_summary.csv` (`10` rows, `13` columns)
  - `outputs/granite/cwe_semantic_analysis.csv` (`647` rows, `6` columns)
  - `outputs/granite/baseline_comparison.csv` (`5` rows, `12` columns)
  - `outputs/granite/temporal_validation_2024_2025.csv` (`10` rows, `9` columns)
- **2026 Benchmark Files (`outputs/granite/benchmark_2026/`)**:
  - `outputs/granite/benchmark_2026/granite_features.csv` (`72,670` rows, `10` columns)
  - `outputs/granite/benchmark_2026/families.csv` (`72,670` rows, `2` columns)
  - `outputs/granite/benchmark_2026/family_summary.csv` (`10` rows, `13` columns)

---

## 2. Exact Column Schemas

### 2.1 `granite_features.csv` (Historical: `2,500` rows | Benchmark: `72,670` rows)
Primary CVE-level feature table for Member 1 model integration and Member 3 Rankings/Explorer pages.

| Column | Type | Allowed / Example Values | Description |
| :--- | :--- | :--- | :--- |
| `cve_id` | `string` | `CVE-2026-0628`, `CVE-2024-21338` | Unique CVE identifier (**Primary Key**, 100% unique, 0 nulls). |
| `family_id` | `int` | `0` to `9` | Assigned IBM Granite semantic vulnerability family ID (**Foreign Key** to `family_summary.csv`). |
| `remote_local` | `string` | `remote`, `local`, `unknown` | Attack reachability extracted from CVSS `attack_vector` first, then high-precision text rules. |
| `auth_required` | `string` | `yes`, `no`, `unknown` | Privilege/authentication requirement (`no` = unauthenticated / `PR:NONE`; `yes` = authenticated). |
| `vulnerability_type` | `string` | `Remote Code Execution`, `Cross-Site Scripting (XSS)`, `Buffer & Memory Corruption`, `unknown` | Deterministic technical mechanism classification from description text. |
| `attack_surface` | `string` | `Web Application / Plugin`, `OS Kernel / Driver`, `Browser / Renderer Engine`, `Network Appliance / VPN / Firewall`, `API / Web Service`, `Database / Storage Engine`, `Enterprise / General Software` | Target software component / deployment surface inferred from description text. |
| `product_or_vendor` | `string` | `Linux Kernel`, `Google Chrome`, `Microsoft Windows`, `unknown` | Extracted product or vendor string when explicitly named in the description. |
| `extraction_method` | `string` | `structured_cvss+text_rules`, `text_rules_fallback` | Provenance flag indicating whether structured CVSSv3/v2 metadata was present (`structured_cvss+text_rules`) or missing (`text_rules_fallback`). |
| `extraction_confidence` | `float` | `0.50` to `0.95` | Confidence score (`0.95` when backed by structured CVSS + text match; `0.75` text rule; `0.50` unknown). |
| `evidence` | `string` | `structured_av=NETWORK; structured_pr=NONE; text_vtype=Remote Code Execution` | Human-readable audit trail showing why each attribute was assigned (ideal for CVE detail tooltips). |

### 2.2 `families.csv` (Historical: `2,500` rows | Benchmark: `72,670` rows)
Lightweight lookup table mapping every CVE to its Granite semantic family.

| Column | Type | Description |
| :--- | :--- | :--- |
| `cve_id` | `string` | Unique CVE identifier (**Primary Key**). |
| `family_id` | `int` | Assigned IBM Granite semantic family (`0`–`9`). |

### 2.3 `family_summary.csv` (`10` rows in both Historical and Benchmark directories)
Family-level metadata and historical KEV risk profile for all 10 semantic families (`family_id` `0`–`9` are identical across historical and benchmark outputs).

| `family_id` | `family_name` | Historical `family_size` (`n=2,500`) | 2026 Benchmark `family_size` (`N=72,670`) | `historical_kev_count` (`K=317`) | Public-Ready `population_kev_rate` (`Pop Lift`) | Sample `historical_kev_rate` *(Disclaimer Required)* |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **0** | `Cross-Site Scripting (XSS)` | 219 | 4,926 (`6.78%`) | 0 | **0.000%** (`0.00×`) | 0.00% |
| **1** | `SQL Injection` | 227 | 4,499 (`6.19%`) | 11 | **0.126%** (`0.35×`) | 4.85% |
| **2** | `Buffer & Memory Corruption & Denial of Service & Crash` | 196 | 6,975 (`9.60%`) | 31 | **0.465%** (`1.29×`) | 15.82% |
| **3** | `Remote Code Execution & Denial of Service & Crash` | 338 | 9,162 (`12.61%`) | 75 | **0.704%** (`1.96×`) | 22.19% |
| **4** | `Remote Code Execution & Path Traversal & File Upload` | 350 | 12,371 (`17.02%`) | 64 | **0.553%** (`1.54×`) | 18.29% |
| **5** | `Cross-Site Scripting (XSS) [CWE-79]` | 134 | 899 (`1.24%`) | 0 | **0.000%** (`0.00×`) | 0.00% |
| **6** | `Denial of Service & Crash & Buffer & Memory Corruption` | 260 | 7,297 (`10.04%`) | 8 | **0.079%** (`0.22×`) | 3.08% |
| **7** | `Privilege Escalation` | 201 | 3,907 (`5.38%`) | 66 | **1.201%** (`3.34×`) | 32.84% |
| **8** | `Cross-Site Scripting (XSS) & Cross-Site Request Forgery (CSRF)` | 260 | 8,202 (`11.29%`) | 24 | **0.252%** (`0.70×`) | 9.23% |
| **9** | `Auth Bypass & Access Control` | 315 | 14,432 (`19.86%`) | 38 | **0.340%** (`0.95×`) | 12.06% |
| **Total** | **All 10 Families** | **2,500** | **72,670 (`100.0%`)** | **317** | **0.360%** (`1.00×` Base) | **12.68%** |

| Column | Type | Safe for Public Display? | Description |
| :--- | :--- | :---: | :--- |
| `family_id` | `int` | Yes | Semantic cluster ID (`0`–`9`, **Primary Key**). |
| `family_name` | `string` | Yes | Human-readable family label derived from centroid representatives and top CWEs. |
| `family_size` | `int` | Yes | Number of CVEs assigned to this family in the respective cohort (`sum = 2,500` in historical; `sum = 72,670` in benchmark). |
| `historical_kev_count` | `int` | Yes | Count of 2024–2025 KEV vulnerabilities in this family (`sum = 317`). |
| `population_kev_rate` | `float` | **Yes (Recommended)** | **Horvitz–Thompson population-adjusted KEV probability** (`0.0000` to `0.012011`, i.e., `0.00%` to `1.201%`), weighted to the full 2024–2025 NVD population (`88,103` CVEs, `0.360%` base rate). |
| `population_lift` | `float` | **Yes (Recommended)** | Ratio of `population_kev_rate` to the `0.360%` population base rate (`0.00×` to `3.34×`). |
| `historical_kev_rate` / `sample_kev_rate` | `float` | **Requires Disclaimer** | Raw KEV rate inside the 2,500-CVE case-control sample (`0.00%` to `32.84%`, where overall sample base rate is `12.68%`). **Never display as a real-world exploitation probability without noting the 35.2× KEV sample enrichment.** |
| `sample_lift` | `float` | With Disclaimer | Ratio of `sample_kev_rate` to the `12.68%` sample average (`0.00×` to `2.59×`). |
| `ci_95_low`, `ci_95_high` | `float` | With Disclaimer | 95% Wilson score confidence interval bounds around `sample_kev_rate`. |
| `representative_cves` | `string` | Yes | Comma-separated list of the 3 CVEs closest to the family's Granite embedding centroid. |
| `top_characteristics` | `string` | Yes | Summary string with cosine cohesion, dominant mechanisms, primary CWE share, and remote/local split. |

### 2.4 Research Evaluation Tables (`outputs/granite/`)
- **`cwe_semantic_analysis.csv` (`647` rows, `6` columns)**:
  - Columns: `family_id, cwe_id, cve_count, family_share, cwe_share_across_families, cwe_name`
  - Cross-tabulation showing how each `(family_id, cwe_id)` pair distributes across families (`family_share` = fraction of the family having that CWE; `cwe_share_across_families` = fraction of that CWE landing in that Granite family).
- **`baseline_comparison.csv` (`5` rows)**:
  - Columns: `method, num_groups, non_missing_coverage, peak_group_kev_rate, peak_group_lift, population_peak_kev_rate, population_peak_lift, top3_groups_kev_share, top3_groups_volume_share, top3_concentration_ratio, population_top3_volume_share, population_top3_concentration_ratio`
  - Compares `IBM Granite Embeddings (KMeans)` against `TF-IDF Text Baseline (KMeans)`, `Simple Keyword Rules`, `Official CWE Top Categories`, and `CVSSv3 Severity × Attack Vector`.
- **`temporal_validation_2024_2025.csv` (`10` rows)**:
  - Columns: `family_id, train_2024_n, train_2024_kev, train_2024_rate, train_2024_lift, val_2025_n, val_2025_kev, val_2025_rate, val_2025_lift`
  - Leakage-free out-of-time validation: clusters fit strictly on 2024 (`1,181` CVEs) and evaluated on held-out 2025 (`1,319` CVEs).

---

## 3. Recommended Join Patterns (Pandas / SQL / Snowflake)

### Pattern A — Enriching Member 1's 2026 Predictions (`Rankings` & `Top 500` Pages)
Join Member 1's `predictions.csv` or `top500.csv` with the **2026 Benchmark** Granite tables:

```python
import pandas as pd

predictions = pd.read_csv("outputs/predictions.csv")  # Member 1 output
bench_features = pd.read_csv("outputs/granite/benchmark_2026/granite_features.csv")
bench_summary = pd.read_csv("outputs/granite/benchmark_2026/family_summary.csv")

# 1. Join CVE-level Granite features (1:1 inner join on cve_id)
df_ranked = predictions.merge(bench_features, on="cve_id", how="left")

# 2. Join Family-level metadata & historical KEV priors (N:1 join on family_id)
df_ranked = df_ranked.merge(
    bench_summary[[
        "family_id",
        "family_name",
        "family_size",
        "population_kev_rate",
        "population_lift",
        "historical_kev_count",
        "top_characteristics",
    ]],
    on="family_id",
    how="left",
)
```

### Pattern B — Historical Family Explorer (`Family Explorer` & `Evaluation` Pages)
Use `outputs/granite/family_summary.csv` joined with `outputs/granite/granite_features.csv` to inspect the 2,500 historical CVEs and 317 KEV cases.

---

## 4. Public Display Rules vs. Disclaimer-Required Metrics

To ensure scientific accuracy during Sheridan Datathon judging:

1. **Metrics Safe to Display Directly (Public-Ready)**:
   - `population_kev_rate` (`0.00%` to `1.20%`) and `population_lift` (`0.00×` to `3.34×` vs. `0.36%` 2024–2025 NVD baseline).
   - `family_size` in `outputs/granite/benchmark_2026/family_summary.csv` (`72,670` total 2026 benchmark CVEs).
   - `historical_kev_count` (captures all `317` KEVs published in 2024–2025; top 3 families capture `205 / 317 = 64.67%` of all KEVs in `31.45%` of population-adjusted volume, a `2.06×` concentration ratio).
   - Out-of-time 2024 $\rightarrow$ 2025 enrichment (`64.24%` of 2025 KEVs captured in `33.28%` of 2025 volume = `1.93×` lift).
   - Metadata fallback recovery on the 2026 benchmark (`extraction_method == "text_rules_fallback"` when structured CVSS is missing).

2. **Metrics Requiring an Explicit Case-Control Sample Disclaimer**:
   - `historical_kev_rate` / `sample_kev_rate` (`0.00%` to `32.84%`).
   - **Required UI Caption if Shown**: *"Sample KEV rates reflect the 2,500-CVE historical research cohort (which includes all 317 KEVs from 2024–2025, a 12.68% sample base rate). Use `population_kev_rate` (base rate 0.36%) for true population-wide exploitation probabilities."*

3. **Semantic Nuance Note for Family 8**:
   - Family 8 (`Cross-Site Scripting (XSS) & Cross-Site Request Forgery (CSRF)`) contains both routine web XSS/CSRF (`6` KEVs in enterprise webmail) and `18` browser engine zero-day KEVs (`Google Chrome V8` / `Apple WebKit` `CWE-843`/`CWE-416` flaws whose descriptions emphasize *"maliciously crafted HTML page"*). If displaying Family 8 on the dashboard, surface `attack_surface` (`Browser / Renderer Engine` vs. `Web Application / Plugin`) so analysts can filter browser zero-days from web XSS.

---

## 5. Recommended Dashboard Visuals & Filters

1. **Global Sidebar / Rankings Filters (from `granite_features.csv`)**:
   - **Granite Semantic Family (`family_name`)**: Multi-select filter allowing analysts to isolate high-risk families (`Family 7: Privilege Escalation`, `Family 3: RCE & DoS/Crash`, `Family 4: RCE & Path Traversal/File Upload`).
   - **Attack Surface (`attack_surface`)**: Filter between `Network Appliance / VPN / Firewall`, `OS Kernel / Driver`, `Browser / Renderer Engine`, and `Web Application / Plugin`.
   - **Reachability & Auth (`remote_local`, `auth_required`)**: Quick toggle for `remote` + `auth_required == "no"` (unauthenticated remote threats), which works even when official NVD CVSS vectors are missing (`UNASSIGNED`).
2. **Family Explorer Bubble / Bar Chart (from `family_summary.csv`)**:
   - **X-axis**: 2026 Benchmark Volume (`family_size` from `benchmark_2026/family_summary.csv`).
   - **Y-axis**: Historical Population-Adjusted KEV Lift (`population_lift`, from `0.00×` in WordPress XSS Families 0 & 5 up to `3.34×` in Family 7 Privilege Escalation and `1.96×` in Family 3 RCE).
   - **Color / Size**: Historical KEV Count (`historical_kev_count`).
3. **CWE Fragmentation Sankey / Heatmap (`cwe_semantic_analysis.csv`)**:
   - Show how a single CWE (`CWE-79` Cross-Site Scripting) splits into `0.00%` KEV WordPress plugin XSS (`Families 0 & 5`) versus `0.25%` population-rate enterprise webmail/browser flaws (`Family 8`), and how `CRITICAL` CVSS (`9.0–10.0`) SQL Injection (`Family 1`, `7.92%` sample KEV rate) has **5.5× lower exploitation risk** than `CRITICAL` CVSS RCE (`Family 3`, `43.56%`) and Auth Bypass (`Family 9`, `44.23%`).
4. **Baseline Comparison Chart (`baseline_comparison.csv`)**:
   - Grouped bar chart comparing **Top-3 Group KEV Capture (`top3_groups_kev_share`)** across IBM Granite (`64.67%` with `100%` coverage), TF-IDF (`36.91%`), Simple Keyword Rules (`38.49%` with only `63.4%` coverage), and Official CWE Categories (`17.03%`).

