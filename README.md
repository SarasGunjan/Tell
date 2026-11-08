# ThreatRank — IBM Granite Intelligence & Research Pipeline (Member 2)

**Sheridan Datathon 2026 | IBM Challenge Track: *Before the Breach***  
**Working Branch:** `feature/granite`

---

## 1. Overview

This branch (`feature/granite`) contains **Member 2's independent IBM Granite Intelligence & Research workstream** for ThreatRank:
- Encodes unstructured CVE descriptions into 384-dimensional semantic embeddings using the official local **IBM Granite Embedding Small English R2** model (`ibm-granite/granite-embedding-small-english-r2`).
- Discovers behavioral vulnerability families using reproducible K-Means clustering with saved centroid persistence for consistent 2026 benchmark assignment.
- Extracts `remote_local`, `auth_required`, `vulnerability_type`, and `attack_surface` while strictly distinguishing structured NVD CVSS fields (`structured_cvss`) from conservative deterministic lexical rules (`deterministic_rule`), defaulting to `unknown` rather than guessing.
- Compares semantic families against official CWE classifications (`cwe_semantic_analysis.csv`) and evaluates historical CISA KEV patterns and simpler baselines under strict temporal leakage controls.
- Produces validated CSV deliverables (`granite_features.csv`, `families.csv`, `family_summary.csv`) under `outputs/granite/`.

---

## 2. Repository Structure (`feature/granite`)

```text
ThreatRank/
├── src/
│   └── granite/
│       ├── __init__.py
│       ├── config.py           # Model IDs, paths, suffix-agnostic dataset resolver
│       ├── load_data.py        # Normalization, deduplication, validation, cohort filtering
│       ├── embeddings.py       # Local IBM Granite embedding engine + SHA-256 .npz caching
│       ├── extraction.py       # Provenance-tracked CVSS + deterministic attribute extraction
│       ├── clustering.py       # Reproducible KMeans, cohesion metrics, model persistence
│       ├── cwe_analysis.py     # CWE vs. semantic family cross-tab & cross-CWE pair finder
│       ├── family_analysis.py  # Time-safe historical KEV statistics & baseline comparisons
│       ├── export.py           # Deliverable builder & strict contract validator
│       └── pipeline.py         # End-to-end CLI entrypoint
├── tests/
│   └── granite/
│       ├── test_data_loading.py
│       ├── test_extraction.py
│       ├── test_clustering.py
│       ├── test_exports.py
│       └── test_research.py
├── docs/
│   ├── granite_dataset_audit.md  # Full audit of all 8 IBM challenge CSV datasets
│   ├── granite_methodology.md    # Technical architecture, provenance, & leakage controls
│   └── research_findings.md      # Quantified discoveries, CWE comparison, & baseline tests
├── outputs/
│   └── granite/
│       ├── granite_features.csv
│       ├── families.csv
│       ├── family_summary.csv
│       ├── cwe_semantic_analysis.csv
│       ├── baseline_comparison.csv
│       └── benchmark_2026/       # Consistent 2026 scoreboard family assignments
├── requirements.txt
└── .gitignore
```

---

## 3. Setup & Installation

```powershell
# 1. Install dependencies
python -m pip install -r requirements.txt
```

- **Hardware Requirements:** Runs locally on CPU (`torch.float32` optimization yields ~135 descriptions/sec) or automatically uses CUDA GPU if available. No IBM Cloud API keys or paid inference services are required.
- **Dataset Location:** The pipeline automatically resolves datasets from `data/raw/`, `data/`, or `c:\Users\johnj\OneDrive\Documentos\Datathon 2026\dataset\data\data\`, transparently matching both suffixed (`vulnerabilities(4).csv`) and unsuffixed (`vulnerabilities.csv`) filenames.

---

## 4. Running the Pipeline & Tests

### Phase 2 Working MVP (100 Real CVEs, 5 Clusters)
```powershell
python -m src.granite.pipeline --input "data/raw/vulnerabilities(4).csv" --limit 100 --clusters 5 --output-dir "outputs/granite/mvp_100"
```

### Phase 3 & 4 Historical Research + 2026 Benchmark Assignment
```powershell
python -m src.granite.pipeline `
  --input "data/raw/vulnerabilities(4).csv" `
  --published-after 2024-01-01 `
  --published-before 2025-12-31 `
  --limit 2500 `
  --clusters 10 `
  --batch-size 32 `
  --research `
  --benchmark "data/raw/scoreboard_2026(4).csv" `
  --benchmark-limit 1000 `
  --benchmark-output-dir "outputs/granite/benchmark_2026"
```

### Run Automated Unit Tests
```powershell
python -m pytest tests/granite -v
```

---

## 5. Deliverable Schemas for Teammates (Member 1 & Member 3)

All deliverables are written to `outputs/granite/` (and `outputs/granite/benchmark_2026/` for the 2026 target cohort):
1. **`granite_features.csv`**: `cve_id,family_id,remote_local,auth_required,vulnerability_type,attack_surface,product_or_vendor,extraction_method,extraction_confidence,evidence`
2. **`families.csv`**: `cve_id,family_id` (1:1 unique hard-cluster assignment per CVE)
3. **`family_summary.csv`**: `family_id,family_name,family_size,historical_kev_count,historical_kev_rate,representative_cves,top_characteristics`

