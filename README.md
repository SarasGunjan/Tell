# Tell: every attack has a tell

**Sheridan Datathon 2026 · IBM "Before the Breach" track**

**Live site: https://tell-datathon.duckdns.org** (any laptop or phone, no login)

Over 92,000 vulnerabilities (CVEs) have been published in 2026, and fewer than 1 in 250 is ever confirmed exploited.
IBM asked: predict which ones attackers will exploit, and show engineers **what to fix first and why**.
Tell answers with a ranked top 500, IBM Granite vulnerability families that explain the patterns behind exploitation,
and a website that lets an analyst explore all 72,670 benchmark CVEs.

- **Submission:** [`top500.csv`](top500.csv) (one column, `cve_id`, 500 unique IDs, all on `scoreboard_2026.csv`)
- **Full write-up:** the *Our Story* page on the live site

## What we found

**Ranking.** We compared five methods, training on 2024 and testing on 2025 (Hits@K = later-exploited CVEs in the top K):

| Method | Hits@100 | Hits@250 | Hits@500 |
|---|---:|---:|---:|
| **Public exploit code first, then EPSS** (submitted) | 8 | 15 | **18** |
| Logistic Regression | 7 | 14 | 16 |
| LightGBM | 8 | 10 | 16 |
| EPSS alone | 4 | 8 | 8 |

The simplest rule beat both machine-learning models, so it produced the submitted top 500. Source: [`results/model_metrics.csv`](results/model_metrics.csv).

**IBM Granite discoveries.** `ibm-granite/granite-embedding-small-english-r2` embedded 2,500 historical CVE descriptions;
K-Means grouped them into 10 families, and every 2026 CVE was assigned one.

- 3 families (Privilege Escalation, Remote Code Execution, RCE with Path Traversal/File Upload) held **64.67%** of 317
  historical KEV cases while making up about **31.45%** of vulnerabilities (population-weighted).
- Out of time: the top 2024 families caught **64.24%** of 2025 KEV cases in **33.28%** of volume (**1.93×**).
- CWE-79 (cross-site scripting) is spread across **8 of 10** families: weakness labels miss context.
- 8.74% of 2026 CVEs lack CVSS v3 and 6.82% lack a CWE, but 100% have a description, so every CVE gets a family.

Sources: [`outputs/granite/`](outputs/granite). `python -m src.api.validate` rebuilds these numbers from the files.

**Fairness.** The ranking uses only snapshot-time columns from `scoreboard_2026.csv`: `epss`, `exploitdb`, `metasploit`,
`nuclei`, `poc_github`. It does not use `nvd_status`, `n_affected_cpes`, `n_references`, blank severity scores or
reference links, which IBM flags as leaky. Granite families explain the ranking; they are not used to produce it,
because descriptions can be edited after disclosure.

## The website

| Page | What it shows |
|---|---|
| Galaxy | All 72,670 CVEs as stars: distance from the core = rank, arm = Granite family, size = EPSS. Tap a star to focus its family, tap again to open it. *Split* separates the 10 families. |
| Signals | Headline numbers and how EPSS and exploit code spread across the ranking |
| Top 500 | The submitted shortlist, searchable and filterable |
| Families | Historical exploitation rate and 2026 size of each Granite family |
| Discoveries | Where exploitation concentrates and the out-of-time check |
| How We Ranked | The five methods compared at 100, 250 and 500 |
| Ask Telly | AI briefs and questions about any CVE, answered only from our data |
| Our Story | The full written analysis, fairness notes and limitations |

Every chart is labelled with where its numbers come from (observed, snapshot signal, model, IBM Granite, AI-generated).
**Telly**, our assistant, uses Google Gemini (`gemini-2.5-flash`) with function calling: it can only answer through tools
that read our results, and a checker verifies CVE-specific claims before they are shown. Telly also appears as a pixel
astronaut that walks the site and explains each chart in plain English.

## Repository

```
top500.csv             submission file
results/               Member 1: predictions, model comparison, patch budget
outputs/granite/       Member 2: Granite families, research metrics, 2026 assignments
src/api/               FastAPI read-only API over results/ and outputs/ (+ data validator)
src/ai/                Gemini briefs, Snowflake Cortex client, evidence grounding
web/                   TypeScript + Chart.js front end (Vite)
deploy/                Docker, nginx, Vultr setup, key and domain scripts
docs/                  architecture, leakage audit, research findings, deploy guide
tests/                 API and contract tests
```

Model training and Granite clustering were developed on the `feature/data-ml` and `feature/granite` branches; this
branch ships their final outputs. `src/dashboard/` is the earlier Streamlit prototype.

## Run it locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r deploy/requirements-web.txt
.venv/bin/uvicorn src.api.server:app --port 8000          # API
npm --prefix web install && npm --prefix web run dev       # site on http://localhost:5173
```

Or with Docker: `docker compose -f deploy/docker-compose.yml up --build` (serves everything on port 8000).
Optional keys go in `.env` (see `.env.example`); without them the AI features use offline answers.
Checks: `.venv/bin/python -m pytest tests/test_api.py` and `.venv/bin/python -m src.api.validate`.

## Deployment

Vultr cloud server (Ubuntu 24.04) running one Docker image behind nginx with HTTPS, AI rate limits and strict security
headers. `deploy/setup_vultr.sh` sets up a fresh server; see [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Team

- **Member 1, data science and prediction:** leakage-safe cohorts, baselines, Logistic Regression and LightGBM, the top 500.
- **Member 2, IBM Granite and research:** embeddings, the 10 families, historical KEV analysis, out-of-time validation.
- **Member 3, full stack and deployment:** API, website, Telly assistant, Vultr deployment.

Built with IBM Granite, Google Gemini (MLH), Vultr (MLH), FastAPI, TypeScript and Chart.js.

## Limitations

The historical sample is KEV-enriched and needs population weighting. Descriptions can contain post-disclosure edits.
KEV is not a complete record of real-world exploitation. Adding Granite features to the ranking model has not yet been
shown to help. These are research findings, not exploit probabilities.
