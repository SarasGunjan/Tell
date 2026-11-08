# Devpost submission draft: Tell

Paste each section into the matching Devpost field. Images are in `docs/devpost/` (3:2 screenshots plus a square logo).
Every number below was checked against the files in `results/` and `outputs/granite/`.

**Name:** Tell
**Tagline:** Every attack has a tell.
**Track:** IBM "Before the Breach". Also enter: Best Use of Gemini API, Best Use of Vultr (plus any optional prize you finish).
**Live demo:** https://149-28-52-109.sslip.io
**Code:** https://github.com/SarasGunjan/Tell
**Submission file:** `top500.csv` in the repo root (one column, `cve_id`, 500 rows)

---

## Inspiration

More than 92,000 vulnerabilities have been published so far in 2026, over double all of 2024, and fewer than 1 in 250 is
ever confirmed to be exploited. Security teams can't patch everything, and the usual answer, sorting by severity (CVSS),
says how bad an attack *could* be, not whether anyone will attack. IBM asked us to predict which vulnerabilities attackers
will exploit and show engineers what to fix first, and why. We wanted to answer the "why" as seriously as the "what".

## What it does

Tell ranks the 72,670 vulnerabilities on IBM's 2026 benchmark and explains the patterns behind exploitation:

- **Top 500:** the shortlist an engineer should look at first (our submitted `top500.csv`).
- **Galaxy:** every CVE is a star. Closer to the core means higher rank, each spiral arm is an IBM Granite family, size is
  EPSS and glow marks the Top 500. Tap a star to light up its family; tap again for the full brief. *Split* separates the
  galaxy into its 10 families.
- **Discoveries:** what IBM Granite found: exploitation concentrates in a few families, and the pattern held on unseen data.
- **Telly:** our Gemini assistant. It answers only by calling tools that read our data, and a checker verifies every
  CVE-specific claim before you see it. Telly also walks the site as a pixel astronaut and explains each chart.
- **Our Story:** the full analysis, the data we used, and our limitations, on the site itself.

Every chart says where its numbers come from: observed history, snapshot signal, model prediction, IBM Granite
assignment, or AI-generated.

## How we built it

**Ranking (Member 1).** We built leakage-safe cohorts (train on 2024, test on 2025) and compared five methods by Hits@K,
the number of later-exploited CVEs in the top K:

| Method | Hits@100 | Hits@250 | Hits@500 |
|---|---:|---:|---:|
| Public exploit code first, then EPSS | 8 | 15 | **18** |
| Logistic Regression | 7 | 14 | 16 |
| LightGBM | 8 | 10 | 16 |
| EPSS alone | 4 | 8 | 8 |

The simplest rule held up best, so it produced our top 500. It uses only snapshot-time columns from
`scoreboard_2026.csv`: `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github`.

**IBM Granite (Member 2).** `ibm-granite/granite-embedding-small-english-r2` turned 2,500 historical CVE descriptions into
embeddings, K-Means grouped them into 10 semantic families, and every 2026 CVE was assigned a family. Because the research
sample kept every KEV case, family rates are re-weighted to the full population of 88,103 CVEs.

**Platform (Member 3).** A FastAPI server reads the teammates' result files and serves a read-only API. The front end is
TypeScript with Chart.js and a canvas galaxy that draws all 72,670 points at about 120 frames per second. It uses IBM Plex
type and IBM's Carbon colours on a space theme, works on phones, and respects reduced motion. Telly runs on Google Gemini
(`gemini-2.5-flash`) with function calling. Everything ships as one Docker image behind nginx (HTTPS, rate limits, strict
security headers) on a Vultr cloud server.

## Challenges we ran into

- **Leakage.** NIST files are today's versions, so fields like `nvd_status` and reference counts quietly reveal which CVEs
  were attacked. We kept them out of the ranking and used Granite families only to explain, since descriptions can be
  edited after disclosure.
- **A sample that over-represents exploits.** The research sample kept every KEV case, so raw family rates are inflated;
  we re-weighted to the full population before comparing families.
- **Our models didn't beat the rule.** We expected LightGBM to win. It didn't, so we shipped the rule and said so.
- **Keeping an AI assistant honest.** Telly can only answer through tools over our data, and a grounding check blocks
  unsupported claims.

## Accomplishments that we're proud of

- A discovery that held up out of time: families chosen on 2024 data caught 64.24% of 2025's exploited cases in 33.28%
  of the volume (1.93×).
- One view of all 72,670 vulnerabilities that a judge or an analyst can understand in seconds.
- Every number on the site is traceable to a file, and an automatic validator rebuilds the headline numbers from the data.

## What we learned

- Severity and weakness labels miss context: cross-site scripting (CWE-79) is spread across 8 of our 10 families.
- On rare events, a strong simple signal (public exploit code) is hard to beat, and saying so honestly is part of good
  data work.
- Descriptions help most when other data is missing: 8.74% of 2026 CVEs lack CVSS v3 and 6.82% lack a CWE, but 100%
  have a description.

## What's next for Tell

- Test whether Granite family features improve the ranking without leakage, using time-stamped descriptions.
- Treat KEV as a lower bound and add other exploitation evidence.
- Weekly refresh so a security team can use Tell for triage.

## Built with

IBM Granite (granite-embedding-small-english-r2), Google Gemini API, Vultr, Python, pandas, scikit-learn, LightGBM,
FastAPI, TypeScript, Chart.js, Vite, Docker, nginx, Let's Encrypt.

---

# Written analysis (corrected)

*Your team's write-up with section 2 and section 4 updated to match the final results. Everything else is unchanged in
substance.*

## Predicting Vulnerability Risk Through Machine Learning and IBM Granite Semantic Intelligence

### 1. What problem are we solving?

Thousands of cybersecurity vulnerabilities are discovered each year, but not all are equally likely to be exploited.
Organizations often rely on CVSS severity scores and EPSS predictions to prioritize vulnerabilities, yet these indicators
do not capture every relationship between security weaknesses. IBM's Before the Breach challenge asks participants to
identify the 500 vulnerabilities most likely to enter CISA's Known Exploited Vulnerabilities (KEV) catalog. We developed
Tell, a platform that combines a validated ranking with IBM Granite semantic analysis to prioritize vulnerabilities and
uncover patterns in historical exploitation data.

### 2. How did we analyze the data?

We used eight IBM-provided datasets containing vulnerability descriptions, CVSS scores, EPSS indicators, CWE
classifications, affected products, exploit signals, and historical KEV records. Our approach has two components:

- **Ranking:** we compared five methods (CVSS first, EPSS first, public exploit code then EPSS, Logistic Regression and
  LightGBM), training on 2024 and testing on 2025. Public exploit code first, then EPSS, found 18 later-exploited CVEs in
  its top 500, ahead of Logistic Regression (16), LightGBM (16) and EPSS alone (8), so our submitted top 500 uses that rule.
  It uses only columns known at each CVE's snapshot month: `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github`.
- **IBM Granite:** the `granite-embedding-small-english-r2` model converts vulnerability descriptions into semantic
  embeddings. K-Means clustering groups similar vulnerabilities into families. Granite analyzed 2,500 historical CVEs,
  identifying 10 semantic families, which were then assigned to all 72,670 candidate CVEs in the 2026 benchmark.

### 3. What did we discover?

**Research Question 1: Can semantic analysis reveal relationships that traditional classifications miss?**
Granite grouped vulnerabilities with different CWE classifications together and separated vulnerabilities sharing the
same CWE into distinct groups. Cross-site scripting (CWE-79) appears across 8 of the 10 families.
*Finding:* CWE classifications identify weakness types, but semantic analysis reveals additional relationships within
and across them.

**Research Question 2: Are certain vulnerability families more associated with historical exploitation?**
Our historical analysis found 317 KEV cases among 2,500 sampled vulnerabilities. Three Granite families (Privilege
Escalation, Remote Code Execution, and Remote Code Execution with Path Traversal/File Upload) contained 64.67% of these
cases. After adjusting for the enriched sampling design, these families represented about 31.45% of the estimated
historical vulnerability population. In a separate 2024-to-2025 validation, the selected families contained 64.24% of
2025 KEV cases while representing 33.28% of evaluated vulnerabilities, a concentration ratio of 1.93×.
*Finding:* historical KEV inclusion was concentrated in particular semantic families, suggesting descriptions contain
useful risk-related information. The validation remains subject to historical description availability and
family-selection limits.

**Research Question 3: Can Granite help when vulnerability information is incomplete?**
Among the 72,670 benchmark CVEs, 8.74% lacked CVSS v3 scores, 6.82% lacked CWE classifications, and 100% contained
descriptions. Granite assigns a family from the description even when structured classifications are missing.
*Finding:* semantic analysis adds context without depending entirely on CVSS or CWE metadata.

### 4. How does Tell address IBM's challenge?

1. **Prediction:** a leakage-safe ranking, validated on 2025, produces the top 500.
2. **Understanding:** IBM Granite families and their historical relationship with KEV inclusion explain what the ranked
   vulnerabilities have in common.
3. **Visualization:** an interactive site presents the ranking, family analysis, research findings and method comparison,
   with Telly, an AI assistant that explores the evidence and cannot answer beyond it.

Analysts can see not only which vulnerabilities rank highly, but also what they share with others. In our 2025 backtest
the submitted method found 18 exploited vulnerabilities in its top 500, 2.25 times as many as EPSS alone (8).

### 5. What is the impact?

Tell shows how a validated ranking and semantic intelligence can support vulnerability prioritization. Vulnerability
descriptions contain relationships beyond severity scores and weakness classifications.
*Key takeaway:* severity tells us how serious a vulnerability could be. Ranking tells us which vulnerabilities deserve
attention first, and IBM Granite helps us understand the patterns behind them.

### Limitations

Our historical analysis used a KEV-enriched sample, requiring population weighting. Historical descriptions may contain
post-disclosure updates, limiting fully leakage-free evaluation. KEV inclusion is not a complete measure of real-world
exploitation, and adding Granite features to the ranking model has not yet been shown to help. These are research
findings, not guaranteed exploitation probabilities.
