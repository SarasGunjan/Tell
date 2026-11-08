---
title: "Every attack has a tell: ranking 72,670 CVEs with IBM Granite, Gemini and a galaxy"
published: false
tags: mlhacks, devchallenge, hackathon, security
---

<!-- MLH x DEV Writing Challenge entry (follows the official template at https://dev.to/mlh-hackathon).
     Post it from the DEV account linked to your MLH registration, during Nov 1-30, 2026.
     Fill in the [brackets] in "Hackathon Experience", add a cover image (docs/devpost/01-galaxy.jpg),
     and replace the video line once the demo is on YouTube. -->

_This is a submission for the [MLH x DEV Writing Challenge](https://dev.to/mlh-hackathon)_

## What I Built

More than 92,000 software vulnerabilities have been published so far in 2026, over double all of 2024. Fewer than 1 in
250 is ever confirmed to be used by attackers. So the question security teams ask every week isn't "how bad is this?" but
**"what do we fix first?"**

At **Sheridan Datathon 2026** our team of three took on IBM's *Before the Breach* track: from 72,670 vulnerabilities
(CVEs) published January to September 2026, pick the 500 most likely to land on CISA's Known Exploited Vulnerabilities
(KEV) list. We called the project **Tell**, because every attack has a tell.

### The simplest ranking won

We tested five ways to rank, training on 2024 and checking against what actually got exploited in 2025
(Hits@500 = how many later-exploited CVEs land in your top 500):

| Method | Hits@500 (2025 backtest) |
|---|---|
| Public exploit code first, then EPSS | **18** |
| Logistic Regression | 16 |
| LightGBM | 16 |
| EPSS alone | 8 |

We expected the models to win. They didn't. A plain rule beat both, so that's what we submitted. We were also strict
about **leakage**: NIST data is today's version, so some fields were filled in *after* attacks happened. Our ranking
uses only what was known at each CVE's snapshot month (EPSS plus four public-exploit flags) and skips fields like
`nvd_status` and reference counts that quietly give the answer away.

### IBM Granite found what severity scores miss

We used **IBM Granite** (`granite-embedding-small-english-r2`) to turn 2,500 historical CVE descriptions into
embeddings, grouped them into 10 semantic families with K-Means, and assigned every 2026 CVE a family.

- **Weakness labels miss context.** Cross-site scripting (CWE-79) shows up in 8 of the 10 families.
- **Exploitation is concentrated.** Three families held **64.7%** of 317 historical KEV cases while making up about
  **31%** of vulnerabilities (after weighting for how the sample was drawn). On 2024 → 2025 data the top families caught
  **64.2% of 2025's KEV cases in 33.3% of the volume (1.93×)**.
- **It works when data is missing.** 8.7% of 2026 CVEs have no CVSS v3 score and 6.8% have no CWE, but every one has a
  description, so every CVE still gets a family.

Because descriptions can be edited after disclosure, families **explain** the ranking rather than drive it.

### A galaxy of 72,670 stars

Numbers in a CSV don't help an analyst at 9am, so I built the web app. The home page is a **Threat Galaxy**: every CVE is
a star, each spiral arm is a Granite family, the closer to the core the higher the rank, size is EPSS and glow marks the
Top 500. Tap a star to light up its family; tap again for its brief. **Split** pulls the galaxy apart into its 10
families. It's vanilla TypeScript and Canvas 2D (no framework), drawing all 72,670 points at about 120 fps from one
compressed API response, with Chart.js charts in IBM's Carbon colours. Every chart is labelled with where its numbers
come from.

What I learned: on rare events, a strong simple signal is hard to beat, and saying so honestly is part of good data work.

## Demo

- **Live site:** https://149-28-52-109.sslip.io (works on phones too)
- **Code:** https://github.com/SarasGunjan/Tell
- **Video:** [add the YouTube link here once it's uploaded]

## Partner Technologies

### Google Gemini API

**Telly**, our assistant, runs on `gemini-2.5-flash` with **function calling**, and it can't answer from memory. Every
question goes through tools that read our own result files: look up a CVE, filter the top 500, compare families,
summarise the research. Gemini picks the tools (up to 4 rounds), our server runs them, and Gemini writes the answer
from what came back. Then a **grounding check** compares every CVE-specific claim (rank, EPSS, exploit flags) against
the data before the reply is shown.

The same model powers Telly's other face: a pixel astronaut that walks around the site and explains any chart in
plain English, and the CVE briefs on the Ask Telly page.

Things we learned working with it:

- **Turn off "thinking" for short answers.** Gemini 2.5 Flash thinks by default, and those tokens count against the
  output limit, so short replies came back cut off. Setting `thinkingConfig.thinkingBudget = 0` fixed it and made it
  faster.
- **Prompt for what not to say.** The first live brief invented a date and called a CVE "critical" with no CVSS score.
  We now tell it to never use severity words unless a score exists, never give exploit odds, and say "not available"
  for missing fields.
- **Keep the key out of URLs.** We send it as an `x-goog-api-key` header so it never ends up in logs, and nginx
  rate-limits the AI endpoints to protect the quota.
- **Have a fallback.** If Gemini is unreachable, a rule-based router answers the common questions from the same tools,
  so the demo never breaks.

### Vultr

Tell runs on a **Vultr** Cloud Compute instance (2 vCPU, 4 GB, Ubuntu 24.04, New York) paid for with MLH's Vultr
credit. One idempotent script, `deploy/setup_vultr.sh`, takes a fresh server to a live HTTPS site: it installs Docker
and nginx, opens only ports 22/80/443 with ufw, builds a multi-stage Docker image (Node builds the front end, a slim
Python image runs FastAPI as a non-root user), puts nginx in front with rate limits and a strict Content Security
Policy, and gets a Let's Encrypt certificate through certbot using a free `sslip.io` hostname. Updates are a
`git pull` and `docker compose up -d --build`. Vultr made it easy: the server was reachable over SSH about a minute
after we created it.

## Hackathon Experience

We built Tell at **Sheridan Datathon 2026** (November 7–8, Sheridan College, Hazel McCallion Campus) as a team of three:
one teammate built the ranking and backtests, one ran the IBM Granite research, and I built the website, the API, Telly
and the deployment.

[Add 2–3 sentences in your own words: what the atmosphere was like, a moment you'll remember, and who you met.]

**Takeaway:** severity tells you how bad a vulnerability *could* be. Ranking tells you what to look at first. IBM
Granite helps explain the patterns behind both.
