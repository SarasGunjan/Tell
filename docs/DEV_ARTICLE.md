---
title: "Every attack has a tell: ranking 72,670 CVEs with IBM Granite, Gemini and a galaxy"
published: false
description: "How our Sheridan Datathon 2026 team picked the 500 vulnerabilities most likely to be exploited, and what IBM Granite found that severity scores miss."
tags: datascience, security, machinelearning, hackathon
cover_image:
---

<!-- Draft for the MLH DEV Writing Challenge. Paste into https://dev.to/new, check the links, add a cover image
     (a screenshot of the galaxy works well), then set published: true. -->

More than 92,000 software vulnerabilities have been published so far in 2026, over double all of 2024. Fewer than 1 in 250 is ever
confirmed to be used by attackers. So the question security teams ask every week isn't "how bad is this?" but
**"what do we fix first?"**

At **Sheridan Datathon 2026** our team of three took on IBM's *Before the Breach* track: from 72,670 vulnerabilities
(CVEs) published January to September 2026, pick the 500 most likely to land on CISA's Known Exploited Vulnerabilities
(KEV) list. We called the project **Tell**, because every attack has a tell.

👉 **Live site:** https://149-28-52-109.sslip.io · **Code:** https://github.com/SarasGunjan/Tell

## 1. The simplest ranking won

We tested five ways to rank, training on 2024 and checking against what actually got exploited in 2025
(Hits@500 = how many later-exploited CVEs land in your top 500):

| Method | Hits@500 (2025 backtest) |
|---|---|
| Public exploit code first, then EPSS | **18** |
| Logistic Regression | 16 |
| LightGBM | 16 |
| EPSS alone | 8 |

We expected the models to win. They didn't. A plain rule (public exploit code first, then EPSS) beat both, so that's
what we submitted. We'd rather ship the method that held up than the one that sounds fancier.

We were also strict about **leakage**. NIST data is today's version, so some fields were filled in *after* attacks
happened. Our ranking uses only what was known at the end of each CVE's snapshot month: EPSS plus four exploit flags
(Exploit-DB, Metasploit, Nuclei, GitHub PoC). We deliberately skipped `nvd_status`, reference counts and similar
columns, because they quietly give away the answer.

## 2. IBM Granite found what severity scores miss

Ranking tells you *which* CVEs. We also wanted to know *why*, and what they have in common.

We used **IBM Granite** (`granite-embedding-small-english-r2`) to turn 2,500 historical CVE descriptions into
embeddings, then grouped them into 10 semantic families with K-Means. Every one of the 72,670 2026 CVEs was then
assigned to a family.

Three findings:

- **Weakness labels don't capture everything.** Cross-site scripting (CWE-79) shows up in 8 of the 10 families. The
  same label splits by technical context, and different labels cluster together.
- **Exploitation is concentrated.** Our sample had 317 KEV cases. Three families (Privilege Escalation, Remote Code
  Execution, and RCE with Path Traversal/File Upload) held **64.7%** of them, while making up only about **31%** of
  vulnerabilities once we weighted for how the sample was drawn. In a separate 2024 → 2025 check, the top 2024 families
  caught **64.2% of 2025's KEV cases in 33.3% of the volume (1.93×)**.
- **It works when data is missing.** 8.7% of the 2026 CVEs have no CVSS v3 score and 6.8% have no CWE, but 100% have a
  description, so every CVE still gets a family.

Because descriptions can be edited after disclosure, we used families to **explain** the ranking, not to drive it.

## 3. Making it explorable: a galaxy of 72,670 stars

Numbers in a CSV don't help an analyst at 9am, so I built the web app. The home page is a **Threat Galaxy**:

- every CVE is a star, and each spiral arm is a Granite family
- the closer to the core, the higher the rank; size is EPSS and glow means Top 500
- tap a star to light up its family, tap again for the full CVE brief
- **Split** view pulls the galaxy apart into 10 separate family clusters

It's a vanilla TypeScript + Canvas 2D app (no framework), drawing 72,670 points at about 120 fps from one columnar
`/api/galaxy` response (~418 KB gzipped). Charts use Chart.js, the colours come from IBM's Carbon palette, and every
chart carries a label for where its numbers come from (observed, model, IBM Granite or AI-generated).

## 4. An assistant that can't make things up

**Ask Tell** is a chat assistant on **Google Gemini** (`gemini-2.5-flash`) with function calling. It can't answer from
memory. It calls tools that read our results (look up a CVE, filter the top 500, compare families), and a grounding
check verifies every CVE-specific claim against the data before you see it. If Gemini is down, a rule-based router
answers the common questions from the same tools.

There's also a small pixel astronaut, Crafternauta, who walks around the site and explains each chart in plain English.

## 5. Shipping it

FastAPI + the built front end in one Docker image, behind nginx (rate limits, a strict Content Security Policy) on a
**Vultr** cloud server, with HTTPS from Let's Encrypt. One script sets up a fresh Ubuntu server from scratch.

## What we'd do next

- Test whether Granite family features actually improve the ranking model. We haven't shown that yet.
- Use time-stamped descriptions to remove post-disclosure leakage from the semantic analysis.
- Treat KEV as a lower bound. A vulnerability not on KEV may still have been attacked.

**Takeaway:** severity tells you how bad a vulnerability *could* be. Ranking tells you what to look at first. IBM
Granite helps explain the patterns behind both.

*Built at Sheridan Datathon 2026 (MLH) by team Tell. Thanks to IBM for the challenge and the data.*
