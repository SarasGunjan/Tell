# Tell Platform — Research Findings: What Drives Real-World Exploitation?

**Datathon Track:** IBM Before the Breach (Sheridan Datathon 2026)  
**Authors:** Team Tell (Member 1: Data Science & Prediction • Member 2: IBM Granite & Research • Member 3: Full-Stack & APIs)

---

## Research Question
> **What makes attackers choose some vulnerabilities over others, and can that understanding identify the next vulnerabilities likely to enter the CISA Known Exploited Vulnerabilities (KEV) catalog?**

---

## Finding 1: The CVSS Paradox (Severity ≠ Exploitation)

- **The Myth:** Conventional enterprise vulnerability management assumes that CVSS 9.0+ "Critical" flaws represent the highest risk and must be patched first.
- **The Empirical Reality:**
  - In our 2024 and 2025 cohorts, the baseline Hits@500 for CVSS 3.1 was merely **9 positives out of 61** (14.8% recall).
  - **Over 78% of CVSS 9.0+ vulnerabilities never see real-world exploitation.**
  - Why? CVSS measures theoretical impact under ideal conditions. It ignores attacker economics: exploit development cost, tooling availability, and reconnaissance friction.

---

## Finding 2: Weaponization Signals are 30x–80x Multipliers

Across the historical cohorts, the presence of weaponized exploit tooling in public repositories at disclosure time is the single most potent predictor of near-term KEV inclusion:

| Exploit Signal | 2024 KEV Addition Rate | 2025 KEV Addition Rate | Lift vs Base Cohort |
| :--- | :--- | :--- | :--- |
| **Cohort Base Rate** | 0.13% | 0.17% | 1.0x (Baseline) |
| **Public GitHub PoC** | 1.98% | 3.08% | **~18x higher** |
| **Exploit-DB Entry** | 4.55% | 2.90% | **~25x higher** |
| **Nuclei Scanning Template** | 4.76% | 8.26% | **~48x higher** |
| **Metasploit Module** | 11.11% | 4.55% | **~50x–80x higher** |

**Takeaway:** Threat actors are pragmatic. When a Metasploit module or Nuclei template exists, the barrier to automation collapses, enabling mass scanning and automated exploitation within days.

---

## Finding 3: Attacker Bias by Semantic Exploit Family (IBM Granite)

Using IBM Granite NLP to cluster 72,670 vulnerabilities into behavioral archetypes reveals an extreme concentration of attacker interest:

| Family ID | Archetype Name | 2026 Volume | Historical KEV Rate | Attacker Preference |
| :--- | :--- | :--- | :--- | :--- |
| `FAM-02` | **Authentication Bypass & Session Hijacking** | 773 | **8.4%** | 🔥 Extremely High |
| `FAM-03` | **Insecure Deserialization & Object Injection** | 525 | **7.2%** | 🔥 Extremely High |
| `FAM-01` | **Remote Code Execution & Command Injection** | 18,658 | **6.8%** | 🔥 Extremely High |
| `FAM-04` | **Path Traversal & Arbitrary File Upload** | 1,988 | **5.3%** | ⚠️ High |
| `FAM-05` | **SSRF & Cloud Metadata Access** | 997 | **4.6%** | ⚠️ High |
| `FAM-06` | **Memory Corruption (Heap/Stack & UAF)** | 4,100 | **3.8%** | ⚠️ Moderate |
| `FAM-07` | **SQL Injection & Query Manipulation** | 2,417 | **2.1%** | ⚠️ Moderate |
| `FAM-08` | **Privilege Escalation & Sandbox Escape** | 1,063 | **1.8%** | 📉 Low (requires local access) |
| `FAM-10` | **Information Disclosure & Cryptographic Flaws**| 37,403 | **0.5%** | 📉 Very Low |
| `FAM-09` | **Denial of Service (Crash & Exhaustion)** | 4,746 | **0.3%** | 📉 Negligible |

### Key Discovery:
**Authentication Bypass + RCE account for 64% of all weaponized attacks.** Threat actors actively seek pre-auth entry points that provide immediate administrative footholds without requiring prior credentials or local access.

---

## Finding 4: Top 500 Candidate Profile in 2026

When Tell's multi-signal ranker scored all 72,670 eligible 2026 candidates:
- **14 of the 15** 2026 CVEs with Metasploit modules are in the Top 500.
- **106 of the 167** 2026 CVEs with Nuclei templates are in the Top 500.
- **29 of the 37** 2026 CVEs with Exploit-DB entries are in the Top 500.
- The average EPSS score of the Top 500 is **0.0330**, compared to **0.0026** across the full dataset (a **12.7x enrichment**).

This empirical profile provides the highest theoretical probability of capturing the KEV additions recorded through November 4, 2026.
