"""
Tell Platform - Google Gemini API Structured Security Briefs
Author: Member 3 (Full-Stack, APIs & Deployment)

Generates standardized executive and technical security briefs for high-risk CVEs
and exploit families using the Google Gemini API (gemini-1.5-flash).
Includes offline grounded fallback for reliable demonstration during datathon judging.
"""

import os
import json
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger("Tell.GeminiBriefs")


class GeminiBriefGenerator:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY", "")
        self.model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        self.is_configured = bool(self.api_key)

        if self.is_configured:
            logger.info(f"Gemini API configured with model {self.model}")
        else:
            logger.info("GEMINI_API_KEY not configured. Running in Grounded Offline Demo Mode.")

    def generate_cve_brief(self, cve_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a structured security brief for a specific CVE.
        """
        if self.is_configured:
            try:
                # Key goes in a header, not the URL, so it never lands in logs or tracebacks
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
                prompt = (
                    "You are a Senior Vulnerability Intelligence Analyst at Tell. "
                    "Write a crisp, evidence-grounded security brief for this vulnerability. "
                    "Include: Executive Summary, Technical Attack Vector, Weaponization Signals, "
                    "and Recommended Mitigation. Do NOT invent numbers or post-snapshot facts.\n\n"
                    f"Vulnerability Data: {json.dumps(cve_context)}"
                )

                payload = {
                    "contents": [{
                        "parts": [{"text": prompt}]
                    }],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 600,
                        "thinkingConfig": {"thinkingBudget": 0}
                    }
                }

                resp = requests.post(url, json=payload, headers={"x-goog-api-key": self.api_key}, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    brief_text = data["candidates"][0]["content"]["parts"][0]["text"]
                    return {
                        "source": "Google Gemini API (Live)",
                        "model": self.model,
                        "content": brief_text
                    }
                else:
                    logger.warning(f"Gemini API error {resp.status_code}: {resp.text}")
            except Exception as e:
                logger.warning(f"Error calling Gemini API: {e}")

        # Grounded Offline Generator
        return self._generate_offline_cve_brief(cve_context)

    def _generate_offline_cve_brief(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = ctx.get("cve_id", "CVE-2026-XXXX")
        rank = ctx.get("rank", 1)
        epss = ctx.get("epss", 0.0)
        score = ctx.get("prediction_score")
        score_str = f" | **Score:** `{score:.4f}`" if isinstance(score, (int, float)) else ""
        family = ctx.get("family_name", "Remote Code Execution")
        remote_local = ctx.get("remote_local", "REMOTE")
        auth = ctx.get("auth_required", "NONE")
        desc = ctx.get("description", "Vulnerability in network protocol handling.")

        exploit_signals = []
        if ctx.get("metasploit", 0) > 0: exploit_signals.append("Metasploit Module")
        if ctx.get("nuclei", 0) > 0: exploit_signals.append("Nuclei Template")
        if ctx.get("exploitdb", 0) > 0: exploit_signals.append("ExploitDB Entry")
        if ctx.get("poc_github", 0) > 0: exploit_signals.append("Public GitHub PoC")
        exploit_str = ", ".join(exploit_signals) if exploit_signals else "No public exploit code cataloged"

        brief = f"""### Executive Vulnerability Brief: {cve_id}
**Tell Rank:** #{rank} of 72,670{score_str} | **EPSS:** `{epss:.4f}`

#### Executive Summary
{cve_id} is ranked #{rank} on the 2026 scoreboard. It belongs to the **{family}** family. Recorded public exploit signals: {exploit_str}.

#### Attack Surface & Prerequisites (IBM Granite family data)
- **Exposure:** `{remote_local}` access vector
- **Authentication:** `{auth}` credentials required for trigger
- **Vulnerability Archetype:** `{family}`
- **Technical Mechanism:** {desc[:200]}...

#### Exploit Intelligence & Threat Landscape
- **Weaponization State:** {exploit_str}
- **Caveat:** A rank reflects recorded signals at the snapshot, not a calibrated probability or confirmed exploitation.

#### Immediate Defensive Actions
1. **Perimeter Audit:** Query attack surface management systems to detect external internet exposure.
2. **Telemetry Tuning:** Ingest detection signatures matching public proof-of-concept indicators.
3. **Emergency Patching:** Expedite patch scheduling within standard emergency change-management SLA.
"""
        return {
            "source": "Tell Grounded Brief Generator (Offline Mode)",
            "model": "gemini-1.5-flash / Grounded Template",
            "content": brief
        }
