"""IBM Granite on watsonx.ai writes CVE briefs when IBM credentials are set; otherwise callers fall back to Gemini.

Env: IBM_WATSONX_APIKEY (IBM Cloud API key), IBM_WATSONX_PROJECT_ID (watsonx project), optional IBM_WATSONX_URL
(region; default Toronto, matching the datathon trial) and IBM_GRANITE_MODEL_ID.
"""
import json
import logging
import os
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger("Tell.Granite")
IAM_URL = "https://iam.cloud.ibm.com/identity/token"
DEFAULT_URL = "https://ca-tor.ml.cloud.ibm.com"
DEFAULT_MODEL = "ibm/granite-3-3-8b-instruct"
_token: Dict[str, Any] = {"value": None, "exp": 0.0}  # IAM tokens last ~60 min; reuse across requests

SYSTEM = (
    "You are IBM Granite writing a short vulnerability brief for a security engineer at Tell. "
    "Use only the JSON fields provided. Sections: Summary, Why it ranks high, Attack surface, Suggested next steps. "
    "If a field is null (CVSS, description), say it is not available. Never use severity words (critical, high, "
    "medium, low) unless cvss3_score is present, and then quote it. Never say a CVE will be exploited or give a "
    "likelihood; the rank is an ordering, not a probability. No dates or author lines. Under 200 words, Markdown."
)


def configured() -> bool:
    key, proj = os.environ.get("IBM_WATSONX_APIKEY", ""), os.environ.get("IBM_WATSONX_PROJECT_ID", "")
    return bool(key and proj) and not (key.startswith("your_") or proj.startswith("your_"))  # ignore template placeholders


def model_id() -> str:
    return os.environ.get("IBM_GRANITE_MODEL_ID", DEFAULT_MODEL)


def _iam_token() -> str:
    if _token["value"] and time.time() < _token["exp"] - 120:
        return _token["value"]
    r = requests.post(IAM_URL, timeout=10,
                      headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                      data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                            "apikey": os.environ["IBM_WATSONX_APIKEY"]})
    r.raise_for_status()
    j = r.json()
    _token.update(value=j["access_token"], exp=time.time() + int(j.get("expires_in", 3600)))
    return _token["value"]


def granite_brief(cve_context: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Brief from Granite, or None (not configured or any failure) so the caller can fall back."""
    if not configured():
        return None
    try:
        base = os.environ.get("IBM_WATSONX_URL", DEFAULT_URL).rstrip("/")
        r = requests.post(
            f"{base}/ml/v1/text/chat?version=2024-10-08", timeout=20,
            headers={"Authorization": f"Bearer {_iam_token()}", "Content-Type": "application/json",
                     "Accept": "application/json"},
            json={"model_id": model_id(), "project_id": os.environ["IBM_WATSONX_PROJECT_ID"],
                  "messages": [{"role": "system", "content": SYSTEM},
                               {"role": "user", "content": f"Vulnerability data: {json.dumps(cve_context)}"}],
                  "max_tokens": 500, "temperature": 0.2})
        if r.status_code != 200:
            logger.warning("watsonx returned %s: %s", r.status_code, r.text[:300])
            return None
        text = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
        return {"source": "IBM Granite on watsonx.ai (Live)", "model": model_id(), "content": text} if text else None
    except Exception as e:  # network, auth or shape errors: fall back, never break the page
        logger.warning("Granite brief failed (%s)", type(e).__name__)
        return None
