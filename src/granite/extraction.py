"""
Structured and semantic feature extraction for ThreatRank.

Distinguishes strictly between:
1. Information directly supplied by the dataset (`structured_cvss`)
2. Information extracted by deterministic rules (`deterministic_rule`)
3. Information inferred by an optional IBM Granite instruction model (`granite_instruct`)
"""
import re
import logging
from typing import Optional
import pandas as pd

logger = logging.getLogger("ThreatRank.GraniteExtraction")

REMOTE_PATTERNS = [
    r"\bunauthenticated remote\b",
    r"\bremote attacker\b",
    r"\bremote attackers\b",
    r"\bremotely\b",
    r"\bremote code execution\b",
    r"\bover the network\b",
    r"\bnetwork-based\b",
    r"\bvia network\b",
    r"\bvia http\b",
    r"\bvia https\b",
    r"\bremote\b",
]

LOCAL_PATTERNS = [
    r"\blocal attacker\b",
    r"\blocal attackers\b",
    r"\blocal user\b",
    r"\blocal users\b",
    r"\blocally\b",
    r"\bon the local system\b",
    r"\bphysical access\b",
    r"\bphysically proximate\b",
    r"\blocal\b",
]

NO_AUTH_PATTERNS = [
    r"\bunauthenticated\b",
    r"\bwithout authentication\b",
    r"\bno authentication\b",
    r"\bwithout credentials\b",
    r"\bpre-auth\b",
    r"\bpre-authentication\b",
    r"\bauthentication bypass\b",
    r"\bbypass authentication\b",
]

AUTH_REQ_PATTERNS = [
    r"\bauthenticated attacker\b",
    r"\bauthenticated attackers\b",
    r"\bauthenticated user\b",
    r"\bauthenticated users\b",
    r"\brequires authentication\b",
    r"\bafter authenticating\b",
    r"\blogged-in user\b",
    r"\bprivileged user\b",
    r"\bwith admin privileges\b",
    r"\bwith administrator privileges\b",
]

VULN_TYPE_RULES = [
    ("Remote Code Execution / Command Injection", [
        r"\bremote code execution\b", r"\brce\b", r"\bcommand injection\b",
        r"\bos command\b", r"\bexecute arbitrary code\b", r"\barbitrary command execution\b",
    ]),
    ("Authentication Bypass & Improper Auth", [
        r"\bauthentication bypass\b", r"\bauth bypass\b", r"\bbypass authentication\b",
        r"\bimproper authentication\b", r"\bhardcoded credentials\b", r"\bdefault credentials\b",
    ]),
    ("Insecure Deserialization", [
        r"\bdeserialization\b", r"\bobject injection\b", r"\bunserialize\b",
    ]),
    ("Path Traversal & File Upload/Inclusion", [
        r"\bpath traversal\b", r"\bdirectory traversal\b", r"\bfile inclusion\b",
        r"\barbitrary file upload\b", r"\bunrestricted upload\b", r"\barbitrary file read\b",
        r"\barbitrary file write\b",
    ]),
    ("Server-Side Request Forgery (SSRF)", [
        r"\bserver-side request forgery\b", r"\bssrf\b",
    ]),
    ("SQL Injection", [
        r"\bsql injection\b", r"\bsqli\b",
    ]),
    ("Memory Corruption & Buffer Overflow", [
        r"\bbuffer overflow\b", r"\bheap-based buffer overflow\b", r"\bstack-based buffer overflow\b",
        r"\buse-after-free\b", r"\bout-of-bounds write\b", r"\bout-of-bounds read\b",
        r"\bmemory corruption\b", r"\binteger overflow\b",
    ]),
    ("Privilege Escalation", [
        r"\bprivilege escalation\b", r"\belevation of privilege\b", r"\bescalate privileges\b",
        r"\bgain elevated privileges\b",
    ]),
    ("Cross-Site Scripting (XSS) & Web Client", [
        r"\bcross-site scripting\b", r"\bxss\b", r"\bcross-site request forgery\b", r"\bcsrf\b",
    ]),
    ("Denial of Service (DoS)", [
        r"\bdenial of service\b", r"\bdenial-of-service\b", r"\bnull pointer dereference\b",
        r"\binfinite loop\b", r"\bresource consumption\b", r"\bapplication crash\b",
    ]),
    ("Information Disclosure & Access Control", [
        r"\binformation disclosure\b", r"\bsensitive information\b", r"\bexposure of sensitive\b",
        r"\bmissing authorization\b", r"\bimproper access control\b", r"\bidor\b",
    ]),
]

ATTACK_SURFACE_RULES = [
    ("Web / HTTP API", [r"\bweb application\b", r"\bhttp\b", r"\bhttps\b", r"\brest api\b", r"\bendpoint\b", r"\bservlet\b", r"\bwordpress\b", r"\bplugin\b"]),
    ("Network Service / Protocol", [r"\bnetwork service\b", r"\btcp\b", r"\budp\b", r"\bdns\b", r"\bsmb\b", r"\bssh\b", r"\btls\b", r"\bvpn\b", r"\bgateway\b", r"\brouter\b", r"\bfirewall\b"]),
    ("File / Document Parser", [r"\bcrafted file\b", r"\bmalformed file\b", r"\bpdf\b", r"\bimage\b", r"\bdocument\b", r"\barchive\b", r"\bzip\b"]),
    ("OS Kernel / Driver / Local Service", [r"\bkernel\b", r"\bdriver\b", r"\blocal service\b", r"\bdaemon\b", r"\bsystemd\b", r"\bwin32k\b"]),
    ("Database / Storage", [r"\bdatabase\b", r"\bsql\b", r"\bpostgres\b", r"\bmysql\b", r"\boracle\b", r"\bredis\b"]),
]


def _match_first_pattern(text_lower: str, patterns: list[str]) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, text_lower)
        if m:
            return m.group(0)
    return None


def extract_record_characteristics(
    description: str,
    attack_vector: object = None,
    privileges_required: object = None,
    cwe_ids: object = None,
    case_mode: str = "lower",
) -> dict[str, object]:
    """
    Extracts `remote_local`, `auth_required`, and optional metadata for a single CVE.

    Mapping rules (explicitly documented):
    - If structured CVSS `attack_vector` is present:
      - `NETWORK` or `ADJACENT_NETWORK` -> `remote` (documented assumption: network-reachable without local logon)
      - `LOCAL` or `PHYSICAL` -> `local`
      - `extraction_method` includes `structured_cvss`
    - Otherwise, deterministic regex rules check for unambiguous remote vs. local phrasing.
      If both or neither appear, returns `unknown` (never guesses).
    - If structured CVSS `privileges_required` is present:
      - `NONE` -> `no` (or `NONE` in upper mode)
      - `LOW` or `HIGH` -> `yes` (or `REQUIRED` in upper mode)
    - Otherwise, deterministic regex rules check for unauthenticated vs. authenticated phrasing.
    """
    desc_str = "" if pd.isna(description) else str(description).strip()
    desc_lower = desc_str.lower()

    av_str = "" if pd.isna(attack_vector) else str(attack_vector).strip().upper()
    pr_str = "" if pd.isna(privileges_required) else str(privileges_required).strip().upper()

    methods_used = []
    evidence_parts = []

    # 1. remote_local
    loc_val = "unknown"
    if av_str in ("NETWORK", "ADJACENT_NETWORK", "ADJACENT"):
        loc_val = "remote"
        methods_used.append("structured_cvss")
        evidence_parts.append(f"cvss:attack_vector={av_str}")
    elif av_str in ("LOCAL", "PHYSICAL"):
        loc_val = "local"
        methods_used.append("structured_cvss")
        evidence_parts.append(f"cvss:attack_vector={av_str}")
    else:
        rem_hit = _match_first_pattern(desc_lower, REMOTE_PATTERNS)
        loc_hit = _match_first_pattern(desc_lower, LOCAL_PATTERNS)
        if rem_hit and not loc_hit:
            loc_val = "remote"
            methods_used.append("deterministic_rule")
            evidence_parts.append(f"text:'{rem_hit}'")
        elif loc_hit and not rem_hit:
            loc_val = "local"
            methods_used.append("deterministic_rule")
            evidence_parts.append(f"text:'{loc_hit}'")

    # 2. auth_required
    auth_val = "unknown"
    if pr_str == "NONE":
        auth_val = "no"
        if "structured_cvss" not in methods_used:
            methods_used.append("structured_cvss")
        evidence_parts.append("cvss:privileges_required=NONE")
    elif pr_str in ("LOW", "HIGH"):
        auth_val = "yes"
        if "structured_cvss" not in methods_used:
            methods_used.append("structured_cvss")
        evidence_parts.append(f"cvss:privileges_required={pr_str}")
    else:
        no_auth_hit = _match_first_pattern(desc_lower, NO_AUTH_PATTERNS)
        req_auth_hit = _match_first_pattern(desc_lower, AUTH_REQ_PATTERNS)
        if no_auth_hit and not req_auth_hit:
            auth_val = "no"
            if "deterministic_rule" not in methods_used:
                methods_used.append("deterministic_rule")
            evidence_parts.append(f"text:'{no_auth_hit}'")
        elif req_auth_hit and not no_auth_hit:
            auth_val = "yes"
            if "deterministic_rule" not in methods_used:
                methods_used.append("deterministic_rule")
            evidence_parts.append(f"text:'{req_auth_hit}'")

    # 3. vulnerability_type
    vuln_type = "unknown"
    for label, pats in VULN_TYPE_RULES:
        hit = _match_first_pattern(desc_lower, pats)
        if hit:
            vuln_type = label
            if "deterministic_rule" not in methods_used:
                methods_used.append("deterministic_rule")
            break

    # 4. attack_surface
    surface = "unknown"
    for s_label, pats in ATTACK_SURFACE_RULES:
        if _match_first_pattern(desc_lower, pats):
            surface = s_label
            break

    # Extraction method & confidence
    if not methods_used:
        method_str = "none"
        confidence = "low"
    elif "structured_cvss" in methods_used and len(methods_used) == 1:
        method_str = "structured_cvss"
        confidence = "high"
    elif "structured_cvss" in methods_used and "deterministic_rule" in methods_used:
        method_str = "structured_cvss+deterministic_rule"
        confidence = "high"
    else:
        method_str = "deterministic_rule"
        confidence = "medium" if (loc_val != "unknown" or auth_val != "unknown") else "low"

    if case_mode == "upper":
        loc_out = loc_val.upper()
        auth_map_upper = {"no": "NONE", "yes": "REQUIRED", "unknown": "UNKNOWN"}
        auth_out = auth_map_upper[auth_val]
    else:
        loc_out = loc_val
        auth_out = auth_val

    return {
        "remote_local": loc_out,
        "auth_required": auth_out,
        "vulnerability_type": vuln_type,
        "attack_surface": surface,
        "extraction_method": method_str,
        "extraction_confidence": confidence,
        "evidence": "; ".join(evidence_parts) if evidence_parts else "none",
    }


def extract_features_dataframe(
    df: pd.DataFrame,
    case_mode: str = "lower",
) -> pd.DataFrame:
    """Applies transparent feature extraction across a vulnerability DataFrame."""
    has_av = "attack_vector" in df.columns
    has_pr = "privileges_required" in df.columns
    has_cwe = "cwe_ids" in df.columns

    records = []
    for row in df.itertuples(index=False):
        desc = getattr(row, "description", "")
        av = getattr(row, "attack_vector", None) if has_av else None
        pr = getattr(row, "privileges_required", None) if has_pr else None
        cwe = getattr(row, "cwe_ids", None) if has_cwe else None
        ext = extract_record_characteristics(
            description=desc,
            attack_vector=av,
            privileges_required=pr,
            cwe_ids=cwe,
            case_mode=case_mode,
        )
        records.append(ext)

    ext_df = pd.DataFrame(records, index=df.index)
    out = df.copy()
    for col in ext_df.columns:
        out[col] = ext_df[col]
    return out
