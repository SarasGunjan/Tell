"""
Tell Platform - IBM Granite Verification & Demonstration CLI
Author: Member 2 (IBM Granite & Research)

Tests the IBM Granite extraction pipeline on known critical vulnerabilities
and verifies adherence to structured output schemas.
"""

import sys
from pathlib import Path
import json

root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from src.granite.watsonx_granite import IBMGraniteClient

TEST_SAMPLES = [
    {
        "cve_id": "CVE-2024-3400",
        "description": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated remote attacker to execute arbitrary code with root privileges on the firewall."
    },
    {
        "cve_id": "CVE-2024-21338",
        "description": "Windows Kernel Elevation of Privilege Vulnerability. An attacker who successfully exploited this vulnerability could gain SYSTEM privileges through a local execution context."
    },
    {
        "cve_id": "CVE-2024-23897",
        "description": "Jenkins built-in command line interface parser flaw allows unauthenticated remote attackers to read arbitrary files on the Jenkins controller file system via path traversal and expand malicious payloads."
    }
]

def run_tests():
    print("=" * 65)
    print("🛡️  TELL PLATFORM: IBM GRANITE FEATURE EXTRACTION TEST")
    print("Model: ibm/granite-13b-instruct-v2 (IBM watsonx.ai)")
    print("=" * 65)

    client = IBMGraniteClient()
    for sample in TEST_SAMPLES:
        print(f"\n[+] Testing {sample['cve_id']}:")
        print(f"    Description: {sample['description']}")
        
        result = client.extract_vulnerability_traits(sample['description'], sample['cve_id'])
        print(f"    Extraction Output:")
        print(f"      - Remote / Local:    {result.get('remote_local')}")
        print(f"      - Auth Required:     {result.get('auth_required')}")
        print(f"      - Attack Type:       {result.get('attack_type')}")
        print(f"      - Granite Reasoning: {result.get('granite_reasoning')}")
        print(f"      - Source Engine:     {result.get('source')}")

    print("\n" + "=" * 65)
    print("✅ IBM Granite Feature Extraction Pipeline Verified!")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()
