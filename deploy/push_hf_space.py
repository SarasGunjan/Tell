"""Deploy Tell to a free Hugging Face Docker Space.

One-time: create a free account at huggingface.co, then sign in on this machine:
    .venv/bin/hf auth login          (paste a token with "write" access when asked)
Deploy or update:
    .venv/bin/python deploy/push_hf_space.py [owner/space-name]   (default: <you>/tell)
Gemini key: add it yourself under the Space's Settings -> Variables and secrets -> New secret
GEMINI_API_KEY. Never commit it.
"""
import shutil
import sys
import tempfile
from pathlib import Path

from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parents[1]
CARD = """---
title: Tell
emoji: 🛰️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 8000
pinned: false
short_description: Every attack has a tell. CVE exploit-risk ranking for 2026.
---

Tell ranks 2026 CVEs by exploit risk. Source: https://github.com/SarasGunjan/Tell
"""
JUNK = shutil.ignore_patterns("node_modules", "dist", "__pycache__", "*.pyc", ".DS_Store", "mvp_100")


def stage(dst: Path) -> None:
    shutil.copy(ROOT / "deploy" / "Dockerfile", dst / "Dockerfile")  # Spaces build the root Dockerfile
    (dst / "README.md").write_text(CARD)
    (dst / "deploy").mkdir()
    shutil.copy(ROOT / "deploy" / "requirements-web.txt", dst / "deploy")
    (dst / "src").mkdir()
    shutil.copy(ROOT / "src" / "__init__.py", dst / "src")
    for d in ("src/api", "src/ai", "results", "outputs/granite", "web"):
        shutil.copytree(ROOT / d, dst / d, ignore=JUNK)


def main() -> None:
    api = HfApi()
    space = sys.argv[1] if len(sys.argv) > 1 else f"{api.whoami()['name']}/tell"
    api.create_repo(space, repo_type="space", space_sdk="docker", exist_ok=True)
    api.add_space_variable(space, "TELL_DATA_LABEL", "final")
    with tempfile.TemporaryDirectory() as tmp:
        stage(Path(tmp))
        # delete_patterns drops remote files that no longer exist locally; uploaded ones are kept
        api.upload_folder(folder_path=tmp, repo_id=space, repo_type="space",
                          delete_patterns=["*"], commit_message="Deploy Tell")
    owner, name = space.split("/")
    print(f"Pushed. Build logs: https://huggingface.co/spaces/{space}")
    print(f"Live app (after the build, ~3-5 min): https://{owner}-{name}.hf.space".lower())


if __name__ == "__main__":
    main()
