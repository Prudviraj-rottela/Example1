"""Onboard repos via GitHub Actions (no ngrok / webhooks required)."""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from src.config import ROOT, settings
from src.github_client import GitHubClient
from src.models import OnboardedRepo

logger = logging.getLogger(__name__)

VENDOR_ROOT = ".github/docker-image-drift-agent"
WORKFLOW_PATH = ".github/workflows/docker-image-drift-agent.yml"

# Files vendored into each onboarded repo for self-contained CI runs
VENDOR_DIRS = ["src", "config", "scripts"]
VENDOR_FILES = ["requirements.txt"]


def _read_template() -> str:
    return (ROOT / "templates" / "github-actions-workflow.yml").read_text(encoding="utf-8")


def _collect_vendor_files() -> dict[str, str]:
    """Return {repo_relative_path: content} for all vendored agent files."""
    files: dict[str, str] = {}

    for name in VENDOR_FILES:
        src = ROOT / name
        if src.exists():
            files[f"{VENDOR_ROOT}/{name}"] = src.read_text(encoding="utf-8")

    for dirname in VENDOR_DIRS:
        src_dir = ROOT / dirname
        if not src_dir.exists():
            continue
        for path in src_dir.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                rel = path.relative_to(ROOT)
                files[f"{VENDOR_ROOT}/{rel.as_posix()}"] = path.read_text(encoding="utf-8")

    return files


def onboard_repo_actions(
    client: GitHubClient,
    full_name: str,
    branch: str | None = None,
) -> OnboardedRepo:
    """Install GitHub Actions workflow + vendored agent into target repo."""
    repo = client._gh.get_repo(full_name)
    branch = branch or repo.default_branch

    workflow_content = _read_template()
    vendor_files = _collect_vendor_files()

    commits: list[tuple[str, str]] = [
        (WORKFLOW_PATH, workflow_content),
        *sorted(vendor_files.items()),
    ]

    for path, content in commits:
        _upsert_file(client, full_name, path, content, branch, f"Add {path} for Docker Image Drift Agent")

    onboarded = OnboardedRepo(
        full_name=full_name,
        default_branch=branch,
        webhook_id=None,
        onboarded_at=datetime.now(timezone.utc).isoformat(),
        enabled=True,
    )

    data = client._load_onboarded()
    repos = [r for r in data.get("repos", []) if r.get("full_name") != full_name]
    entry = onboarded.model_dump()
    entry["mode"] = "github_actions"
    repos.append(entry)
    data["repos"] = repos
    client._save_onboarded(data)

    logger.info("Onboarded %s via GitHub Actions", full_name)
    return onboarded


def _upsert_file(
    client: GitHubClient,
    full_name: str,
    path: str,
    content: str,
    branch: str,
    message: str,
) -> None:
    repo = client._gh.get_repo(full_name)
    try:
        existing = repo.get_contents(path, ref=branch)
        repo.update_file(path, message, content, existing.sha, branch=branch)
    except Exception:
        repo.create_file(path, message, content, branch=branch)
