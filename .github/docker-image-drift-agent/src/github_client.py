"""GitHub API client for repo onboarding and PR analysis."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from github import Auth, Github, GithubException

from src.config import settings
from src.models import OnboardedRepo

logger = logging.getLogger(__name__)


class GitHubClient:
  def __init__(self, token: str | None = None):
    self.token = token or settings.github_token
    if not self.token:
      raise ValueError("GITHUB_TOKEN is required")
    self._gh = Github(auth=Auth.Token(self.token))
    self._repos_path = Path(settings.onboarded_repos_path)

  def verify_webhook_signature(self, payload: bytes, signature_header: str | None) -> bool:
    secret = settings.github_webhook_secret
    if not secret:
      logger.warning("GITHUB_WEBHOOK_SECRET not set; skipping signature verification")
      return True
    if not signature_header:
      return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)

  def _load_onboarded(self) -> dict[str, Any]:
    if not self._repos_path.exists():
      return {"repos": []}
    return json.loads(self._repos_path.read_text(encoding="utf-8"))

  def _save_onboarded(self, data: dict[str, Any]) -> None:
    self._repos_path.parent.mkdir(parents=True, exist_ok=True)
    self._repos_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

  def list_onboarded_repos(self) -> list[OnboardedRepo]:
    data = self._load_onboarded()
    return [OnboardedRepo(**r) for r in data.get("repos", [])]

  def is_repo_onboarded(self, full_name: str) -> bool:
    return any(
        r.full_name == full_name and r.enabled
        for r in self.list_onboarded_repos()
    )

  def onboard_repo(
      self,
      full_name: str,
      webhook_url: str,
      events: list[str] | None = None,
  ) -> OnboardedRepo:
    """Register a repo for PR monitoring and persist onboarding state."""
    events = events or ["pull_request"]
    owner, repo_name = full_name.split("/", 1)
    repo = self._gh.get_repo(full_name)

    config: dict[str, Any] = {
        "url": webhook_url,
        "content_type": "json",
    }
    if settings.github_webhook_secret:
      config["secret"] = settings.github_webhook_secret

    hook = repo.create_hook("web", config, events=events, active=True)

    onboarded = OnboardedRepo(
        full_name=full_name,
        default_branch=repo.default_branch,
        webhook_id=hook.id,
        onboarded_at=datetime.now(timezone.utc).isoformat(),
        enabled=True,
    )

    data = self._load_onboarded()
    repos = [r for r in data.get("repos", []) if r.get("full_name") != full_name]
    repos.append(onboarded.model_dump())
    data["repos"] = repos
    self._save_onboarded(data)

    logger.info("Onboarded repo %s with webhook %s", full_name, hook.id)
    return onboarded

  def offboard_repo(self, full_name: str) -> bool:
    data = self._load_onboarded()
    repos = data.get("repos", [])
    target = next((r for r in repos if r.get("full_name") == full_name), None)
    if not target:
      return False

    if target.get("webhook_id"):
      try:
        owner, repo_name = full_name.split("/", 1)
        repo = self._gh.get_repo(full_name)
        hook = repo.get_hook(target["webhook_id"])
        hook.delete()
      except GithubException as exc:
        logger.warning("Failed to delete webhook for %s: %s", full_name, exc)

    data["repos"] = [r for r in repos if r.get("full_name") != full_name]
    self._save_onboarded(data)
    return True

  def get_pr_diff(self, full_name: str, pr_number: int) -> str:
    repo = self._gh.get_repo(full_name)
    pr = repo.get_pull(pr_number)
    files = pr.get_files()
    diff_parts: list[str] = []
    for f in files:
      if f.patch:
        diff_parts.append(f"diff --git a/{f.filename} b/{f.filename}\n")
        diff_parts.append(f"+++ b/{f.filename}\n")
        diff_parts.append(f.patch)
        diff_parts.append("")
    return "\n".join(diff_parts)

  def get_pr_info(self, full_name: str, pr_number: int) -> dict[str, Any]:
    repo = self._gh.get_repo(full_name)
    pr = repo.get_pull(pr_number)
    return {
        "number": pr.number,
        "title": pr.title,
        "url": pr.html_url,
        "state": pr.state,
        "head_sha": pr.head.sha,
        "base_branch": pr.base.ref,
    }

  def post_pr_comment(self, full_name: str, pr_number: int, body: str) -> int:
    repo = self._gh.get_repo(full_name)
    pr = repo.get_pull(pr_number)
    comment = pr.create_issue_comment(body)
    return comment.id

  def set_commit_status(
      self,
      full_name: str,
      sha: str,
      state: str,
      description: str,
      context: str = "docker-image-drift-agent",
  ) -> None:
    repo = self._gh.get_repo(full_name)
    repo.get_commit(sha).create_status(
        state=state,
        description=description[:140],
        context=context,
    )
