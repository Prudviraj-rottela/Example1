#!/usr/bin/env python3
"""CI entry point — runs in GitHub Actions on pull_request events."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Vendored agent root: .github/docker-image-drift-agent/
AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AGENT_ROOT))

from src.agent import DriftAgent  # noqa: E402
from src.github_client import GitHubClient  # noqa: E402
from src.models import DeploymentDecision  # noqa: E402


def main() -> int:
    repo = os.environ.get("REPO_FULL_NAME") or os.environ.get("GITHUB_REPOSITORY", "")
    pr_number = int(os.environ.get("PR_NUMBER", "0"))
    token = os.environ.get("GITHUB_TOKEN", "")

    if not repo or not pr_number:
        print("REPO_FULL_NAME and PR_NUMBER are required", file=sys.stderr)
        return 1
    if not token:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 1

    # Point config paths at vendored copies
    os.environ.setdefault("GOLDEN_IMAGES_PATH", str(AGENT_ROOT / "config" / "golden_images.yaml"))
    os.environ.setdefault("SIGNATURE_POLICY_PATH", str(AGENT_ROOT / "config" / "signature_policy.yaml"))
    os.environ.setdefault("TRIVY_PATH", "trivy")

    agent = DriftAgent()
    agent.pipeline.github = GitHubClient(token=token)
    result = agent.run_pr(repo, pr_number)

    if not result.triggered:
        print("No image changes detected — skipping comment.")
        return 0

    client = GitHubClient(token=token)
    client.post_pr_comment(repo, pr_number, result.pr_comment_markdown)

    head_sha = os.environ.get("PR_HEAD_SHA", "")
    if head_sha:
        status_map = {
            DeploymentDecision.APPROVE: "success",
            DeploymentDecision.WARN: "pending",
            DeploymentDecision.BLOCK: "failure",
        }
        client.set_commit_status(
            repo,
            head_sha,
            status_map.get(result.decision, "pending"),
            f"Image drift: {result.decision.value}",
        )

    print(f"Decision: {result.decision.value}")
    print(result.pr_comment_markdown)

    if result.decision == DeploymentDecision.BLOCK:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
