"""FastAPI webhook server for GitHub PR events."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from src.agent import DriftAgent
from src.config import settings
from src.github_client import GitHubClient
from src.models import DeploymentDecision

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

agent = DriftAgent()
github_client: GitHubClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
  global github_client
  if settings.github_token:
    try:
      github_client = GitHubClient()
      agent.pipeline.github = github_client
    except ValueError as exc:
      logger.warning("GitHub client not initialized: %s", exc)
  yield


app = FastAPI(
    title="Docker Image Drift Agent",
    description="LangChain agent for Dockerfile/K8s image drift detection on PRs",
    version="1.0.0",
    lifespan=lifespan,
)


class OnboardRequest(BaseModel):
  repo_full_name: str
  webhook_url: str


class AnalyzeRequest(BaseModel):
  repo_full_name: str
  pr_number: int


@app.get("/health")
def health() -> dict[str, str]:
  from src.trivy_scanner import TrivyScanner

  trivy = TrivyScanner()
  return {
      "status": "ok",
      "trivy": "available" if trivy.is_available() else "missing",
      "trivy_version": trivy.get_version(),
      "trivy_path": trivy.trivy_path,
  }


@app.get("/repos")
def list_repos() -> dict[str, Any]:
  if github_client is None:
    raise HTTPException(503, "GitHub client not configured")
  return {"repos": [r.model_dump() for r in github_client.list_onboarded_repos()]}


@app.post("/onboard")
def onboard_repo(req: OnboardRequest) -> dict[str, Any]:
  if github_client is None:
    raise HTTPException(503, "GitHub client not configured")
  repo = github_client.onboard_repo(req.repo_full_name, req.webhook_url)
  return {"status": "onboarded", "repo": repo.model_dump()}


@app.delete("/onboard/{owner}/{repo}")
def offboard_repo(owner: str, repo: str) -> dict[str, str]:
  if github_client is None:
    raise HTTPException(503, "GitHub client not configured")
  full_name = f"{owner}/{repo}"
  if github_client.offboard_repo(full_name):
    return {"status": "offboarded", "repo": full_name}
  raise HTTPException(404, f"Repo {full_name} not onboarded")


@app.post("/analyze")
def analyze_pr(req: AnalyzeRequest) -> dict[str, Any]:
  """Manually trigger PR analysis."""
  result = agent.run_pr(req.repo_full_name, req.pr_number)
  return result.model_dump()


@app.post("/webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> dict[str, Any]:
  """Handle GitHub webhook events (pull_request)."""
  payload = await request.body()

  if github_client and not github_client.verify_webhook_signature(payload, x_hub_signature_256):
    raise HTTPException(401, "Invalid webhook signature")

  event = await request.json()

  if x_github_event != "pull_request":
    return {"status": "ignored", "event": x_github_event}

  action = event.get("action", "")
  if action not in ("opened", "synchronize", "reopened", "edited"):
    return {"status": "ignored", "action": action}

  pr = event.get("pull_request", {})
  repo = event.get("repository", {})
  full_name = repo.get("full_name", "")
  pr_number = pr.get("number", 0)

  if github_client and not github_client.is_repo_onboarded(full_name):
    logger.info("Repo %s not onboarded, skipping", full_name)
    return {"status": "skipped", "reason": "repo not onboarded"}

  logger.info("Processing PR #%s on %s (action=%s)", pr_number, full_name, action)

  result = agent.run_pr(full_name, pr_number)

  if github_client and result.triggered:
    github_client.post_pr_comment(full_name, pr_number, result.pr_comment_markdown)

    status_map = {
        DeploymentDecision.APPROVE: "success",
        DeploymentDecision.WARN: "pending",
        DeploymentDecision.BLOCK: "failure",
    }
    head_sha = pr.get("head", {}).get("sha", "")
    if head_sha:
      github_client.set_commit_status(
          full_name,
          head_sha,
          status_map.get(result.decision, "pending"),
          f"Image drift: {result.decision.value}",
      )

  return {
      "status": "processed",
      "decision": result.decision.value,
      "triggered": result.triggered,
      "reports": len(result.reports),
  }
