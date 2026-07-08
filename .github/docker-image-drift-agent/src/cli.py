"""CLI for Docker Image Drift Agent."""

from __future__ import annotations

import argparse
import json
import sys

from src.actions_onboard import onboard_repo_actions
from src.agent import DriftAgent
from src.config import settings
from src.github_client import GitHubClient


def cmd_onboard(args: argparse.Namespace) -> None:
  client = GitHubClient()
  webhook_url = args.webhook_url or f"http://{settings.host}:{settings.port}/webhook"
  repo = client.onboard_repo(args.repo, webhook_url)
  print(json.dumps(repo.model_dump(), indent=2))


def cmd_offboard(args: argparse.Namespace) -> None:
  client = GitHubClient()
  if client.offboard_repo(args.repo):
    print(f"Offboarded {args.repo}")
  else:
    print(f"Repo {args.repo} was not onboarded", file=sys.stderr)
    sys.exit(1)


def cmd_list(args: argparse.Namespace) -> None:
  client = GitHubClient()
  repos = client.list_onboarded_repos()
  print(json.dumps([r.model_dump() for r in repos], indent=2))


def cmd_analyze_pr(args: argparse.Namespace) -> None:
  agent = DriftAgent()
  result = agent.run_pr(args.repo, args.pr_number)
  if args.output == "markdown":
    print(result.pr_comment_markdown)
  else:
    print(json.dumps(result.model_dump(), indent=2, default=str))


def cmd_analyze_diff(args: argparse.Namespace) -> None:
  diff_text = open(args.diff_file, encoding="utf-8").read()
  agent = DriftAgent()
  result = agent.run(diff_text, repo_full_name=args.repo or "local/test", pr_number=0)
  if args.output == "markdown":
    print(result.pr_comment_markdown)
  else:
    print(json.dumps(result.model_dump(), indent=2, default=str))


def cmd_onboard_actions(args: argparse.Namespace) -> None:
  client = GitHubClient()
  repo = onboard_repo_actions(client, args.repo)
  print(json.dumps(repo.model_dump(), indent=2))
  print(
      "\nGitHub Actions onboarding complete. No ngrok/webhook needed.\n"
      "Optional: add OPENAI_API_KEY to repo Secrets for LLM summaries.\n"
      "Open a PR that changes a Dockerfile or k8s image field to trigger the agent."
  )


def cmd_serve(args: argparse.Namespace) -> None:
  import uvicorn

  uvicorn.run(
      "src.webhook_server:app",
      host=settings.host,
      port=settings.port,
      reload=args.reload,
  )


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Docker Image Drift Agent — LangChain + Trivy + GitHub PR monitoring"
  )
  sub = parser.add_subparsers(dest="command", required=True)

  p_onboard = sub.add_parser("onboard", help="Onboard via GitHub webhook (needs public URL)")
  p_onboard.add_argument("repo", help="owner/repo")
  p_onboard.add_argument("--webhook-url", help="Public webhook URL for GitHub")
  p_onboard.set_defaults(func=cmd_onboard)

  p_onboard_actions = sub.add_parser(
      "onboard-actions",
      help="Onboard via GitHub Actions (recommended — no ngrok needed)",
  )
  p_onboard_actions.add_argument("repo", help="owner/repo")
  p_onboard_actions.set_defaults(func=cmd_onboard_actions)

  p_offboard = sub.add_parser("offboard", help="Remove repo from monitoring")
  p_offboard.add_argument("repo", help="owner/repo")
  p_offboard.set_defaults(func=cmd_offboard)

  p_list = sub.add_parser("list", help="List onboarded repos")
  p_list.set_defaults(func=cmd_list)

  p_pr = sub.add_parser("analyze-pr", help="Analyze a GitHub PR")
  p_pr.add_argument("repo", help="owner/repo")
  p_pr.add_argument("pr_number", type=int)
  p_pr.add_argument("--output", choices=["json", "markdown"], default="markdown")
  p_pr.set_defaults(func=cmd_analyze_pr)

  p_diff = sub.add_parser("analyze-diff", help="Analyze a local diff file")
  p_diff.add_argument("diff_file", help="Path to unified diff file")
  p_diff.add_argument("--repo", default="local/test")
  p_diff.add_argument("--output", choices=["json", "markdown"], default="markdown")
  p_diff.set_defaults(func=cmd_analyze_diff)

  p_serve = sub.add_parser("serve", help="Start webhook server")
  p_serve.add_argument("--reload", action="store_true")
  p_serve.set_defaults(func=cmd_serve)

  args = parser.parse_args()
  args.func(args)


if __name__ == "__main__":
  main()
