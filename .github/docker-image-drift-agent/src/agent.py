"""LangChain agent for Docker image drift analysis."""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from src.config import settings
from src.models import DeploymentDecision, PrAnalysisResult
from src.pipeline import AnalysisPipeline
from src.patch_generator import build_report_markdown

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Docker Image Drift Agent — an enterprise security assistant.

Your job when a GitHub PR changes container base images:
1. Detect Dockerfile FROM line or Kubernetes image field changes
2. Scan new images with Trivy (CVEs, misconfigurations, secrets, SBOM)
3. Validate against the golden-image catalog and signature policy
4. Recommend an approved digest or block the PR

Always be precise about:
- Whether the image is vulnerable, unsigned, unpinned, or not approved
- Non-root user recommendations
- A minimal patch with approved digest when available

Use the provided tools to gather facts before making a deployment decision.
"""


def _build_tools(pipeline: AnalysisPipeline) -> list:
  @tool
  def detect_image_changes(diff_text: str) -> str:
    """Detect Dockerfile FROM or Kubernetes image field changes in a PR unified diff."""
    from src.diff_detector import detect_image_changes_from_diff

    changes = detect_image_changes_from_diff(diff_text)
    return json.dumps([c.model_dump() for c in changes], default=str)

  @tool
  def trivy_scan_image(image_reference: str) -> str:
    """Run Trivy scan on a container image for CVEs, misconfigurations, secrets, and SBOM."""
    result = pipeline.trivy.scan_image(image_reference)
    return result.model_dump_json()

  @tool
  def check_golden_image_policy(image_json: str, trivy_json: str) -> str:
    """Check image against golden catalog and signature policy. Pass image and trivy as JSON strings."""
    from src.models import ImageReference, TrivyScanResult

    image = ImageReference(**json.loads(image_json))
    trivy = TrivyScanResult(**json.loads(trivy_json))
    result = pipeline.policy.evaluate(image, trivy)
    return result.model_dump_json()

  @tool
  def analyze_pr_diff(
      diff_text: str,
      repo_full_name: str = "",
      pr_number: int = 0,
      pr_url: str = "",
  ) -> str:
    """Full pipeline: detect changes, Trivy scan, policy check, and generate patch suggestions."""
    result = pipeline.analyze_diff(diff_text, repo_full_name, pr_number, pr_url)
    return result.model_dump_json()

  return [detect_image_changes, trivy_scan_image, check_golden_image_policy, analyze_pr_diff]


class DriftAgent:
  """LangChain ReAct agent for image drift analysis."""

  def __init__(self, pipeline: AnalysisPipeline | None = None):
    self.pipeline = pipeline or AnalysisPipeline()
    self._agent = None

  def _get_llm(self):
    if not settings.openai_api_key or settings.openai_api_key.startswith("sk-your"):
      return None
    if not self._openai_key_works():
      return None
    return ChatOpenAI(model=settings.openai_model, api_key=settings.openai_api_key, temperature=0)

  def _openai_key_works(self) -> bool:
    if getattr(self, "_openai_key_valid", None) is not None:
      return self._openai_key_valid
    try:
      from openai import OpenAI

      client = OpenAI(api_key=settings.openai_api_key)
      client.chat.completions.create(
          model=settings.openai_model,
          messages=[{"role": "user", "content": "ping"}],
          max_tokens=1,
      )
      self._openai_key_valid = True
    except Exception as exc:
      logger.warning("OpenAI API key not usable, using rule-based summary: %s", exc)
      self._openai_key_valid = False
    return self._openai_key_valid

  def _get_agent(self):
    if self._agent is not None:
      return self._agent
    llm = self._get_llm()
    if llm is None:
      return None
    tools = _build_tools(self.pipeline)
    self._agent = create_react_agent(llm, tools)
    return self._agent

  def run(
      self,
      diff_text: str,
      repo_full_name: str = "",
      pr_number: int = 0,
      pr_url: str = "",
      pr_title: str = "",
  ) -> PrAnalysisResult:
    """Run analysis: deterministic pipeline + optional LLM summary."""
    result = self.pipeline.analyze_diff(
        diff_text, repo_full_name, pr_number, pr_url
    )

    if not result.triggered:
      return result

    agent = self._get_agent()
    if agent is None:
      result.agent_summary = self._rule_based_summary(result)
      result.pr_comment_markdown = build_report_markdown(result)
      return result

    prompt = (
        f"Analyze this PR for container image drift.\n"
        f"Repo: {repo_full_name}\nPR #{pr_number}: {pr_title}\nURL: {pr_url}\n\n"
        f"Use analyze_pr_diff with the diff below, then provide a concise "
        f"deployment recommendation (approve/warn/block).\n\n"
        f"```diff\n{diff_text[:12000]}\n```"
    )

    try:
      response = agent.invoke(
          {"messages": [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)]}
      )
      last_msg = response["messages"][-1]
      result.agent_summary = last_msg.content if hasattr(last_msg, "content") else str(last_msg)
    except Exception as exc:
      logger.exception("LangChain agent failed, using rule-based summary")
      result.agent_summary = self._rule_based_summary(result) + f"\n\n_Agent error: {exc}_"

    result.pr_comment_markdown = build_report_markdown(result)
    return result

  def run_pr(self, full_name: str, pr_number: int) -> PrAnalysisResult:
    from src.github_client import GitHubClient

    github = self.pipeline.github or GitHubClient()
    self.pipeline.github = github
    pr_info = github.get_pr_info(full_name, pr_number)
    diff_text = github.get_pr_diff(full_name, pr_number)
    return self.run(
        diff_text,
        repo_full_name=full_name,
        pr_number=pr_number,
        pr_url=pr_info["url"],
        pr_title=pr_info["title"],
    )

  @staticmethod
  def _rule_based_summary(result: PrAnalysisResult) -> str:
    if not result.reports:
      return "No image changes detected."

    lines = [
        f"Analyzed {len(result.reports)} image change(s).",
        f"**Decision: {result.decision.value.upper()}**",
        "",
    ]
    for report in result.reports:
      img = report.change.new_image.display
      lines.append(f"- `{img}`: {report.policy.decision.value}")
      if report.policy.recommended_image:
        lines.append(f"  - Recommended: `{report.policy.recommended_image}`")
      if report.policy.violations:
        for v in report.policy.violations[:3]:
          lines.append(f"  - Violation: {v}")
    return "\n".join(lines)

  def invoke_agent_chat(self, message: str) -> str:
    """Free-form agent interaction for debugging."""
    agent = self._get_agent()
    if agent is None:
      return "OpenAI API key not configured. Set OPENAI_API_KEY to enable the LangChain agent."
    response = agent.invoke(
        {"messages": [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=message)]}
    )
    last = response["messages"][-1]
    return last.content if hasattr(last, "content") else str(last)
