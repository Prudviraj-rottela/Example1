"""Core analysis pipeline for image drift detection."""

from __future__ import annotations

import logging

from src.diff_detector import detect_image_changes_from_diff
from src.github_client import GitHubClient
from src.models import DeploymentDecision, ImageAnalysisReport, PrAnalysisResult
from src.patch_generator import assemble_pr_result, generate_patch_snippet
from src.policy_engine import PolicyEngine
from src.trivy_scanner import TrivyScanner

logger = logging.getLogger(__name__)


class AnalysisPipeline:
  def __init__(
      self,
      trivy: TrivyScanner | None = None,
      policy: PolicyEngine | None = None,
      github: GitHubClient | None = None,
  ):
    self.trivy = trivy or TrivyScanner()
    self.policy = policy or PolicyEngine()
    self.github = github

  def analyze_diff(
      self,
      diff_text: str,
      repo_full_name: str = "",
      pr_number: int = 0,
      pr_url: str = "",
  ) -> PrAnalysisResult:
    changes = detect_image_changes_from_diff(diff_text)
    if not changes:
      return PrAnalysisResult(
          repo_full_name=repo_full_name,
          pr_number=pr_number,
          pr_url=pr_url,
          triggered=False,
          decision=DeploymentDecision.APPROVE,
          pr_comment_markdown="No Dockerfile or Kubernetes image changes detected.",
      )

    reports: list[ImageAnalysisReport] = []
    for change in changes:
      image_ref = change.new_image.display
      logger.info("Scanning image %s from %s with Trivy", image_ref, change.file_path)

      trivy_result = self.trivy.scan_image(image_ref)

      # Enrich SBOM via CycloneDX when primary scan succeeds
      if trivy_result.success:
        sbom_result = self.trivy.scan_sbom(image_ref)
        if sbom_result.success and sbom_result.sbom_packages > trivy_result.sbom_packages:
          trivy_result.sbom_packages = sbom_result.sbom_packages
          trivy_result.raw_summary["sbom_format"] = "cyclonedx"

      policy_result = self.policy.evaluate(change.new_image, trivy_result)
      patch = generate_patch_snippet(change, policy_result)

      reports.append(
          ImageAnalysisReport(
              change=change,
              trivy=trivy_result,
              policy=policy_result,
              patch_snippet=patch,
          )
      )

    return assemble_pr_result(repo_full_name, pr_number, pr_url, reports)

  def analyze_pr(self, full_name: str, pr_number: int) -> PrAnalysisResult:
    if self.github is None:
      raise ValueError("GitHub client required for PR analysis")

    pr_info = self.github.get_pr_info(full_name, pr_number)
    diff_text = self.github.get_pr_diff(full_name, pr_number)
    result = self.analyze_diff(
        diff_text,
        repo_full_name=full_name,
        pr_number=pr_number,
        pr_url=pr_info["url"],
    )
    return result
