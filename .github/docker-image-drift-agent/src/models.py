"""Pydantic models for the Docker Image Drift Agent."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ImageSource(str, Enum):
    DOCKERFILE = "dockerfile"
    KUBERNETES = "kubernetes"


class DeploymentDecision(str, Enum):
    APPROVE = "approve"
    BLOCK = "block"
    WARN = "warn"


class ImageReference(BaseModel):
    raw: str
    repository: str
    tag: str | None = None
    digest: str | None = None
    is_pinned: bool = False

    @property
    def display(self) -> str:
        if self.digest:
            base = f"{self.repository}@{self.digest}"
        elif self.tag:
            base = f"{self.repository}:{self.tag}"
        else:
            base = self.repository
        return base


class ImageChange(BaseModel):
    source: ImageSource
    file_path: str
    line_number: int | None = None
    old_image: ImageReference | None = None
    new_image: ImageReference
    context_line: str = ""


class CveFinding(BaseModel):
    vulnerability_id: str
    severity: str
    package: str
    installed_version: str | None = None
    fixed_version: str | None = None
    title: str | None = None


class TrivyScanResult(BaseModel):
    image: str
    success: bool
    error: str | None = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    cves: list[CveFinding] = Field(default_factory=list)
    misconfigurations: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)
    sbom_packages: int = 0
    raw_summary: dict[str, Any] = Field(default_factory=dict)


class SignatureStatus(str, Enum):
    SIGNED = "signed"
    UNSIGNED = "unsigned"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"
    INVALID = "invalid"


class PolicyCheckResult(BaseModel):
    image: ImageReference
    in_golden_catalog: bool
    approved: bool
    is_pinned: bool
    signature_status: SignatureStatus
    signature_detail: str = ""
    recommended_digest: str | None = None
    recommended_image: str | None = None
    violations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    non_root_recommended: bool = False
    decision: DeploymentDecision = DeploymentDecision.WARN


class ImageAnalysisReport(BaseModel):
    change: ImageChange
    trivy: TrivyScanResult
    policy: PolicyCheckResult
    patch_snippet: str = ""
    agent_summary: str = ""


class PrAnalysisResult(BaseModel):
    repo_full_name: str
    pr_number: int
    pr_url: str
    triggered: bool
    decision: DeploymentDecision
    reports: list[ImageAnalysisReport] = Field(default_factory=list)
    pr_comment_markdown: str = ""
    agent_summary: str = ""
    block_reasons: list[str] = Field(default_factory=list)


class OnboardedRepo(BaseModel):
    full_name: str
    default_branch: str = "main"
    webhook_id: int | None = None
    onboarded_at: str = ""
    enabled: bool = True
