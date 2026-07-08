"""Golden-image catalog and signature policy enforcement."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from src.config import settings
from src.models import (
    DeploymentDecision,
    ImageReference,
    PolicyCheckResult,
    SignatureStatus,
    TrivyScanResult,
)

logger = logging.getLogger(__name__)


class PolicyEngine:
  def __init__(
      self,
      golden_images_path: str | None = None,
      signature_policy_path: str | None = None,
      cosign_path: str | None = None,
  ):
    self.golden_images_path = Path(golden_images_path or settings.golden_images_path)
    self.signature_policy_path = Path(signature_policy_path or settings.signature_policy_path)
    self.cosign_path = cosign_path or settings.cosign_path
    self._golden: dict[str, Any] = {}
    self._signature: dict[str, Any] = {}
    self.reload()

  def reload(self) -> None:
    self._golden = yaml.safe_load(self.golden_images_path.read_text(encoding="utf-8"))
    self._signature = yaml.safe_load(self.signature_policy_path.read_text(encoding="utf-8"))

  def _normalize_repo(self, repository: str) -> str:
    repo = repository.lower()
    if not repo.startswith("docker.io/") and "/" not in repo:
      repo = f"docker.io/library/{repo}"
    return repo

  def _find_catalog_entry(self, image: ImageReference) -> dict[str, Any] | None:
    repo = self._normalize_repo(image.repository)
    for entry in self._golden.get("approved_images", []):
      entry_repo = self._normalize_repo(entry.get("repository", ""))
      aliases = [self._normalize_repo(a) for a in entry.get("aliases", [])]
      if repo == entry_repo or repo.endswith("/" + entry_repo.split("/")[-1]):
        return entry
      short = repo.split("/")[-1]
      if short in aliases or repo in aliases:
        return entry
    return None

  def _is_blocked(self, image: ImageReference) -> bool:
    display = image.display.lower()
    for blocked in self._golden.get("blocked_images", []):
      if blocked.lower() in display or display.startswith(blocked.lower()):
        return True
    return False

  def verify_signature(self, image: ImageReference) -> tuple[SignatureStatus, str]:
    exempt = [
        self._normalize_repo(r)
        for r in self._signature.get("exempt_repositories", [])
    ]
    repo = self._normalize_repo(image.repository)
    if repo in exempt or any(repo.endswith(e.split("/")[-1]) for e in exempt):
      return SignatureStatus.EXEMPT, "Repository exempt from signature verification"

    if not self._signature.get("require_signatures", True):
      return SignatureStatus.UNKNOWN, "Signature verification disabled by policy"

    if not shutil.which(self.cosign_path):
      return SignatureStatus.UNKNOWN, (
          f"cosign not found at '{self.cosign_path}'; cannot verify signatures"
      )

    image_ref = image.display
    cmd = [self.cosign_path, "verify", image_ref]
    identities = self._signature.get("trusted_identities", [])
    for identity in identities:
      if identity.get("issuer"):
        cmd.extend(["--certificate-issuer", identity["issuer"]])
      if identity.get("subject"):
        cmd.extend(["--certificate-identity", identity["subject"]])

    try:
      proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
      if proc.returncode == 0:
        return SignatureStatus.SIGNED, "Image signature verified with cosign"
      return SignatureStatus.UNSIGNED, proc.stderr.strip() or "Signature verification failed"
    except Exception as exc:
      return SignatureStatus.INVALID, str(exc)

  def evaluate(
      self,
      image: ImageReference,
      trivy: TrivyScanResult,
  ) -> PolicyCheckResult:
    violations: list[str] = []
    warnings: list[str] = []
    recommended_digest: str | None = None
    recommended_image: str | None = None

    if self._is_blocked(image):
      violations.append(f"Image '{image.display}' is explicitly blocked")

    if not trivy.success:
      violations.append(f"Trivy scan failed — cannot verify image security: {trivy.error}")

    entry = self._find_catalog_entry(image)
    in_catalog = entry is not None

    sig_status, sig_detail = self.verify_signature(image)
    if sig_status == SignatureStatus.UNSIGNED:
      action = self._signature.get("unsigned_action", "block")
      msg = f"Image is unsigned: {sig_detail}"
      if action == "block":
        violations.append(msg)
      else:
        warnings.append(msg)
    elif sig_status == SignatureStatus.INVALID:
      violations.append(f"Invalid signature: {sig_detail}")

    if not image.is_pinned:
      action = self._signature.get("unpinned_action", "warn")
      msg = "Image is not pinned to a digest (tag-only reference)"
      if action == "block":
        violations.append(msg)
      else:
        warnings.append(msg)

    if entry:
      approved_tags = entry.get("approved_tags", [])
      approved_digests = entry.get("approved_digests", [])
      max_critical = entry.get("max_critical_cves", 0)
      max_high = entry.get("max_high_cves", 0)
      require_non_root = entry.get("require_non_root", False)

      if image.tag and approved_tags and image.tag not in approved_tags:
        violations.append(
            f"Tag '{image.tag}' not in approved tags: {approved_tags}"
        )

      if image.digest and approved_digests and image.digest not in approved_digests:
        if approved_digests:
          recommended_digest = approved_digests[0]
          recommended_image = f"{image.repository}@{recommended_digest}"
          violations.append(
              f"Digest not in approved list. Use: {recommended_image}"
          )

      if not image.digest and approved_digests:
        recommended_digest = approved_digests[0]
        recommended_image = f"{image.repository}@{recommended_digest}"
        warnings.append(f"Pin to approved digest: {recommended_image}")

      if trivy.success:
        if trivy.critical_count > max_critical:
          violations.append(
              f"Critical CVEs ({trivy.critical_count}) exceed limit ({max_critical})"
          )
        if trivy.high_count > max_high:
          violations.append(
              f"High CVEs ({trivy.high_count}) exceed limit ({max_high})"
          )

      if trivy.secrets:
        violations.append(f"Secrets detected in image: {len(trivy.secrets)}")

      non_root_recommended = require_non_root
    else:
      default = self._golden.get("default_policy", {})
      if default.get("action") == "block":
        violations.append(
            default.get("message", "Image not in golden catalog")
        )
      else:
        warnings.append(default.get("message", "Image not in golden catalog"))
      non_root_recommended = True

    approved = len(violations) == 0
    if violations:
      decision = DeploymentDecision.BLOCK
    elif warnings:
      decision = DeploymentDecision.WARN
    else:
      decision = DeploymentDecision.APPROVE

    return PolicyCheckResult(
        image=image,
        in_golden_catalog=in_catalog,
        approved=approved,
        is_pinned=image.is_pinned,
        signature_status=sig_status,
        signature_detail=sig_detail,
        recommended_digest=recommended_digest,
        recommended_image=recommended_image,
        violations=violations,
        warnings=warnings,
        non_root_recommended=non_root_recommended if entry else True,
        decision=decision,
    )
