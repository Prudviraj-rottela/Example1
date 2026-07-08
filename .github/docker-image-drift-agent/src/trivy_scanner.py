"""Trivy integration for container image scanning."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from src.config import settings
from src.models import CveFinding, TrivyScanResult

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TrivyScanner:
    def __init__(
        self,
        trivy_path: str | None = None,
        timeout: int | None = None,
        severity_threshold: str | None = None,
    ):
        self.trivy_path = trivy_path or settings.trivy_path
        self.timeout = timeout or settings.trivy_timeout_seconds
        self.severity_threshold = (severity_threshold or settings.trivy_severity_threshold).upper()
        self._version: str | None = None

    def is_available(self) -> bool:
        return Path(self.trivy_path).is_file()

    def get_version(self) -> str:
        if self._version:
            return self._version
        if not self.is_available():
            return "not installed"
        try:
            proc = subprocess.run(
                [self.trivy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._version = proc.stdout.strip().splitlines()[0] if proc.stdout else "unknown"
        except Exception:
            self._version = "unknown"
        return self._version

    def _severity_filter(self) -> list[str]:
        """Return severities at or above the configured threshold."""
        if self.severity_threshold not in SEVERITY_ORDER:
            return SEVERITY_ORDER
        idx = SEVERITY_ORDER.index(self.severity_threshold)
        return SEVERITY_ORDER[idx:]

    def scan_image(self, image_ref: str) -> TrivyScanResult:
        """Scan image for CVEs, misconfigurations, secrets, and SBOM."""
        if not self.is_available():
            return TrivyScanResult(
                image=image_ref,
                success=False,
                error=(
                    f"Trivy not found at '{self.trivy_path}'. "
                    "Install from https://trivy.dev/ or run: "
                    "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/"
                    "main/contrib/install.sh | sh -s -- -b ./bin"
                ),
            )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_path = Path(tmp.name)

        severities = ",".join(self._severity_filter())
        cmd = [
            self.trivy_path,
            "image",
            "--format", "json",
            "--output", str(output_path),
            "--scanners", "vuln,secret,misconfig",
            "--list-all-pkgs",
            "--severity", severities,
            image_ref,
        ]

        logger.info("Trivy scanning %s (severity >= %s)", image_ref, self.severity_threshold)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            # Trivy exits 1 when vulnerabilities are found — still a successful scan
            if proc.returncode not in (0, 1):
                return TrivyScanResult(
                    image=image_ref,
                    success=False,
                    error=proc.stderr.strip() or f"Trivy exited with code {proc.returncode}",
                )

            if not output_path.exists() or output_path.stat().st_size == 0:
                return TrivyScanResult(
                    image=image_ref,
                    success=False,
                    error="Trivy produced no output",
                )

            raw = json.loads(output_path.read_text(encoding="utf-8"))
            result = self._parse_trivy_json(image_ref, raw)
            result.raw_summary["trivy_version"] = self.get_version()
            result.raw_summary["scanners"] = ["vuln", "secret", "misconfig"]
            logger.info(
                "Trivy scan complete for %s: %d CVEs (%d critical, %d high), %d SBOM packages",
                image_ref,
                len(result.cves),
                result.critical_count,
                result.high_count,
                result.sbom_packages,
            )
            return result
        except subprocess.TimeoutExpired:
            return TrivyScanResult(
                image=image_ref,
                success=False,
                error=f"Trivy scan timed out after {self.timeout}s",
            )
        except json.JSONDecodeError as exc:
            return TrivyScanResult(
                image=image_ref,
                success=False,
                error=f"Failed to parse Trivy JSON: {exc}",
            )
        except Exception as exc:
            return TrivyScanResult(
                image=image_ref,
                success=False,
                error=str(exc),
            )
        finally:
            output_path.unlink(missing_ok=True)

    def _parse_trivy_json(self, image_ref: str, data: dict) -> TrivyScanResult:
        cves: list[CveFinding] = []
        misconfigs: list[str] = []
        secrets: list[str] = []
        sbom_count = 0

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                sev = (vuln.get("Severity") or "UNKNOWN").upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                cves.append(
                    CveFinding(
                        vulnerability_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                        severity=sev,
                        package=vuln.get("PkgName", ""),
                        installed_version=vuln.get("InstalledVersion"),
                        fixed_version=vuln.get("FixedVersion"),
                        title=vuln.get("Title"),
                    )
                )

            for mc in result.get("Misconfigurations") or []:
                misconfigs.append(
                    f"{mc.get('ID', 'MISCONFIG')}: {mc.get('Title', mc.get('Description', ''))}"
                )

            for secret in result.get("Secrets") or []:
                secrets.append(
                    f"{secret.get('RuleID', 'SECRET')}: {secret.get('Title', 'detected secret')}"
                )

            for pkg in result.get("Packages") or []:
                sbom_count += 1

        return TrivyScanResult(
            image=image_ref,
            success=True,
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            cves=cves,
            misconfigurations=misconfigs,
            secrets=secrets,
            sbom_packages=sbom_count,
            raw_summary={
                "severity_counts": severity_counts,
                "total_cves": len(cves),
            },
        )

    def scan_sbom(self, image_ref: str) -> TrivyScanResult:
        """Generate CycloneDX SBOM via Trivy."""
        if not self.is_available():
            return TrivyScanResult(image=image_ref, success=False, error="Trivy not available")

        with tempfile.NamedTemporaryFile(suffix=".cdx.json", delete=False) as tmp:
            output_path = Path(tmp.name)

        cmd = [
            self.trivy_path,
            "image",
            "--format", "cyclonedx",
            "--output", str(output_path),
            image_ref,
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, check=False)
            pkg_count = 0
            if output_path.exists():
                try:
                    sbom = json.loads(output_path.read_text(encoding="utf-8"))
                    pkg_count = len(sbom.get("components", []))
                except json.JSONDecodeError:
                    pkg_count = 1
            return TrivyScanResult(
                image=image_ref,
                success=True,
                sbom_packages=pkg_count,
                raw_summary={"sbom_format": "cyclonedx", "components": pkg_count},
            )
        except Exception as exc:
            return TrivyScanResult(image=image_ref, success=False, error=str(exc))
        finally:
            output_path.unlink(missing_ok=True)
