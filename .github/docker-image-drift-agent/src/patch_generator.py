"""Generate minimal Dockerfile/Kubernetes patches and PR comments."""

from __future__ import annotations

from src.models import (
    DeploymentDecision,
    ImageAnalysisReport,
    ImageChange,
    ImageSource,
    PolicyCheckResult,
    PrAnalysisResult,
    TrivyScanResult,
)


def generate_patch_snippet(
    change: ImageChange,
    policy: PolicyCheckResult,
) -> str:
    """Produce a minimal patch snippet with approved digest."""
    target_image = (
        policy.recommended_image
        or (f"{change.new_image.repository}@{policy.recommended_digest}"
            if policy.recommended_digest
            else change.new_image.display)
    )

    if change.source == ImageSource.DOCKERFILE:
        old_line = change.context_line.strip()
        if old_line.upper().startswith("FROM"):
            prefix = old_line.split(change.new_image.raw)[0] if change.new_image.raw in old_line else "FROM "
            return f"{prefix}{target_image}"
        return f"FROM {target_image}"

    indent = len(change.context_line) - len(change.context_line.lstrip())
    pad = " " * indent
    return f"{pad}image: {target_image}"


def _format_cve_table(trivy: TrivyScanResult, limit: int = 15) -> str:
    if not trivy.cves:
        return "_No CVEs reported._\n"

    lines = [
        "| CVE | Severity | Package | Fixed |",
        "|-----|----------|---------|-------|",
    ]
    sorted_cves = sorted(
        trivy.cves,
        key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c.severity, 4),
    )
    for cve in sorted_cves[:limit]:
        lines.append(
            f"| {cve.vulnerability_id} | {cve.severity} | {cve.package} | {cve.fixed_version or '—'} |"
        )
    if len(trivy.cves) > limit:
        lines.append(f"\n_...and {len(trivy.cves) - limit} more._")
    return "\n".join(lines) + "\n"


def build_report_markdown(result: PrAnalysisResult) -> str:
    """Build the full PR comment markdown."""
    decision_emoji = {
        DeploymentDecision.APPROVE: "✅",
        DeploymentDecision.WARN: "⚠️",
        DeploymentDecision.BLOCK: "🚫",
    }
    emoji = decision_emoji.get(result.decision, "ℹ️")

    sections = [
        "## 🛡️ Docker Image Drift Agent",
        "",
        f"**Deployment decision:** {emoji} `{result.decision.value.upper()}`",
        "",
    ]

    if result.block_reasons:
        sections.append("### Block reasons")
        for reason in result.block_reasons:
            sections.append(f"- {reason}")
        sections.append("")

    for report in result.reports:
        change = report.change
        trivy = report.trivy
        policy = report.policy

        sections.extend([
            f"### `{change.file_path}` (line {change.line_number or '?'})",
            "",
            f"- **Source:** {change.source.value}",
            f"- **Old image:** `{change.old_image.display if change.old_image else '—'}`",
            f"- **New image:** `{change.new_image.display}`",
            f"- **Pinned:** {'yes' if policy.is_pinned else 'no'}",
            f"- **Golden catalog:** {'yes' if policy.in_golden_catalog else 'no'}",
            f"- **Signature:** `{policy.signature_status.value}` — {policy.signature_detail}",
            "",
            "#### Trivy scan",
            f"- Scanner: **Trivy** `{trivy.raw_summary.get('trivy_version', 'unknown')}`",
            f"- Scanners: {', '.join(trivy.raw_summary.get('scanners', ['vuln', 'secret', 'misconfig']))}",
            f"- Critical: **{trivy.critical_count}** | High: **{trivy.high_count}** | "
            f"Medium: {trivy.medium_count} | Low: {trivy.low_count}",
            f"- Misconfigurations: {len(trivy.misconfigurations)} | "
            f"Secrets: {len(trivy.secrets)} | SBOM packages: {trivy.sbom_packages}",
            "",
        ])

        if not trivy.success:
            sections.append(f"_Trivy scan failed: {trivy.error}_\n")
        else:
            sections.append("#### CVE findings (top)")
            sections.append(_format_cve_table(trivy))
            if trivy.misconfigurations:
                sections.append("#### Misconfigurations")
                for mc in trivy.misconfigurations[:5]:
                    sections.append(f"- {mc}")
                sections.append("")
            if trivy.secrets:
                sections.append("#### Secrets detected")
                for sec in trivy.secrets[:5]:
                    sections.append(f"- {sec}")
                sections.append("")

        if policy.violations:
            sections.append("#### Policy violations")
            for v in policy.violations:
                sections.append(f"- ❌ {v}")
            sections.append("")

        if policy.warnings:
            sections.append("#### Warnings")
            for w in policy.warnings:
                sections.append(f"- ⚠️ {w}")
            sections.append("")

        if policy.non_root_recommended:
            sections.append(
                "#### Non-root recommendation\n"
                "Add a non-root user to your Dockerfile:\n"
                "```dockerfile\n"
                "RUN addgroup -S app && adduser -S app -G app\n"
                "USER app\n"
                "```\n"
            )

        if report.patch_snippet:
            lang = "dockerfile" if change.source == ImageSource.DOCKERFILE else "yaml"
            sections.extend([
                "#### Suggested patch",
                f"```{lang}",
                report.patch_snippet,
                "```",
                "",
            ])

    if result.agent_summary:
        sections.extend([
            "### Agent summary",
            result.agent_summary,
            "",
        ])

    sections.append("---")
    sections.append("_Powered by Trivy + LangChain Docker Image Drift Agent_")

    return "\n".join(sections)


def assemble_pr_result(
    repo_full_name: str,
    pr_number: int,
    pr_url: str,
    reports: list[ImageAnalysisReport],
) -> PrAnalysisResult:
    block_reasons: list[str] = []
    for report in reports:
        block_reasons.extend(report.policy.violations)

    if any(r.policy.decision == DeploymentDecision.BLOCK for r in reports):
        decision = DeploymentDecision.BLOCK
    elif any(r.policy.decision == DeploymentDecision.WARN for r in reports):
        decision = DeploymentDecision.WARN
    else:
        decision = DeploymentDecision.APPROVE

    result = PrAnalysisResult(
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        pr_url=pr_url,
        triggered=len(reports) > 0,
        decision=decision,
        reports=reports,
        block_reasons=block_reasons,
    )
    result.pr_comment_markdown = build_report_markdown(result)
    return result
