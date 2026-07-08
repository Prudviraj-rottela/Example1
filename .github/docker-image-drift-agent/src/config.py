"""Application settings."""

from __future__ import annotations

import shutil
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


def resolve_trivy_path(configured: str = "trivy") -> str:
    """Resolve Trivy binary: project bin/ > configured path > PATH."""
    candidates: list[Path] = []

    if configured and configured != "trivy":
        p = Path(configured)
        candidates.append(p if p.is_absolute() else ROOT / p)

    candidates.append(ROOT / "bin" / "trivy")

    which = shutil.which(configured) or shutil.which("trivy")
    if which:
        candidates.append(Path(which))

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())

    return configured or "trivy"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    github_token: str = ""
    github_webhook_secret: str = ""

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    host: str = "0.0.0.0"
    port: int = 8080

    golden_images_path: str = str(ROOT / "config" / "golden_images.yaml")
    signature_policy_path: str = str(ROOT / "config" / "signature_policy.yaml")
    onboarded_repos_path: str = str(ROOT / "data" / "onboarded_repos.json")

    trivy_path: str = "trivy"
    trivy_timeout_seconds: int = 300
    trivy_severity_threshold: str = "HIGH"

    cosign_path: str = "cosign"

    @model_validator(mode="after")
    def resolve_binaries(self) -> "Settings":
        self.trivy_path = resolve_trivy_path(self.trivy_path)
        return self


settings = Settings()
