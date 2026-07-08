"""Parse image references from Dockerfile and Kubernetes manifests."""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.models import ImageReference

# FROM [--platform=...] image[:tag][@digest] [AS name]
FROM_PATTERN = re.compile(
    r"^\s*FROM\s+(?:--platform=[^\s]+\s+)?"
    r"(?P<image>(?:[\w./-]+(?::[\w./-]+)?)(?:@sha256:[a-fA-F0-9]{64})?)"
    r"(?:\s+AS\s+\w+)?",
    re.IGNORECASE,
)

# Kubernetes image fields: image: value
K8S_IMAGE_PATTERN = re.compile(
    r"^\s*image:\s*['\"]?(?P<image>[^\s'\"#]+)['\"]?\s*(?:#.*)?$",
    re.IGNORECASE,
)

DIGEST_PATTERN = re.compile(r"@(sha256:[a-fA-F0-9]{64})$")
TAG_PATTERN = re.compile(r":([^@/]+)(?:@|$)")


def parse_image_reference(raw: str) -> ImageReference:
    """Parse a container image string into structured components."""
    raw = raw.strip().strip("'\"")
    digest_match = DIGEST_PATTERN.search(raw)
    digest = digest_match.group(1) if digest_match else None

    repo_part = raw.split("@")[0] if digest else raw
    tag = None
    if ":" in repo_part.rsplit("/", 1)[-1]:
        tag_match = TAG_PATTERN.search(repo_part)
        if tag_match:
            tag = tag_match.group(1)
            repo_part = repo_part[: repo_part.rfind(f":{tag}")]

    repository = repo_part
    if not repository.startswith(("docker.io/", "gcr.io/", "ghcr.io/", "quay.io/")):
        if "/" not in repository:
            repository = f"docker.io/library/{repository}"

    return ImageReference(
        raw=raw,
        repository=repository,
        tag=tag,
        digest=digest,
        is_pinned=digest is not None,
    )


@dataclass
class ParsedLine:
    file_path: str
    line_number: int
    image: ImageReference
    context_line: str


def extract_dockerfile_images(content: str, file_path: str) -> list[ParsedLine]:
    results: list[ParsedLine] = []
    for idx, line in enumerate(content.splitlines(), start=1):
        match = FROM_PATTERN.match(line)
        if match:
            results.append(
                ParsedLine(
                    file_path=file_path,
                    line_number=idx,
                    image=parse_image_reference(match.group("image")),
                    context_line=line.rstrip(),
                )
            )
    return results


def extract_k8s_images(content: str, file_path: str) -> list[ParsedLine]:
    results: list[ParsedLine] = []
    for idx, line in enumerate(content.splitlines(), start=1):
        match = K8S_IMAGE_PATTERN.match(line)
        if match:
            results.append(
                ParsedLine(
                    file_path=file_path,
                    line_number=idx,
                    image=parse_image_reference(match.group("image")),
                    context_line=line.rstrip(),
                )
            )
    return results


def images_differ(old: ImageReference | None, new: ImageReference) -> bool:
    if old is None:
        return True
    return (
        old.repository != new.repository
        or old.tag != new.tag
        or old.digest != new.digest
    )
