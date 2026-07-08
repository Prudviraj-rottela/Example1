"""Detect Dockerfile and Kubernetes image changes in PR diffs."""

from __future__ import annotations

import re

from src.image_parser import (
    extract_dockerfile_images,
    extract_k8s_images,
    images_differ,
    parse_image_reference,
)
from src.models import ImageChange, ImageSource

DOCKERFILE_PATHS = re.compile(r"(^|/)(Dockerfile[^/]*|\.dockerfile)$", re.IGNORECASE)
K8S_PATHS = re.compile(
    r"(^|/)([^/]+\.(ya?ml)|kustomization\.ya?ml|values\.ya?ml)$",
    re.IGNORECASE,
)


def _classify_file(path: str) -> ImageSource | None:
    if DOCKERFILE_PATHS.search(path):
        return ImageSource.DOCKERFILE
    if K8S_PATHS.search(path) and any(
        k in path.lower()
        for k in ("deploy", "k8s", "kube", "helm", "chart", "manifest", "values")
    ):
        return ImageSource.KUBERNETES
    if K8S_PATHS.search(path):
        return ImageSource.KUBERNETES
    return None


def _parse_unified_diff(diff_text: str) -> list[tuple[str, str, str]]:
    """Return list of (filename, old_content, new_content) from unified diff."""
    files: list[tuple[str, str, str]] = []
    if not diff_text:
        return files

    current_file = ""
    old_lines: list[str] = []
    new_lines: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_file:
                files.append((current_file, "\n".join(old_lines), "\n".join(new_lines)))
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[3][2:] if parts[3].startswith("b/") else parts[3]
            old_lines, new_lines = [], []
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            continue
        elif line.startswith("-") and not line.startswith("---"):
            old_lines.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            new_lines.append(line[1:])
        elif line.startswith(" "):
            old_lines.append(line[1:])
            new_lines.append(line[1:])

    if current_file:
        files.append((current_file, "\n".join(old_lines), "\n".join(new_lines)))

    return files


def detect_image_changes_from_diff(diff_text: str) -> list[ImageChange]:
    """Detect FROM line or Kubernetes image field changes in a PR diff."""
    changes: list[ImageChange] = []

    for file_path, old_content, new_content in _parse_unified_diff(diff_text):
        source = _classify_file(file_path)
        if source is None:
            continue

        if source == ImageSource.DOCKERFILE:
            old_images = extract_dockerfile_images(old_content, file_path)
            new_images = extract_dockerfile_images(new_content, file_path)
        else:
            old_images = extract_k8s_images(old_content, file_path)
            new_images = extract_k8s_images(new_content, file_path)

        old_by_line = {p.line_number: p for p in old_images}
        for new_parsed in new_images:
            old_parsed = old_by_line.get(new_parsed.line_number)
            old_ref = old_parsed.image if old_parsed else None
            if images_differ(old_ref, new_parsed.image):
                changes.append(
                    ImageChange(
                        source=source,
                        file_path=file_path,
                        line_number=new_parsed.line_number,
                        old_image=old_ref,
                        new_image=new_parsed.image,
                        context_line=new_parsed.context_line,
                    )
                )

        # Handle added files where line numbers may not align
        if not old_content and new_images:
            for new_parsed in new_images:
                if not any(
                    c.file_path == file_path and c.new_image.raw == new_parsed.image.raw
                    for c in changes
                ):
                    changes.append(
                        ImageChange(
                            source=source,
                            file_path=file_path,
                            line_number=new_parsed.line_number,
                            old_image=None,
                            new_image=new_parsed.image,
                            context_line=new_parsed.context_line,
                        )
                    )

    return changes


def detect_image_changes_from_files(
    file_contents: dict[str, tuple[str, str]],
) -> list[ImageChange]:
    """Detect changes given {path: (old_content, new_content)}."""
    all_changes: list[ImageChange] = []
    for path, (old_content, new_content) in file_contents.items():
        source = _classify_file(path)
        if source is None:
            continue

        if source == ImageSource.DOCKERFILE:
            old_images = extract_dockerfile_images(old_content, path)
            new_images = extract_dockerfile_images(new_content, path)
        else:
            old_images = extract_k8s_images(old_content, path)
            new_images = extract_k8s_images(new_content, path)

        max_len = max(len(old_images), len(new_images))
        for i in range(max_len):
            old_ref = old_images[i].image if i < len(old_images) else None
            new_parsed = new_images[i] if i < len(new_images) else None
            if new_parsed is None:
                continue
            if images_differ(old_ref, new_parsed.image):
                all_changes.append(
                    ImageChange(
                        source=source,
                        file_path=path,
                        line_number=new_parsed.line_number,
                        old_image=old_ref,
                        new_image=new_parsed.image,
                        context_line=new_parsed.context_line,
                    )
                )

    return all_changes
