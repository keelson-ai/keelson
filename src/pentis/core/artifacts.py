"""Artifact type system for Pentis scan outputs.

Defines a discriminated union of all supported artifact types, metadata per type,
and a factory for constructing typed artifacts from raw data.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal


class ArtifactType(str, Enum):
    """Canonical set of artifact types produced by Pentis scans."""

    TEXT = "text"
    CODE = "code"
    JSON = "json"
    MARKDOWN = "markdown"
    SCAN_RESULT = "scan_result"
    REPORT = "report"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ArtifactMeta:
    """Metadata describing how an artifact type should be handled."""

    mime_type: str
    file_extension: str
    render_strategy: str  # "plain", "highlight", "markdown", "json", "binary"
    max_size_bytes: int | None = None


# Registry of per-type metadata — add a new entry when adding a new ArtifactType
ARTIFACT_META: dict[ArtifactType, ArtifactMeta] = {
    ArtifactType.TEXT: ArtifactMeta(
        mime_type="text/plain",
        file_extension=".txt",
        render_strategy="plain",
    ),
    ArtifactType.CODE: ArtifactMeta(
        mime_type="text/x-code",
        file_extension=".txt",
        render_strategy="highlight",
        max_size_bytes=1_048_576,  # 1 MiB
    ),
    ArtifactType.JSON: ArtifactMeta(
        mime_type="application/json",
        file_extension=".json",
        render_strategy="json",
        max_size_bytes=10_485_760,  # 10 MiB
    ),
    ArtifactType.MARKDOWN: ArtifactMeta(
        mime_type="text/markdown",
        file_extension=".md",
        render_strategy="markdown",
    ),
    ArtifactType.SCAN_RESULT: ArtifactMeta(
        mime_type="application/json",
        file_extension=".json",
        render_strategy="json",
        max_size_bytes=52_428_800,  # 50 MiB
    ),
    ArtifactType.REPORT: ArtifactMeta(
        mime_type="text/markdown",
        file_extension=".md",
        render_strategy="markdown",
    ),
    ArtifactType.ERROR: ArtifactMeta(
        mime_type="text/plain",
        file_extension=".txt",
        render_strategy="plain",
    ),
    ArtifactType.UNKNOWN: ArtifactMeta(
        mime_type="application/octet-stream",
        file_extension=".bin",
        render_strategy="plain",
    ),
}


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Per-type artifact dataclasses — each carries a Literal discriminator so
# pyright can narrow the union in handler code.
# ---------------------------------------------------------------------------


@dataclass
class TextArtifact:
    """Plain-text artifact (e.g. raw agent responses)."""

    artifact_type: Literal[ArtifactType.TEXT]
    content: str
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)


@dataclass
class CodeArtifact:
    """Source code artifact with optional language hint."""

    artifact_type: Literal[ArtifactType.CODE]
    content: str
    language: str = ""
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)


@dataclass
class JsonArtifact:
    """Structured JSON artifact."""

    artifact_type: Literal[ArtifactType.JSON]
    content: str  # raw JSON string
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)

    def parsed(self) -> object:
        """Return the parsed Python object, or raise ValueError on bad JSON."""
        try:
            return json.loads(self.content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON content: {exc}") from exc


@dataclass
class MarkdownArtifact:
    """Markdown-formatted artifact (e.g. narrative reports)."""

    artifact_type: Literal[ArtifactType.MARKDOWN]
    content: str
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)


@dataclass
class ScanResultArtifact:
    """Serialised ScanResult or CampaignResult from a completed scan."""

    artifact_type: Literal[ArtifactType.SCAN_RESULT]
    content: str  # JSON-serialised scan result
    scan_id: str = ""
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)


@dataclass
class ReportArtifact:
    """Final rendered security report."""

    artifact_type: Literal[ArtifactType.REPORT]
    content: str
    report_format: str = "markdown"  # "markdown", "html", "pdf"
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)


@dataclass
class ErrorArtifact:
    """Error output from a scan step or adapter call."""

    artifact_type: Literal[ArtifactType.ERROR]
    content: str
    error_code: str = ""
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)


@dataclass
class UnknownArtifact:
    """Fallback for unrecognised artifact types — never raises."""

    artifact_type: Literal[ArtifactType.UNKNOWN]
    content: str
    raw_type: str = ""  # original type string before normalisation
    source: str = ""
    artifact_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utcnow)


# The discriminated union — exhaustive over all concrete types.
Artifact = (
    TextArtifact
    | CodeArtifact
    | JsonArtifact
    | MarkdownArtifact
    | ScanResultArtifact
    | ReportArtifact
    | ErrorArtifact
    | UnknownArtifact
)


def make_artifact(artifact_type: ArtifactType, content: str, **kwargs: object) -> Artifact:
    """Construct a typed artifact from a raw type string and content.

    Unknown or unrecognised types produce an ``UnknownArtifact`` rather than
    raising — callers should not need to guard every construction site.
    """
    if artifact_type == ArtifactType.TEXT:
        return TextArtifact(
            artifact_type=ArtifactType.TEXT,
            content=content,
            source=str(kwargs.get("source", "")),
        )
    if artifact_type == ArtifactType.CODE:
        return CodeArtifact(
            artifact_type=ArtifactType.CODE,
            content=content,
            language=str(kwargs.get("language", "")),
            source=str(kwargs.get("source", "")),
        )
    if artifact_type == ArtifactType.JSON:
        return JsonArtifact(
            artifact_type=ArtifactType.JSON,
            content=content,
            source=str(kwargs.get("source", "")),
        )
    if artifact_type == ArtifactType.MARKDOWN:
        return MarkdownArtifact(
            artifact_type=ArtifactType.MARKDOWN,
            content=content,
            source=str(kwargs.get("source", "")),
        )
    if artifact_type == ArtifactType.SCAN_RESULT:
        return ScanResultArtifact(
            artifact_type=ArtifactType.SCAN_RESULT,
            content=content,
            scan_id=str(kwargs.get("scan_id", "")),
            source=str(kwargs.get("source", "")),
        )
    if artifact_type == ArtifactType.REPORT:
        return ReportArtifact(
            artifact_type=ArtifactType.REPORT,
            content=content,
            report_format=str(kwargs.get("report_format", "markdown")),
            source=str(kwargs.get("source", "")),
        )
    if artifact_type == ArtifactType.ERROR:
        return ErrorArtifact(
            artifact_type=ArtifactType.ERROR,
            content=content,
            error_code=str(kwargs.get("error_code", "")),
            source=str(kwargs.get("source", "")),
        )
    # ArtifactType.UNKNOWN or any future unhandled value
    return UnknownArtifact(
        artifact_type=ArtifactType.UNKNOWN,
        content=content,
        raw_type=str(kwargs.get("raw_type", artifact_type.value)),
        source=str(kwargs.get("source", "")),
    )


def artifact_from_string(raw_type: str, content: str, **kwargs: object) -> Artifact:
    """Construct a typed artifact from a raw type string.

    Gracefully falls back to ``UnknownArtifact`` if the type string does not
    match any known ``ArtifactType``.
    """
    try:
        artifact_type = ArtifactType(raw_type)
    except ValueError:
        return UnknownArtifact(
            artifact_type=ArtifactType.UNKNOWN,
            content=content,
            raw_type=raw_type,
            source=str(kwargs.get("source", "")),
        )
    return make_artifact(artifact_type, content, **kwargs)
