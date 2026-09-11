"""Safe output functions for Phishing Evidence Analyzer.

This module writes locally generated analysis results.
It does not perform network access or modify source email evidence.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASE_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9._-]+$"
)


def validate_case_name(
    case_name: str,
) -> str:
    """Validate a case name used as an output filename prefix."""

    if not case_name:
        raise ValueError(
            "Case name must not be empty."
        )

    if not CASE_NAME_PATTERN.fullmatch(
        case_name
    ):
        raise ValueError(
            "Case name may contain only letters, numbers, "
            "periods, underscores, and hyphens."
        )

    if case_name in {".", ".."}:
        raise ValueError(
            "Invalid case name."
        )

    return case_name


def utc_timestamp() -> str:
    """Return current UTC time in ISO 8601 format."""

    return datetime.now(
        timezone.utc
    ).isoformat(
        timespec="seconds"
    ).replace(
        "+00:00",
        "Z",
    )


def ensure_output_paths_available(
    paths: list[Path],
    *,
    overwrite: bool,
) -> None:
    """Check all output paths before writing any file."""

    if overwrite:
        return

    for path in paths:
        if path.exists():
            raise FileExistsError(
                f"Output file already exists: {path}"
            )


def write_text_file(
    path: Path,
    content: str,
) -> None:
    """Write UTF-8 text locally."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content,
        encoding="utf-8",
        newline="\n",
    )


def build_hash_record(
    analysis: dict[str, Any],
    recorded_at_utc: str,
) -> str:
    """Build a human-readable SHA-256 record."""

    lines = [
        f"File Name    : {analysis['file_name']}",
        f"File Size    : {analysis['file_size_bytes']} bytes",
        "Algorithm    : SHA256",
        f"SHA256       : {analysis['sha256']}",
        f"Recorded UTC : {recorded_at_utc}",
        "",
    ]

    return "\n".join(lines)


def build_header_record(
    analysis: dict[str, Any],
    recorded_at_utc: str,
) -> dict[str, Any]:
    """Build structured header output without local absolute paths."""

    return {
        "schema_version": "1.0",
        "recorded_at_utc": recorded_at_utc,
        "source": {
            "file_name": analysis["file_name"],
            "file_size_bytes": analysis["file_size_bytes"],
            "sha256": analysis["sha256"],
        },
        "headers": analysis["headers"],
    }


def build_url_record(
    analysis: dict[str, Any],
    recorded_at_utc: str,
) -> dict[str, Any]:
    """Build safe URL indicator output using defanged URLs only."""

    return {
        "schema_version": "1.0",
        "recorded_at_utc": recorded_at_utc,
        "source": {
            "file_name": analysis["file_name"],
            "sha256": analysis["sha256"],
        },
        "url_count": len(
            analysis["urls"]
        ),
        "urls": analysis["urls"],
    }


def save_analysis_outputs(
    analysis: dict[str, Any],
    investigation_root: str | Path,
    case_name: str,
    *,
    overwrite: bool = False,
) -> dict[str, str]:
    """Save local hash, header, and defanged URL records."""

    safe_case_name = validate_case_name(
        case_name
    )

    root = Path(
        investigation_root
    ).expanduser().resolve()

    hash_directory = (
        root / "02_Hash_Records"
    )

    header_directory = (
        root / "03_Header_Text"
    )

    hash_path = (
        hash_directory
        / f"{safe_case_name}_sha256.txt"
    )

    header_path = (
        header_directory
        / f"{safe_case_name}_headers.json"
    )

    url_path = (
        header_directory
        / f"{safe_case_name}_urls.json"
    )

    output_paths = [
        hash_path,
        header_path,
        url_path,
    ]

    ensure_output_paths_available(
        output_paths,
        overwrite=overwrite,
    )

    recorded_at_utc = utc_timestamp()

    hash_content = build_hash_record(
        analysis,
        recorded_at_utc,
    )

    header_content = json.dumps(
        build_header_record(
            analysis,
            recorded_at_utc,
        ),
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    url_content = json.dumps(
        build_url_record(
            analysis,
            recorded_at_utc,
        ),
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    write_text_file(
        hash_path,
        hash_content,
    )

    write_text_file(
        header_path,
        header_content,
    )

    write_text_file(
        url_path,
        url_content,
    )

    return {
        "hash_record": str(
            hash_path
        ),
        "header_record": str(
            header_path
        ),
        "url_record": str(
            url_path
        ),
    }