"""Core offline analysis functions for suspicious email files.

This module performs local-only parsing.
It does not access URLs, perform DNS lookups, or contact external services.
"""

from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from phishing_evidence_analyzer.url_extractor import (
    build_defanged_url_records,
)


SINGLE_VALUE_HEADERS = (
    "Date",
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Return-Path",
    "Subject",
    "Message-ID",
)

MULTI_VALUE_HEADERS = (
    "Received",
    "Authentication-Results",
    "Received-SPF",
    "DKIM-Signature",
)


def calculate_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 hash of a file without modifying it."""

    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):
            sha256.update(chunk)

    return sha256.hexdigest().upper()


def analyze_eml(file_path: str | Path) -> dict[str, Any]:
    """Read and parse an EML file locally.

    The source file is opened in binary read-only mode.
    No external network access is performed.
    """

    path = Path(file_path).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(
            f"EML file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Path is not a file: {path}"
        )

    if path.suffix.lower() != ".eml":
        raise ValueError(
            f"Expected an .eml file: {path}"
        )

    file_size = path.stat().st_size
    sha256 = calculate_sha256(path)

    with path.open("rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    headers: dict[str, Any] = {}

    for header_name in SINGLE_VALUE_HEADERS:
        value = message.get(header_name)

        headers[header_name] = (
            str(value)
            if value is not None
            else None
        )

    for header_name in MULTI_VALUE_HEADERS:
        values = message.get_all(
            header_name,
            [],
        )

        headers[header_name] = [
            str(value)
            for value in values
        ]

    urls = build_defanged_url_records(
        message
    )

    return {
        "file_name": path.name,
        "file_path": str(path),
        "file_size_bytes": file_size,
        "sha256": sha256,
        "headers": headers,
        "urls": urls,
    }