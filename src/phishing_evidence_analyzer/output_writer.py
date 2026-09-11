"""Safe output functions for Phishing Evidence Analyzer."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phishing_evidence_analyzer.report_generator import (
    build_markdown_report,
)


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

    if case_name in {
        ".",
        "..",
    }:
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
    """Build structured header output."""

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
    """Build defanged URL output."""

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


def build_indicator_record(
    analysis: dict[str, Any],
    recorded_at_utc: str,
) -> dict[str, Any]:
    """Build normalized indicator output."""

    return {
        "schema_version": "1.0",
        "recorded_at_utc": recorded_at_utc,
        "source": {
            "file_name": analysis["file_name"],
            "sha256": analysis["sha256"],
        },
        "indicators": analysis["indicators"],
    }


def build_rdap_candidate_record(
    analysis: dict[str, Any],
    recorded_at_utc: str,
) -> dict[str, Any]:
    """Build local-only RDAP candidate output."""

    return {
        "schema_version": "1.0",
        "recorded_at_utc": recorded_at_utc,
        "source": {
            "file_name": analysis["file_name"],
            "sha256": analysis["sha256"],
        },
        "rdap_candidates": analysis["rdap_candidates"],
    }


def save_analysis_outputs(
    analysis: dict[str, Any],
    investigation_root: str | Path,
    case_name: str,
    *,
    overwrite: bool = False,
) -> dict[str, str]:
    """Save all locally generated analysis records."""

    safe_case_name = validate_case_name(
        case_name
    )

    root = Path(
        investigation_root
    ).expanduser().resolve()

    hash_directory = (
        root
        / "02_Hash_Records"
    )

    header_directory = (
        root
        / "03_Header_Text"
    )

    rdap_directory = (
        root
        / "04_RDAP"
    )

    report_directory = (
        root
        / "05_Report"
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

    indicator_path = (
        header_directory
        / f"{safe_case_name}_indicators.json"
    )

    rdap_candidate_path = (
        rdap_directory
        / f"{safe_case_name}_rdap_candidates.json"
    )

    report_path = (
        report_directory
        / f"{safe_case_name}_report.md"
    )

    output_paths = [
        hash_path,
        header_path,
        url_path,
        indicator_path,
        rdap_candidate_path,
        report_path,
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

    indicator_content = json.dumps(
        build_indicator_record(
            analysis,
            recorded_at_utc,
        ),
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    rdap_candidate_content = json.dumps(
        build_rdap_candidate_record(
            analysis,
            recorded_at_utc,
        ),
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    report_content = build_markdown_report(
        analysis,
        recorded_at_utc,
    )

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

    write_text_file(
        indicator_path,
        indicator_content,
    )

    write_text_file(
        rdap_candidate_path,
        rdap_candidate_content,
    )

    write_text_file(
        report_path,
        report_content,
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
        "indicator_record": str(
            indicator_path
        ),
        "rdap_candidate_record": str(
            rdap_candidate_path
        ),
        "report": str(
            report_path
        ),
    }


def rewrite_analysis_report(
    analysis: dict[str, Any],
    registration_summary: dict[str, Any],
    investigation_root: str | Path,
    case_name: str,
) -> str:
    """Rewrite the report created earlier in the same analysis run."""

    safe_case_name = validate_case_name(
        case_name
    )

    root = Path(
        investigation_root
    ).expanduser().resolve()

    report_path = (
        root
        / "05_Report"
        / f"{safe_case_name}_report.md"
    )

    if not report_path.exists():
        raise FileNotFoundError(
            f"Analysis report does not exist: {report_path}"
        )

    recorded_at_utc = utc_timestamp()

    report_content = build_markdown_report(
        analysis,
        recorded_at_utc,
        registration_summary,
    )

    write_text_file(
        report_path,
        report_content,
    )

    return str(
        report_path
    )

def get_rdap_enrichment_output_paths(
    investigation_root: str | Path,
    case_name: str,
) -> dict[str, Path]:
    """Return paths used for explicit RDAP enrichment output."""

    safe_case_name = validate_case_name(
        case_name
    )

    root = Path(
        investigation_root
    ).expanduser().resolve()

    rdap_directory = (
        root
        / "04_RDAP"
    )

    return {
        "domain_rdap": (
            rdap_directory
            / f"{safe_case_name}_domain_rdap.json"
        ),
        "ip_rdap": (
            rdap_directory
            / f"{safe_case_name}_ip_rdap.json"
        ),
        "rdap_summary": (
            rdap_directory
            / f"{safe_case_name}_rdap_summary.json"
        ),
    }


def ensure_rdap_enrichment_outputs_available(
    investigation_root: str | Path,
    case_name: str,
    *,
    overwrite: bool,
) -> None:
    """Preflight-check explicit RDAP output paths."""

    paths = get_rdap_enrichment_output_paths(
        investigation_root,
        case_name,
    )

    ensure_output_paths_available(
        list(
            paths.values()
        ),
        overwrite=overwrite,
    )


def save_rdap_enrichment_outputs(
    analysis: dict[str, Any],
    enrichment: dict[str, Any],
    summary: dict[str, Any],
    investigation_root: str | Path,
    case_name: str,
    *,
    overwrite: bool = False,
) -> dict[str, str]:
    """Save normalized explicit RDAP enrichment results."""

    paths = get_rdap_enrichment_output_paths(
        investigation_root,
        case_name,
    )

    ensure_output_paths_available(
        list(
            paths.values()
        ),
        overwrite=overwrite,
    )

    recorded_at_utc = utc_timestamp()

    source = {
        "file_name": analysis["file_name"],
        "sha256": analysis["sha256"],
    }

    domain_content = json.dumps(
        {
            "schema_version": "1.0",
            "recorded_at_utc": recorded_at_utc,
            "source": source,
            "network_access_performed": True,
            "domain_results": enrichment.get(
                "domain_results",
                [],
            ),
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    ip_content = json.dumps(
        {
            "schema_version": "1.0",
            "recorded_at_utc": recorded_at_utc,
            "source": source,
            "network_access_performed": True,
            "ip_results": enrichment.get(
                "ip_results",
                [],
            ),
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    summary_content = json.dumps(
        {
            "schema_version": "1.0",
            "recorded_at_utc": recorded_at_utc,
            "source": source,
            "rdap_summary": summary,
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    write_text_file(
        paths["domain_rdap"],
        domain_content,
    )

    write_text_file(
        paths["ip_rdap"],
        ip_content,
    )

    write_text_file(
        paths["rdap_summary"],
        summary_content,
    )

    return {
        key: str(path)
        for key, path in paths.items()
    }

def get_whois_output_paths(
    investigation_root: str | Path,
    case_name: str,
) -> dict[str, Path]:
    """Return output paths used for explicit WHOIS fallback."""

    safe_case_name = validate_case_name(
        case_name
    )

    root = Path(
        investigation_root
    ).expanduser().resolve()

    rdap_directory = (
        root
        / "04_RDAP"
    )

    return {
        "domain_whois": (
            rdap_directory
            / f"{safe_case_name}_domain_whois.json"
        ),
        "registration_summary": (
            rdap_directory
            / f"{safe_case_name}_registration_summary.json"
        ),
    }


def ensure_whois_outputs_available(
    investigation_root: str | Path,
    case_name: str,
    *,
    overwrite: bool,
) -> None:
    """Preflight-check WHOIS fallback output paths."""

    paths = get_whois_output_paths(
        investigation_root,
        case_name,
    )

    ensure_output_paths_available(
        list(
            paths.values()
        ),
        overwrite=overwrite,
    )


def save_whois_outputs(
    analysis: dict[str, Any],
    whois_enrichment: dict[str, Any],
    registration_summary: dict[str, Any],
    investigation_root: str | Path,
    case_name: str,
    *,
    overwrite: bool = False,
) -> dict[str, str]:
    """Save normalized WHOIS and combined registration results."""

    paths = get_whois_output_paths(
        investigation_root,
        case_name,
    )

    ensure_output_paths_available(
        list(
            paths.values()
        ),
        overwrite=overwrite,
    )

    recorded_at_utc = utc_timestamp()

    source = {
        "file_name": analysis[
            "file_name"
        ],
        "sha256": analysis[
            "sha256"
        ],
    }

    whois_content = json.dumps(
        {
            "schema_version": "1.0",
            "recorded_at_utc": (
                recorded_at_utc
            ),
            "source": source,
            "network_access_performed": (
                whois_enrichment.get(
                    "network_access_performed",
                    False,
                )
            ),
            "transport": whois_enrichment.get(
                "transport"
            ),
            "encrypted": whois_enrichment.get(
                "encrypted"
            ),
            "domain_results": (
                whois_enrichment.get(
                    "domain_results",
                    [],
                )
            ),
            "errors": whois_enrichment.get(
                "errors",
                [],
            ),
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    summary_content = json.dumps(
        {
            "schema_version": "1.0",
            "recorded_at_utc": (
                recorded_at_utc
            ),
            "source": source,
            "registration_summary": (
                registration_summary
            ),
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    write_text_file(
        paths[
            "domain_whois"
        ],
        whois_content,
    )

    write_text_file(
        paths[
            "registration_summary"
        ],
        summary_content,
    )

    return {
        key: str(
            path
        )
        for key, path in paths.items()
    }