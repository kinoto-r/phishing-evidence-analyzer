"""Command-line interface for Phishing Evidence Analyzer."""

from __future__ import annotations

import argparse
import json
import sys

from phishing_evidence_analyzer.analyzer import (
    analyze_eml,
)
from phishing_evidence_analyzer.output_writer import (
    save_analysis_outputs,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-evidence-analyzer",
        description=(
            "Locally calculate SHA-256, extract selected headers, "
            "and extract defanged URLs from an EML file "
            "without network access."
        ),
    )

    parser.add_argument(
        "eml_file",
        help="Path to the .eml file to analyze.",
    )

    parser.add_argument(
        "--output-root",
        help=(
            "Investigation workspace root. "
            "Generated results are stored locally."
        ),
    )

    parser.add_argument(
        "--case-name",
        help=(
            "Safe filename prefix for generated output."
        ),
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Allow generated output files to be overwritten. "
            "Disabled by default."
        ),
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.output_root and not args.case_name:
        parser.error(
            "--case-name is required when --output-root is specified."
        )

    if args.case_name and not args.output_root:
        parser.error(
            "--output-root is required when --case-name is specified."
        )

    try:
        result = analyze_eml(
            args.eml_file
        )

        saved_files = None

        if args.output_root:
            saved_files = save_analysis_outputs(
                analysis=result,
                investigation_root=args.output_root,
                case_name=args.case_name,
                overwrite=args.overwrite,
            )

    except (
        FileExistsError,
        FileNotFoundError,
        ValueError,
        OSError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 1

    console_result = {
        "file_name": result["file_name"],
        "file_size_bytes": result["file_size_bytes"],
        "sha256": result["sha256"],
        "headers": result["headers"],
        "urls": result["urls"],
    }

    if saved_files is not None:
        console_result[
            "saved_files"
        ] = saved_files

    print(
        json.dumps(
            console_result,
            ensure_ascii=False,
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )