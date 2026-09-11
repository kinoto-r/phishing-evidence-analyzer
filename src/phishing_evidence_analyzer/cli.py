"""Command-line interface for Phishing Evidence Analyzer."""

from __future__ import annotations

import argparse
import json
import sys

from phishing_evidence_analyzer.analyzer import (
    analyze_eml,
)
from phishing_evidence_analyzer.output_writer import (
    ensure_rdap_enrichment_outputs_available,
    ensure_whois_outputs_available,
    rewrite_analysis_report,
    save_analysis_outputs,
    save_rdap_enrichment_outputs,
    save_whois_outputs,
)
from phishing_evidence_analyzer.rdap_client import (
    RdapClient,
)
from phishing_evidence_analyzer.rdap_enrichment import (
    build_rdap_summary,
    enrich_rdap,
)
from phishing_evidence_analyzer.whois_client import (
    WhoisClient,
)
from phishing_evidence_analyzer.whois_enrichment import (
    build_registration_summary,
    enrich_whois_fallback,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-evidence-analyzer",
        description=(
            "Perform local EML analysis. "
            "Optional RDAP and WHOIS enrichment "
            "require explicit command-line options."
        ),
    )

    parser.add_argument(
        "eml_file",
        help="Path to the .eml file to analyze.",
    )

    parser.add_argument(
        "--output-root",
        help="Investigation workspace root.",
    )

    parser.add_argument(
        "--case-name",
        help="Safe filename prefix for generated output.",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Allow generated output files to be overwritten. "
            "Disabled by default."
        ),
    )

    parser.add_argument(
        "--rdap",
        action="store_true",
        help=(
            "Explicitly enable external HTTPS RDAP enrichment. "
            "Without this option, no RDAP network access occurs."
        ),
    )

    parser.add_argument(
        "--whois-fallback",
        action="store_true",
        help=(
            "Explicitly enable unencrypted TCP port 43 WHOIS "
            "fallback for domains without RDAP bootstrap support. "
            "Requires --rdap."
        ),
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.output_root and not args.case_name:
        parser.error(
            "--case-name is required when "
            "--output-root is specified."
        )

    if args.case_name and not args.output_root:
        parser.error(
            "--output-root is required when "
            "--case-name is specified."
        )

    if args.rdap and not args.output_root:
        parser.error(
            "--rdap requires --output-root "
            "and --case-name."
        )

    if args.whois_fallback and not args.rdap:
        parser.error(
            "--whois-fallback requires --rdap."
        )

    try:
        result = analyze_eml(
            args.eml_file
        )

        saved_files = None
        rdap_enrichment = None
        rdap_summary = None
        whois_enrichment = None
        registration_summary = None

        if args.output_root:
            if args.rdap:
                ensure_rdap_enrichment_outputs_available(
                    args.output_root,
                    args.case_name,
                    overwrite=args.overwrite,
                )

            if args.whois_fallback:
                ensure_whois_outputs_available(
                    args.output_root,
                    args.case_name,
                    overwrite=args.overwrite,
                )

            saved_files = save_analysis_outputs(
                analysis=result,
                investigation_root=args.output_root,
                case_name=args.case_name,
                overwrite=args.overwrite,
            )

        if args.rdap:
            rdap_client = RdapClient()

            rdap_enrichment = enrich_rdap(
                result[
                    "rdap_candidates"
                ],
                rdap_client,
            )

            rdap_summary = build_rdap_summary(
                rdap_enrichment
            )

            registration_summary = (
                build_registration_summary(
                    rdap_enrichment
                )
            )

            rdap_saved_files = (
                save_rdap_enrichment_outputs(
                    analysis=result,
                    enrichment=rdap_enrichment,
                    summary=rdap_summary,
                    investigation_root=(
                        args.output_root
                    ),
                    case_name=args.case_name,
                    overwrite=args.overwrite,
                )
            )

            if saved_files is not None:
                saved_files.update(
                    rdap_saved_files
                )

        if args.whois_fallback:
            if rdap_enrichment is None:
                raise RuntimeError(
                    "RDAP enrichment is required "
                    "before WHOIS fallback."
                )

            whois_client = WhoisClient()

            whois_enrichment = (
                enrich_whois_fallback(
                    rdap_enrichment,
                    whois_client,
                )
            )

            registration_summary = (
                build_registration_summary(
                    rdap_enrichment,
                    whois_enrichment,
                )
            )

            whois_saved_files = (
                save_whois_outputs(
                    analysis=result,
                    whois_enrichment=(
                        whois_enrichment
                    ),
                    registration_summary=(
                        registration_summary
                    ),
                    investigation_root=(
                        args.output_root
                    ),
                    case_name=args.case_name,
                    overwrite=args.overwrite,
                )
            )

            if saved_files is not None:
                saved_files.update(
                    whois_saved_files
                )

        if (
            args.rdap
            and registration_summary is not None
        ):
            report_path = rewrite_analysis_report(
                analysis=result,
                registration_summary=registration_summary,
                investigation_root=args.output_root,
                case_name=args.case_name,
            )

            if saved_files is not None:
                saved_files[
                    "report"
                ] = report_path

    except (
        FileExistsError,
        FileNotFoundError,
        ValueError,
        RuntimeError,
        OSError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 1

    console_result = {
        "file_name": result[
            "file_name"
        ],
        "file_size_bytes": result[
            "file_size_bytes"
        ],
        "sha256": result[
            "sha256"
        ],
        "headers": result[
            "headers"
        ],
        "urls": result[
            "urls"
        ],
        "indicators": result[
            "indicators"
        ],
        "rdap_candidates": result[
            "rdap_candidates"
        ],
    }

    if rdap_summary is not None:
        console_result[
            "rdap_summary"
        ] = rdap_summary

    if whois_enrichment is not None:
        console_result[
            "whois_fallback"
        ] = whois_enrichment

    if registration_summary is not None:
        console_result[
            "registration_summary"
        ] = registration_summary

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