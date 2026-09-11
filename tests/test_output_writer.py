"""Tests for safe local output generation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from phishing_evidence_analyzer.output_writer import (
    rewrite_analysis_report,
    save_analysis_outputs,
    validate_case_name,
)


SAMPLE_ANALYSIS = {
    "file_name": "テストメール.eml",
    "file_path": r"C:\Sensitive\Original\テストメール.eml",
    "file_size_bytes": 1234,
    "sha256": "A" * 64,
    "headers": {
        "Date": "Thu, 10 Sep 2026 01:11:45 +0000",
        "From": "sender@example.test",
        "To": "recipient@example.test",
        "Cc": None,
        "Reply-To": None,
        "Return-Path": "<sender@example.test>",
        "Subject": "日本語件名",
        "Message-ID": "<test@example.test>",
        "Received": [],
        "Authentication-Results": [],
        "Received-SPF": [],
        "DKIM-Signature": [],
    },
    "urls": [
        {
            "scheme": "https",
            "host": "example[.]test",
            "defanged_url": "hxxps://example[.]test/login",
        }
    ],
    "indicators": {
        "domains": {
            "from_domain": "example.test",
            "return_path_domain": "example.test",
            "spf_mailfrom_domain": "example.test",
            "dkim_signing_domain": "example.test",
            "dmarc_header_from_domain": "example.test",
            "link_hosts": [
                "example[.]test",
            ],
        },
        "ip_addresses": {
            "spf_client_ip": "192.0.2.44",
            "received_ip_candidates": [
                "192.0.2.44",
            ],
        },
        "authentication": {
            "spf": {
                "result": "pass",
                "smtp_mailfrom_domain": "example.test",
                "client_ip": "192.0.2.44",
            },
            "dkim": {
                "result": "pass",
                "signing_domain": "example.test",
            },
            "dmarc": {
                "result": "pass",
                "header_from_domain": "example.test",
            },
        },
    },
    "rdap_candidates": {
        "domain_candidates": {
            "sender_domains": [
                "example.test",
            ],
            "link_hosts": [
                "example.test",
            ],
        },
        "ip_candidates": [
            "192.0.2.44",
        ],
        "lookup_scope": {
            "domain_rdap": {
                "intended_fields": [
                    "registrar",
                    "registration_events",
                    "statuses",
                    "nameservers",
                ]
            },
            "ip_rdap": {
                "intended_fields": [
                    "network_name",
                    "network_range",
                    "cidr",
                    "rir",
                    "allocation_organization",
                    "abuse_contact",
                ]
            },
        },
        "network_access_performed": False,
    },
}


class OutputWriterTests(unittest.TestCase):
    def test_valid_case_name(self) -> None:
        self.assertEqual(
            validate_case_name(
                "2026-09-10_test-case"
            ),
            "2026-09-10_test-case",
        )

    def test_invalid_case_name_is_rejected(self) -> None:
        invalid_names = (
            "../escape",
            "folder/name",
            r"folder\name",
            "case name",
        )

        for case_name in invalid_names:
            with self.subTest(
                case_name=case_name
            ):
                with self.assertRaises(
                    ValueError
                ):
                    validate_case_name(
                        case_name
                    )

    def test_outputs_are_created(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            expected_keys = (
                "hash_record",
                "header_record",
                "url_record",
                "indicator_record",
                "rdap_candidate_record",
                "report",
            )

            for key in expected_keys:
                self.assertIn(
                    key,
                    result,
                )

                self.assertTrue(
                    Path(
                        result[key]
                    ).exists()
                )

    def test_output_directories_are_correct(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            self.assertEqual(
                Path(
                    result["hash_record"]
                ).parent.name,
                "02_Hash_Records",
            )

            self.assertEqual(
                Path(
                    result["header_record"]
                ).parent.name,
                "03_Header_Text",
            )

            self.assertEqual(
                Path(
                    result["url_record"]
                ).parent.name,
                "03_Header_Text",
            )

            self.assertEqual(
                Path(
                    result["indicator_record"]
                ).parent.name,
                "03_Header_Text",
            )

            self.assertEqual(
                Path(
                    result["rdap_candidate_record"]
                ).parent.name,
                "04_RDAP",
            )

            self.assertEqual(
                Path(
                    result["report"]
                ).parent.name,
                "05_Report",
            )

    def test_absolute_source_path_is_not_written_to_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            json_keys = (
                "header_record",
                "url_record",
                "indicator_record",
                "rdap_candidate_record",
            )

            for key in json_keys:
                content = Path(
                    result[key]
                ).read_text(
                    encoding="utf-8",
                )

                self.assertNotIn(
                    r"C:\Sensitive\Original",
                    content,
                )

    def test_absolute_source_path_is_not_written_to_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            content = Path(
                result["report"]
            ).read_text(
                encoding="utf-8",
            )

            self.assertNotIn(
                r"C:\Sensitive\Original",
                content,
            )

    def test_existing_output_is_not_overwritten_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            with self.assertRaises(
                FileExistsError
            ):
                save_analysis_outputs(
                    analysis=SAMPLE_ANALYSIS,
                    investigation_root=temp_dir,
                    case_name="test-case",
                )

    def test_overwrite_requires_explicit_option(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
                overwrite=True,
            )

            self.assertTrue(
                Path(
                    result["hash_record"]
                ).exists()
            )

            self.assertTrue(
                Path(
                    result["header_record"]
                ).exists()
            )

            self.assertTrue(
                Path(
                    result["url_record"]
                ).exists()
            )

            self.assertTrue(
                Path(
                    result["indicator_record"]
                ).exists()
            )

            self.assertTrue(
                Path(
                    result["rdap_candidate_record"]
                ).exists()
            )

            self.assertTrue(
                Path(
                    result["report"]
                ).exists()
            )

    def test_url_output_contains_only_defanged_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            content = Path(
                result["url_record"]
            ).read_text(
                encoding="utf-8",
            )

            self.assertIn(
                "hxxps://example[.]test/login",
                content,
            )

            self.assertNotIn(
                "https://example.test/login",
                content,
            )

            parsed = json.loads(
                content
            )

            self.assertEqual(
                parsed["url_count"],
                1,
            )

    def test_indicator_output_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            content = Path(
                result["indicator_record"]
            ).read_text(
                encoding="utf-8",
            )

            parsed = json.loads(
                content
            )

            indicators = parsed[
                "indicators"
            ]

            self.assertEqual(
                indicators[
                    "authentication"
                ]["dkim"]["result"],
                "pass",
            )

            self.assertEqual(
                indicators[
                    "ip_addresses"
                ]["spf_client_ip"],
                "192.0.2.44",
            )

    def test_rdap_candidate_output_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            content = Path(
                result["rdap_candidate_record"]
            ).read_text(
                encoding="utf-8",
            )

            parsed = json.loads(
                content
            )

            rdap_candidates = parsed[
                "rdap_candidates"
            ]

            self.assertEqual(
                rdap_candidates[
                    "domain_candidates"
                ]["sender_domains"],
                [
                    "example.test",
                ],
            )

            self.assertEqual(
                rdap_candidates[
                    "ip_candidates"
                ],
                [
                    "192.0.2.44",
                ],
            )

            self.assertFalse(
                rdap_candidates[
                    "network_access_performed"
                ]
            )


    def test_report_can_be_rewritten_with_registration_summary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = save_analysis_outputs(
                analysis=SAMPLE_ANALYSIS,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            registration_summary = {
                "network_access_performed": True,
                "domains": [
                    {
                        "source": "rdap",
                        "registered_domain": "example.com",
                        "observed_hosts": [
                            "mail.example.com",
                        ],
                        "registrar": {
                            "name": "Example Registrar",
                        },
                        "registration_events": [],
                        "statuses": [
                            "active",
                        ],
                        "nameservers": [
                            "ns1.example.test",
                        ],
                    }
                ],
                "ip_addresses": [
                    {
                        "ip_address": "192.0.2.44",
                        "rir": "Example RIR",
                        "network": {
                            "name": "EXAMPLE-NET",
                            "start_address": "192.0.2.0",
                            "end_address": "192.0.2.255",
                        },
                    }
                ],
                "errors": [],
            }

            rewritten_path = rewrite_analysis_report(
                analysis=SAMPLE_ANALYSIS,
                registration_summary=registration_summary,
                investigation_root=temp_dir,
                case_name="test-case",
            )

            self.assertEqual(
                rewritten_path,
                result["report"],
            )

            content = Path(
                rewritten_path
            ).read_text(
                encoding="utf-8",
            )

            self.assertIn(
                "## 外部登録情報",
                content,
            )

            self.assertIn(
                "Example Registrar",
                content,
            )

            self.assertIn(
                "Example RIR",
                content,
            )

            self.assertNotIn(
                r"C:\Sensitive\Original",
                content,
            )



if __name__ == "__main__":
    unittest.main()