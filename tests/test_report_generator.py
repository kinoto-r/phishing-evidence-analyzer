"""Tests for Japanese Markdown report generation."""

from __future__ import annotations

import unittest

from phishing_evidence_analyzer.report_generator import (
    build_markdown_report,
)


TICK = chr(96)


SAMPLE_ANALYSIS = {
    "file_name": "sample.eml",
    "file_path": r"C:\Sensitive\sample.eml",
    "file_size_bytes": 1234,
    "sha256": "A" * 64,
    "headers": {
        "Date": "Thu, 10 Sep 2026 01:11:45 +0000",
        "From": "Brand <support@example.test>",
        "To": "recipient@example.test",
        "Cc": None,
        "Reply-To": None,
        "Return-Path": "<support@example.test>",
        "Subject": "テストメール",
        "Message-ID": "<test@example.test>",
        "Received": [],
        "Authentication-Results": [],
        "Received-SPF": [],
        "DKIM-Signature": [],
    },
    "urls": [
        {
            "scheme": "https",
            "host": "login[.]example[.]invalid",
            "defanged_url": (
                "hxxps://login[.]example[.]invalid/account"
            ),
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
                "login[.]example[.]invalid",
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
                "result": "none",
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
}


class ReportGeneratorTests(unittest.TestCase):
    def test_report_contains_core_sections(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertIn(
            "# 不審メール解析レポート",
            report,
        )

        self.assertIn(
            "## メール認証結果",
            report,
        )

        self.assertIn(
            "## リンク情報",
            report,
        )

        self.assertIn(
            "## 観測事項",
            report,
        )

        self.assertIn(
            "## 解析範囲",
            report,
        )

    def test_report_contains_sha256(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertIn(
            "A" * 64,
            report,
        )

    def test_report_contains_defanged_url(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertIn(
            "hxxps://login[.]example[.]invalid/account",
            report,
        )

    def test_report_does_not_contain_live_url(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertNotIn(
            "https://login.example.invalid/account",
            report,
        )

    def test_report_does_not_expose_local_path(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertNotIn(
            r"C:\Sensitive",
            report,
        )

    def test_report_contains_authentication_results(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertIn(
            f"| SPF | {TICK}none{TICK} |",
            report,
        )

        self.assertIn(
            f"| DKIM | {TICK}pass{TICK} |",
            report,
        )

        self.assertIn(
            f"| DMARC | {TICK}pass{TICK} |",
            report,
        )

    def test_report_contains_japanese_scope_statement(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertIn(
            "ローカル環境で実施した静的解析",
            report,
        )

        self.assertIn(
            "外部通信は行いません",
            report,
        )


    def test_report_can_include_registration_summary(self) -> None:
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
                    "registration_events": [
                        {
                            "action": "registration",
                            "date": "2020-01-01T00:00:00Z",
                        }
                    ],
                    "statuses": [
                        "active",
                    ],
                    "nameservers": [
                        "ns1.example.test",
                    ],
                },
                {
                    "source": "whois",
                    "registered_domain": "example-registrant.it",
                    "observed_hosts": [
                        "host.example-registrant.it",
                    ],
                    "transport": "tcp/43",
                    "encrypted": False,
                    "registrar": {
                        "name": "EXAMPLE-REG",
                    },
                    "registration_events": [],
                    "statuses": [
                        "ok",
                    ],
                    "nameservers": [
                        "ns1.example.test",
                    ],
                },
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

        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
            registration_summary,
        )

        self.assertIn(
            "## 外部登録情報",
            report,
        )

        self.assertIn(
            "example-registrant.it",
            report,
        )

        self.assertIn(
            "tcp/43",
            report,
        )

        self.assertIn(
            "192.0.2.44",
            report,
        )

        self.assertIn(
            "Example RIR",
            report,
        )

    def test_enriched_report_does_not_claim_no_external_network(
        self,
    ) -> None:
        registration_summary = {
            "network_access_performed": True,
            "domains": [],
            "ip_addresses": [],
            "errors": [],
        }

        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
            registration_summary,
        )

        self.assertNotIn(
            "外部通信は行いません",
            report,
        )

        self.assertIn(
            "明示的に実行されたRDAPまたはWHOIS照会",
            report,
        )

    def test_local_report_remains_local_only(self) -> None:
        report = build_markdown_report(
            SAMPLE_ANALYSIS,
            "2026-09-11T00:00:00Z",
        )

        self.assertNotIn(
            "## 外部登録情報",
            report,
        )

        self.assertIn(
            "外部通信は行いません",
            report,
        )



if __name__ == "__main__":
    unittest.main()