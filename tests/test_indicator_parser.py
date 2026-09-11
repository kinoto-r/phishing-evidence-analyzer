"""Tests for structured offline indicator extraction."""

from __future__ import annotations

import unittest

from phishing_evidence_analyzer.indicator_parser import (
    build_structured_indicators,
    extract_address_domain,
    extract_received_ips,
)


SAMPLE_HEADERS = {
    "From": "Example Sender <support@sw1.example.test>",
    "Return-Path": "<bounce@sw1.example.test>",
    "Received": [
        (
            "from sw4.example.test "
            "(sw4.example.test. [192.0.2.44]) "
            "by mx.example.test"
        )
    ],
    "Authentication-Results": [
        (
            "mx.example.test; "
            "dkim=pass header.i=@example.test; "
            "spf=none "
            "smtp.mailfrom=support@sw1.example.test; "
            "dmarc=pass "
            "header.from=example.test"
        )
    ],
    "Received-SPF": [
        (
            "none client-ip=192.0.2.44;"
        )
    ],
    "DKIM-Signature": [
        (
            "v=1; a=rsa-sha256; "
            "d=example.test; "
            "s=selector1;"
        )
    ],
}


SAMPLE_URLS = [
    {
        "scheme": "https",
        "host": "login[.]example[.]invalid",
        "defanged_url": (
            "hxxps://login[.]example[.]invalid/account"
        ),
    }
]


class IndicatorParserTests(unittest.TestCase):
    def test_extract_address_domain(self) -> None:
        self.assertEqual(
            extract_address_domain(
                "Name <user@sub.example.test>"
            ),
            "sub.example.test",
        )

    def test_extract_received_ips(self) -> None:
        self.assertEqual(
            extract_received_ips(
                SAMPLE_HEADERS["Received"]
            ),
            [
                "192.0.2.44",
            ],
        )

    def test_structured_domains(self) -> None:
        result = build_structured_indicators(
            SAMPLE_HEADERS,
            SAMPLE_URLS,
        )

        domains = result[
            "domains"
        ]

        self.assertEqual(
            domains["from_domain"],
            "sw1.example.test",
        )

        self.assertEqual(
            domains["return_path_domain"],
            "sw1.example.test",
        )

        self.assertEqual(
            domains["spf_mailfrom_domain"],
            "sw1.example.test",
        )

        self.assertEqual(
            domains["dkim_signing_domain"],
            "example.test",
        )

        self.assertEqual(
            domains["dmarc_header_from_domain"],
            "example.test",
        )

        self.assertEqual(
            domains["link_hosts"],
            [
                "login[.]example[.]invalid",
            ],
        )

    def test_structured_authentication(self) -> None:
        result = build_structured_indicators(
            SAMPLE_HEADERS,
            SAMPLE_URLS,
        )

        authentication = result[
            "authentication"
        ]

        self.assertEqual(
            authentication["spf"]["result"],
            "none",
        )

        self.assertEqual(
            authentication["dkim"]["result"],
            "pass",
        )

        self.assertEqual(
            authentication["dmarc"]["result"],
            "pass",
        )

        self.assertEqual(
            authentication["spf"]["client_ip"],
            "192.0.2.44",
        )

    def test_structured_ip_candidates(self) -> None:
        result = build_structured_indicators(
            SAMPLE_HEADERS,
            SAMPLE_URLS,
        )

        self.assertEqual(
            result["ip_addresses"]["spf_client_ip"],
            "192.0.2.44",
        )

        self.assertEqual(
            result["ip_addresses"]["received_ip_candidates"],
            [
                "192.0.2.44",
            ],
        )


if __name__ == "__main__":
    unittest.main()