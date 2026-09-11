"""Tests for local-only RDAP candidate generation."""

from __future__ import annotations

import unittest

from phishing_evidence_analyzer.rdap_candidates import (
    build_rdap_candidates,
    normalize_domain_candidate,
    normalize_ip_candidate,
    refang_host,
)


SAMPLE_INDICATORS = {
    "domains": {
        "from_domain": "sw1.example.test",
        "return_path_domain": "sw1.example.test",
        "spf_mailfrom_domain": "sw1.example.test",
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
}


class RdapCandidateTests(unittest.TestCase):
    def test_refang_host(self) -> None:
        self.assertEqual(
            refang_host(
                "login[.]example[.]invalid"
            ),
            "login.example.invalid",
        )

    def test_normalize_domain_candidate(self) -> None:
        self.assertEqual(
            normalize_domain_candidate(
                "Example.TEST"
            ),
            "example.test",
        )

    def test_normalize_ip_candidate(self) -> None:
        self.assertEqual(
            normalize_ip_candidate(
                "192.0.2.44"
            ),
            "192.0.2.44",
        )

    def test_invalid_ip_is_rejected(self) -> None:
        self.assertIsNone(
            normalize_ip_candidate(
                "999.999.999.999"
            )
        )

    def test_build_candidates_deduplicates_domains(self) -> None:
        result = build_rdap_candidates(
            SAMPLE_INDICATORS
        )

        self.assertEqual(
            result["domain_candidates"]["sender_domains"],
            [
                "sw1.example.test",
                "example.test",
            ],
        )

    def test_build_candidates_refangs_link_host(self) -> None:
        result = build_rdap_candidates(
            SAMPLE_INDICATORS
        )

        self.assertEqual(
            result["domain_candidates"]["link_hosts"],
            [
                "login.example.invalid",
            ],
        )

    def test_build_candidates_deduplicates_ips(self) -> None:
        result = build_rdap_candidates(
            SAMPLE_INDICATORS
        )

        self.assertEqual(
            result["ip_candidates"],
            [
                "192.0.2.44",
            ],
        )

    def test_candidate_generation_performs_no_network_access(self) -> None:
        result = build_rdap_candidates(
            SAMPLE_INDICATORS
        )

        self.assertFalse(
            result["network_access_performed"]
        )


if __name__ == "__main__":
    unittest.main()