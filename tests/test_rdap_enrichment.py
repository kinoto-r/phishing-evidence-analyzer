"""Tests for RDAP enrichment orchestration."""

from __future__ import annotations

import unittest

from phishing_evidence_analyzer.rdap_enrichment import (
    build_rdap_summary,
    enrich_rdap,
)


CANDIDATES = {
    "domain_candidates": {
        "sender_domains": [
            "sw1.example.com",
            "example.com",
        ],
        "link_hosts": [
            "login.other.example",
        ],
    },
    "ip_candidates": [
        "192.0.2.44",
    ],
}


class FakeRdapClient:
    def __init__(self) -> None:
        self.domain_calls: list[str] = []
        self.ip_calls: list[str] = []

    def resolve_registered_domain(
        self,
        host: str,
    ) -> dict:
        self.domain_calls.append(
            host
        )

        if host in {
            "sw1.example.com",
            "example.com",
        }:
            return {
                "registered_domain": "example.com",
                "queried_domain": "example.com",
                "rdap_service": (
                    "https://rdap.example.test/"
                ),
                "handle": "EXAMPLE",
                "registrar": {
                    "name": "Example Registrar",
                    "handle": "999",
                    "public_ids": [],
                },
                "registration_events": [],
                "statuses": [],
                "nameservers": [
                    "ns1.example.test",
                ],
            }

        return {
            "registered_domain": "other.example",
            "queried_domain": "other.example",
            "rdap_service": (
                "https://rdap.other.test/"
            ),
            "handle": "OTHER",
            "registrar": {
                "name": "Other Registrar",
                "handle": "888",
                "public_ids": [],
            },
            "registration_events": [],
            "statuses": [],
            "nameservers": [
                "ns1.other.test",
            ],
        }

    def query_ip(
        self,
        ip_value: str,
    ) -> dict:
        self.ip_calls.append(
            ip_value
        )

        return {
            "ip_address": ip_value,
            "rdap_service": (
                "https://rdap.db.ripe.net/"
            ),
            "rir": "RIPE NCC",
            "network": {
                "handle": "TEST-NET",
                "name": "TEST-NETWORK",
                "type": "ASSIGNED PA",
                "country": "NL",
                "start_address": "192.0.2.0",
                "end_address": "192.0.2.255",
                "cidr": [],
            },
            "allocation_organization": {
                "name": "Example Network",
                "handle": "ORG-EXAMPLE",
                "source_role": "registrant",
            },
            "abuse_contacts": [],
        }


class RdapEnrichmentTests(unittest.TestCase):
    def test_network_access_flag_is_true(self) -> None:
        client = FakeRdapClient()

        result = enrich_rdap(
            CANDIDATES,
            client,
        )

        self.assertTrue(
            result[
                "network_access_performed"
            ]
        )

    def test_registered_domains_are_deduplicated(self) -> None:
        client = FakeRdapClient()

        result = enrich_rdap(
            CANDIDATES,
            client,
        )

        registered_domains = {
            item["registered_domain"]
            for item in result[
                "domain_results"
            ]
        }

        self.assertEqual(
            registered_domains,
            {
                "example.com",
                "other.example",
            },
        )

    def test_observed_hosts_are_preserved(self) -> None:
        client = FakeRdapClient()

        result = enrich_rdap(
            CANDIDATES,
            client,
        )

        example_result = next(
            item
            for item in result[
                "domain_results"
            ]
            if item[
                "registered_domain"
            ] == "example.com"
        )

        self.assertEqual(
            example_result[
                "observed_hosts"
            ],
            [
                "sw1.example.com",
                "example.com",
            ],
        )

    def test_ip_result_is_preserved(self) -> None:
        client = FakeRdapClient()

        result = enrich_rdap(
            CANDIDATES,
            client,
        )

        self.assertEqual(
            result[
                "ip_results"
            ][0]["rir"],
            "RIPE NCC",
        )

    def test_summary_separates_registrar_and_nameservers(
        self,
    ) -> None:
        client = FakeRdapClient()

        enrichment = enrich_rdap(
            CANDIDATES,
            client,
        )

        summary = build_rdap_summary(
            enrichment
        )

        first_domain = summary[
            "domains"
        ][0]

        self.assertIn(
            "registrar",
            first_domain,
        )

        self.assertIn(
            "nameservers",
            first_domain,
        )

    def test_summary_separates_ip_allocation_organization(
        self,
    ) -> None:
        client = FakeRdapClient()

        enrichment = enrich_rdap(
            CANDIDATES,
            client,
        )

        summary = build_rdap_summary(
            enrichment
        )

        ip_result = summary[
            "ip_addresses"
        ][0]

        self.assertEqual(
            ip_result[
                "allocation_organization"
            ]["name"],
            "Example Network",
        )


if __name__ == "__main__":
    unittest.main()