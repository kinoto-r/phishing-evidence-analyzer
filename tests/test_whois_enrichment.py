"""Tests for WHOIS fallback orchestration."""

from __future__ import annotations

import unittest

from phishing_evidence_analyzer.whois_enrichment import (
    build_registration_summary,
    enrich_whois_fallback,
    get_whois_fallback_targets,
)


RDAP_ENRICHMENT = {
    "network_access_performed": True,
    "domain_results": [
        {
            "registered_domain": "example.com",
            "observed_hosts": [
                "mail.example.com",
                "example.com",
            ],
            "rdap": {
                "registered_domain": "example.com",
                "queried_domain": "example.com",
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
            },
        }
    ],
    "ip_results": [
        {
            "ip_address": "192.0.2.44",
            "rir": "RIPE NCC",
        }
    ],
    "errors": [
        {
            "type": "domain",
            "target": (
                "host.example-registrant.it"
            ),
            "error": (
                "RdapServiceNotFoundError: "
                "No RDAP bootstrap service "
                "found for TLD: it"
            ),
        },
        {
            "type": "ip",
            "target": "198.51.100.10",
            "error": "TimeoutError: test timeout",
        },
    ],
}


class FakeWhoisClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def resolve_registered_it_domain(
        self,
        target: str,
    ) -> dict:
        self.calls.append(
            target
        )

        return {
            "registered_domain": (
                "example-registrant.it"
            ),
            "queried_domain": (
                "example-registrant.it"
            ),
            "whois_server": "whois.nic.it",
            "transport": "tcp/43",
            "encrypted": False,
            "status": "ok",
            "created": (
                "2016-03-10 10:00:00"
            ),
            "last_update": (
                "2026-03-10 10:00:00"
            ),
            "expire_date": (
                "2027-03-10"
            ),
            "registrar": {
                "organization": (
                    "Example Registrar S.p.A."
                ),
                "name": "EXAMPLE-REG",
                "web": None,
                "dnssec": "yes",
            },
            "nameservers": [
                "dns.example.test",
                "dns2.example.test",
            ],
        }


class WhoisEnrichmentTests(
    unittest.TestCase
):
    def test_only_rdap_unavailable_domains_are_selected(
        self,
    ) -> None:
        targets = get_whois_fallback_targets(
            RDAP_ENRICHMENT
        )

        self.assertEqual(
            targets,
            [
                "host.example-registrant.it",
            ],
        )

    def test_whois_fallback_runs_for_it_target(
        self,
    ) -> None:
        client = FakeWhoisClient()

        result = enrich_whois_fallback(
            RDAP_ENRICHMENT,
            client,
        )

        self.assertEqual(
            client.calls,
            [
                "host.example-registrant.it",
            ],
        )

        self.assertTrue(
            result[
                "network_access_performed"
            ]
        )

        self.assertEqual(
            result["transport"],
            "tcp/43",
        )

        self.assertFalse(
            result["encrypted"]
        )

    def test_whois_result_preserves_observed_host(
        self,
    ) -> None:
        client = FakeWhoisClient()

        result = enrich_whois_fallback(
            RDAP_ENRICHMENT,
            client,
        )

        item = result[
            "domain_results"
        ][0]

        self.assertEqual(
            item[
                "registered_domain"
            ],
            "example-registrant.it",
        )

        self.assertEqual(
            item[
                "observed_hosts"
            ],
            [
                "host.example-registrant.it",
            ],
        )

    def test_registration_summary_contains_rdap_and_whois(
        self,
    ) -> None:
        client = FakeWhoisClient()

        whois = enrich_whois_fallback(
            RDAP_ENRICHMENT,
            client,
        )

        summary = build_registration_summary(
            RDAP_ENRICHMENT,
            whois,
        )

        sources = {
            item["source"]
            for item in summary[
                "domains"
            ]
        }

        self.assertEqual(
            sources,
            {
                "rdap",
                "whois",
            },
        )

    def test_resolved_rdap_unavailable_error_is_removed(
        self,
    ) -> None:
        client = FakeWhoisClient()

        whois = enrich_whois_fallback(
            RDAP_ENRICHMENT,
            client,
        )

        summary = build_registration_summary(
            RDAP_ENRICHMENT,
            whois,
        )

        domain_errors = [
            error
            for error in summary[
                "errors"
            ]
            if error.get(
                "type"
            ) == "domain"
        ]

        self.assertEqual(
            domain_errors,
            [],
        )

    def test_unrelated_ip_error_is_preserved(
        self,
    ) -> None:
        client = FakeWhoisClient()

        whois = enrich_whois_fallback(
            RDAP_ENRICHMENT,
            client,
        )

        summary = build_registration_summary(
            RDAP_ENRICHMENT,
            whois,
        )

        self.assertEqual(
            summary["errors"],
            [
                {
                    "type": "ip",
                    "target": (
                        "198.51.100.10"
                    ),
                    "error": (
                        "TimeoutError: "
                        "test timeout"
                    ),
                }
            ],
        )

    def test_whois_dates_become_registration_events(
        self,
    ) -> None:
        client = FakeWhoisClient()

        whois = enrich_whois_fallback(
            RDAP_ENRICHMENT,
            client,
        )

        summary = build_registration_summary(
            RDAP_ENRICHMENT,
            whois,
        )

        whois_domain = next(
            item
            for item in summary[
                "domains"
            ]
            if item[
                "source"
            ] == "whois"
        )

        actions = {
            event["action"]
            for event in whois_domain[
                "registration_events"
            ]
        }

        self.assertEqual(
            actions,
            {
                "registration",
                "last changed",
                "expiration",
            },
        )


if __name__ == "__main__":
    unittest.main()