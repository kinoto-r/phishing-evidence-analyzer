"""Tests for WHOIS fallback processing."""

from __future__ import annotations

import unittest

from phishing_evidence_analyzer.whois_client import (
    WhoisClient,
    WhoisServerNotFoundError,
    is_it_registered,
    parse_iana_whois_server,
    parse_it_whois,
)


IANA_IT_RESPONSE = """
domain:       IT
organisation: IIT - CNR
whois:        whois.nic.it
"""


AVAILABLE_RESPONSE = """
Domain:             host.example-registrant.it
Status:             AVAILABLE
"""


REGISTERED_RESPONSE = """
Domain:             example-registrant.it
Status:             ok
Signed:             no
Created:            2016-03-10 10:00:00
Last Update:        2026-03-10 10:00:00
Expire Date:        2027-03-10

Registrant
Organization:       Private Example Person
Address:            Private Address
Phone:              +00 000000
Email:              private@example.test

Admin Contact
Name:               Private Admin

Registrar
Organization:       Example Registrar S.p.A.
Name:               EXAMPLE-REG
Web:                https://registrar.example.test
DNSSEC:             yes

Nameservers
dns.example.test
dns2.example.test
"""


class FakeWhoisQuery:
    def __init__(self) -> None:
        self.calls: list[
            tuple[str, str]
        ] = []

    def __call__(
        self,
        server: str,
        query: str,
        timeout: float,
    ) -> str:
        self.calls.append(
            (
                server,
                query,
            )
        )

        if (
            server == "whois.iana.org"
            and query == "it"
        ):
            return IANA_IT_RESPONSE

        if (
            server == "whois.nic.it"
            and query
            == "host.example-registrant.it"
        ):
            return AVAILABLE_RESPONSE

        if (
            server == "whois.nic.it"
            and query
            == "example-registrant.it"
        ):
            return REGISTERED_RESPONSE

        raise AssertionError(
            f"Unexpected WHOIS query: "
            f"{server} {query}"
        )


class WhoisClientTests(unittest.TestCase):
    def test_parse_iana_whois_server(self) -> None:
        self.assertEqual(
            parse_iana_whois_server(
                IANA_IT_RESPONSE
            ),
            "whois.nic.it",
        )

    def test_missing_iana_referral_is_rejected(self) -> None:
        with self.assertRaises(
            WhoisServerNotFoundError
        ):
            parse_iana_whois_server(
                "domain: EXAMPLE"
            )

    def test_available_domain_is_not_registered(self) -> None:
        parsed = parse_it_whois(
            AVAILABLE_RESPONSE
        )

        self.assertFalse(
            is_it_registered(
                parsed
            )
        )

    def test_it_registration_fields_are_parsed(self) -> None:
        parsed = parse_it_whois(
            REGISTERED_RESPONSE
        )

        self.assertEqual(
            parsed["domain"],
            "example-registrant.it",
        )

        self.assertEqual(
            parsed["status"],
            "ok",
        )

        self.assertEqual(
            parsed["created"],
            "2016-03-10 10:00:00",
        )

        self.assertEqual(
            parsed["registrar"]["name"],
            "EXAMPLE-REG",
        )

        self.assertEqual(
            parsed["nameservers"],
            [
                "dns.example.test",
                "dns2.example.test",
            ],
        )

    def test_private_sections_are_not_preserved(self) -> None:
        parsed = parse_it_whois(
            REGISTERED_RESPONSE
        )

        serialized = repr(
            parsed
        )

        self.assertNotIn(
            "Private Example Person",
            serialized,
        )

        self.assertNotIn(
            "Private Address",
            serialized,
        )

        self.assertNotIn(
            "private@example.test",
            serialized,
        )

    def test_subdomain_falls_back_to_registered_it_domain(
        self,
    ) -> None:
        query = FakeWhoisQuery()

        client = WhoisClient(
            query_whois=query
        )

        result = client.resolve_registered_it_domain(
            "host.example-registrant.it"
        )

        self.assertIsNotNone(
            result
        )

        self.assertEqual(
            result["registered_domain"],
            "example-registrant.it",
        )

        self.assertEqual(
            result["whois_server"],
            "whois.nic.it",
        )

        self.assertFalse(
            result["encrypted"]
        )

    def test_iana_registry_lookup_is_cached(self) -> None:
        query = FakeWhoisQuery()

        client = WhoisClient(
            query_whois=query
        )

        client.resolve_registered_it_domain(
            "host.example-registrant.it"
        )

        client.discover_registry_server(
            "example.it"
        )

        iana_calls = [
            call
            for call in query.calls
            if call[0] == "whois.iana.org"
        ]

        self.assertEqual(
            len(
                iana_calls
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()