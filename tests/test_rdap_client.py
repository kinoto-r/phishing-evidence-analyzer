"""Tests for explicit RDAP enrichment."""

from __future__ import annotations

import io
import unittest
from urllib.error import HTTPError
from urllib.request import Request

from phishing_evidence_analyzer.rdap_client import (
    HttpsOnlyRedirectHandler,
    JsonFetchResult,
    RIR_RDAP_HOSTS,
    RdapClient,
    UnsafeRdapUrlError,
    build_allowed_redirect_hosts,
    extract_abuse_contacts,
    extract_allocation_organization,
    extract_nameservers,
    extract_registrar,
    find_domain_service,
    find_ip_service,
    identify_rir,
    normalize_domain,
)


DOMAIN_BOOTSTRAP = {
    "services": [
        [
            [
                "com",
            ],
            [
                "https://rdap.example.test/",
            ],
        ],
        [
            [
                "it",
            ],
            [
                "https://rdap.it.example.test/",
            ],
        ],
    ]
}


IPV4_BOOTSTRAP = {
    "services": [
        [
            [
                "192.0.2.0/24",
            ],
            [
                "https://rdap.db.ripe.net/",
            ],
        ]
    ]
}


DOMAIN_RDAP = {
    "objectClassName": "domain",
    "handle": "EXAMPLE-COM",
    "ldhName": "EXAMPLE.COM",
    "status": [
        "client transfer prohibited",
    ],
    "events": [
        {
            "eventAction": "registration",
            "eventDate": "2023-08-03T11:26:39Z",
        },
        {
            "eventAction": "expiration",
            "eventDate": "2027-08-03T11:26:39Z",
        },
    ],
    "nameservers": [
        {
            "ldhName": "DNS.EXAMPLE.TEST",
        },
        {
            "ldhName": "DNS2.EXAMPLE.TEST",
        },
    ],
    "entities": [
        {
            "handle": "999",
            "roles": [
                "registrar",
            ],
            "vcardArray": [
                "vcard",
                [
                    [
                        "version",
                        {},
                        "text",
                        "4.0",
                    ],
                    [
                        "fn",
                        {},
                        "text",
                        "Example Registrar",
                    ],
                ],
            ],
            "publicIds": [
                {
                    "type": "IANA Registrar ID",
                    "identifier": "999",
                }
            ],
        }
    ],
}


IP_RDAP = {
    "objectClassName": "ip network",
    "handle": "NET-45-0-0-0-1",
    "name": "EXAMPLE-NET",
    "type": "ASSIGNED PA",
    "country": "NL",
    "startAddress": "192.0.2.0",
    "endAddress": "192.0.2.255",
    "cidr0_cidrs": [
        {
            "v4prefix": "192.0.2.0",
            "length": 8,
        }
    ],
    "entities": [
        {
            "handle": "ORG-EXAMPLE",
            "roles": [
                "registrant",
            ],
            "vcardArray": [
                "vcard",
                [
                    [
                        "version",
                        {},
                        "text",
                        "4.0",
                    ],
                    [
                        "fn",
                        {},
                        "text",
                        "Example Network Operator",
                    ],
                ],
            ],
            "entities": [
                {
                    "handle": "ABUSE-EXAMPLE",
                    "roles": [
                        "abuse",
                    ],
                    "vcardArray": [
                        "vcard",
                        [
                            [
                                "version",
                                {},
                                "text",
                                "4.0",
                            ],
                            [
                                "fn",
                                {},
                                "text",
                                "Abuse Contact",
                            ],
                            [
                                "email",
                                {},
                                "text",
                                "abuse@example.test",
                            ],
                        ],
                    ],
                }
            ],
        }
    ],
}


def make_http_404(
    url: str,
) -> HTTPError:
    return HTTPError(
        url=url,
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=io.BytesIO(),
    )


class FakeFetcher:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(
        self,
        url: str,
        timeout: float,
    ) -> dict:
        self.calls.append(
            url
        )

        if url.endswith(
            "/dns.json"
        ):
            return DOMAIN_BOOTSTRAP

        if url.endswith(
            "/ipv4.json"
        ):
            return IPV4_BOOTSTRAP

        if (
            "/domain/sw1.example.com"
            in url
        ):
            raise make_http_404(
                url
            )

        if (
            "/domain/example.com"
            in url
        ):
            return DOMAIN_RDAP

        if (
            "/ip/192.0.2.44"
            in url
        ):
            return IP_RDAP

        raise AssertionError(
            f"Unexpected test URL: {url}"
        )


IPV4_REFERRAL_BOOTSTRAP = {
    "services": [
        [
            [
                "192.0.2.0/24",
            ],
            [
                "https://rdap.arin.net/registry/",
            ],
        ]
    ]
}


class ReferralFakeFetcher:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(
        self,
        url: str,
        timeout: float,
    ):
        self.calls.append(
            url
        )

        if url.endswith(
            "/ipv4.json"
        ):
            return IPV4_REFERRAL_BOOTSTRAP

        if url.startswith(
            "https://rdap.arin.net/registry/ip/"
        ):
            return JsonFetchResult(
                data=IP_RDAP,
                effective_url=(
                    "https://rdap.db.ripe.net/"
                    "ip/192.0.2.44"
                ),
            )

        raise AssertionError(
            f"Unexpected test URL: {url}"
        )

class RdapClientTests(unittest.TestCase):
    def test_normalize_domain(self) -> None:
        self.assertEqual(
            normalize_domain(
                "SW1.Example.COM."
            ),
            "sw1.example.com",
        )

    def test_domain_service_uses_tld(self) -> None:
        result = find_domain_service(
            "sw1.example.com",
            DOMAIN_BOOTSTRAP,
        )

        self.assertEqual(
            result,
            "https://rdap.example.test/",
        )

    def test_non_https_domain_service_is_rejected(self) -> None:
        bootstrap = {
            "services": [
                [
                    [
                        "com",
                    ],
                    [
                        "http://unsafe.example.test/",
                    ],
                ]
            ]
        }

        with self.assertRaises(
            UnsafeRdapUrlError
        ):
            find_domain_service(
                "example.com",
                bootstrap,
            )

    def test_ip_service_selects_matching_network(self) -> None:
        result = find_ip_service(
            "192.0.2.44",
            IPV4_BOOTSTRAP,
        )

        self.assertEqual(
            result,
            "https://rdap.db.ripe.net/",
        )

    def test_registrar_is_extracted_separately(self) -> None:
        registrar = extract_registrar(
            DOMAIN_RDAP
        )

        self.assertIsNotNone(
            registrar
        )

        self.assertEqual(
            registrar["name"],
            "Example Registrar",
        )

    def test_nameservers_are_extracted_separately(self) -> None:
        nameservers = extract_nameservers(
            DOMAIN_RDAP
        )

        self.assertEqual(
            nameservers,
            [
                "dns.example.test",
                "dns2.example.test",
            ],
        )

    def test_allocation_organization_is_role_based(self) -> None:
        organization = (
            extract_allocation_organization(
                IP_RDAP
            )
        )

        self.assertIsNotNone(
            organization
        )

        self.assertEqual(
            organization["name"],
            "Example Network Operator",
        )

        self.assertEqual(
            organization["source_role"],
            "registrant",
        )

    def test_nested_abuse_contact_is_extracted(self) -> None:
        contacts = extract_abuse_contacts(
            IP_RDAP
        )

        self.assertEqual(
            len(
                contacts
            ),
            1,
        )

        self.assertEqual(
            contacts[0]["email"],
            [
                "abuse@example.test",
            ],
        )

    def test_rir_is_derived_from_bootstrap_service(self) -> None:
        self.assertEqual(
            identify_rir(
                "https://rdap.db.ripe.net/"
            ),
            "RIPE NCC",
        )

    def test_subdomain_falls_back_to_registered_domain(self) -> None:
        fetcher = FakeFetcher()

        client = RdapClient(
            fetch_json=fetcher
        )

        result = client.resolve_registered_domain(
            "sw1.example.com"
        )

        self.assertIsNotNone(
            result
        )

        self.assertEqual(
            result["registered_domain"],
            "example.com",
        )

        self.assertEqual(
            result["queried_domain"],
            "example.com",
        )

    def test_registered_domain_result_is_cached(self) -> None:
        fetcher = FakeFetcher()

        client = RdapClient(
            fetch_json=fetcher
        )

        first = client.resolve_registered_domain(
            "sw1.example.com"
        )

        call_count_after_first = len(
            fetcher.calls
        )

        second = client.resolve_registered_domain(
            "example.com"
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            len(
                fetcher.calls
            ),
            call_count_after_first,
        )

    def test_ip_lookup_returns_separate_categories(self) -> None:
        fetcher = FakeFetcher()

        client = RdapClient(
            fetch_json=fetcher
        )

        result = client.query_ip(
            "192.0.2.44"
        )

        self.assertEqual(
            result["rir"],
            "RIPE NCC",
        )

        self.assertEqual(
            result["network"]["name"],
            "EXAMPLE-NET",
        )

        self.assertEqual(
            result[
                "allocation_organization"
            ]["name"],
            "Example Network Operator",
        )

        self.assertEqual(
            result[
                "abuse_contacts"
            ][0]["email"],
            [
                "abuse@example.test",
            ],
        )


    def test_rir_request_allows_known_rir_hosts(self) -> None:
        allowed = build_allowed_redirect_hosts(
            "https://rdap.arin.net/registry/ip/192.0.2.44"
        )

        self.assertEqual(
            allowed,
            set(
                RIR_RDAP_HOSTS
            ),
        )

    def test_non_rir_request_allows_only_same_host(self) -> None:
        allowed = build_allowed_redirect_hosts(
            "https://rdap.verisign.com/com/v1/domain/example.com"
        )

        self.assertEqual(
            allowed,
            {
                "rdap.verisign.com",
            },
        )

    def test_known_rir_cross_host_redirect_is_allowed(
        self,
    ) -> None:
        handler = HttpsOnlyRedirectHandler(
            set(
                RIR_RDAP_HOSTS
            )
        )

        request = Request(
            "https://rdap.arin.net/registry/ip/192.0.2.44"
        )

        redirected = handler.redirect_request(
            request,
            None,
            301,
            "Moved Permanently",
            {},
            "https://rdap.db.ripe.net/ip/192.0.2.44",
        )

        self.assertIsNotNone(
            redirected
        )

        self.assertEqual(
            redirected.full_url,
            "https://rdap.db.ripe.net/ip/192.0.2.44",
        )

    def test_unrelated_cross_host_redirect_is_rejected(
        self,
    ) -> None:
        handler = HttpsOnlyRedirectHandler(
            set(
                RIR_RDAP_HOSTS
            )
        )

        request = Request(
            "https://rdap.arin.net/registry/ip/192.0.2.44"
        )

        with self.assertRaises(
            UnsafeRdapUrlError
        ):
            handler.redirect_request(
                request,
                None,
                301,
                "Moved Permanently",
                {},
                "https://unexpected.example.test/ip/192.0.2.44",
            )

    def test_rir_redirect_to_http_is_rejected(
        self,
    ) -> None:
        handler = HttpsOnlyRedirectHandler(
            set(
                RIR_RDAP_HOSTS
            )
        )

        request = Request(
            "https://rdap.arin.net/registry/ip/192.0.2.44"
        )

        with self.assertRaises(
            UnsafeRdapUrlError
        ):
            handler.redirect_request(
                request,
                None,
                301,
                "Moved Permanently",
                {},
                "http://rdap.db.ripe.net/ip/192.0.2.44",
            )
    def test_ip_referral_records_effective_rdap_service(
        self,
    ) -> None:
        fetcher = ReferralFakeFetcher()

        client = RdapClient(
            fetch_json=fetcher
        )

        result = client.query_ip(
            "192.0.2.44"
        )

        self.assertEqual(
            result[
                "bootstrap_rdap_service"
            ],
            "https://rdap.arin.net/registry/",
        )

        self.assertEqual(
            result[
                "effective_rdap_service"
            ],
            "https://rdap.db.ripe.net/",
        )

        self.assertEqual(
            result[
                "effective_rdap_url"
            ],
            (
                "https://rdap.db.ripe.net/"
                "ip/192.0.2.44"
            ),
        )

        self.assertEqual(
            result["rir"],
            "RIPE NCC",
        )

    def test_plain_dict_fetcher_remains_supported(
        self,
    ) -> None:
        fetcher = FakeFetcher()

        client = RdapClient(
            fetch_json=fetcher
        )

        result = client.query_ip(
            "192.0.2.44"
        )

        self.assertEqual(
            result["rir"],
            "RIPE NCC",
        )
if __name__ == "__main__":
    unittest.main()