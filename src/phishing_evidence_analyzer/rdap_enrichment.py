"""RDAP enrichment orchestration.

This module is used only when external RDAP enrichment
has been explicitly requested by the user.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError

from phishing_evidence_analyzer.rdap_client import (
    RdapClient,
    RdapError,
)


def enrich_rdap(
    candidates: dict[str, Any],
    client: RdapClient,
) -> dict[str, Any]:
    """Perform explicit RDAP enrichment.

    Duplicate observed hosts that resolve to the same registered
    domain are merged into one result.
    """

    domain_candidates = candidates.get(
        "domain_candidates",
        {},
    )

    observed_hosts: list[str] = []

    for category in (
        "sender_domains",
        "link_hosts",
    ):
        for value in domain_candidates.get(
            category,
            [],
        ):
            if value not in observed_hosts:
                observed_hosts.append(
                    value
                )

    domain_results_by_registered: dict[
        str,
        dict[str, Any],
    ] = {}

    errors: list[dict[str, Any]] = []

    for observed_host in observed_hosts:
        try:
            result = client.resolve_registered_domain(
                observed_host
            )

            if result is None:
                errors.append(
                    {
                        "type": "domain",
                        "target": observed_host,
                        "error": (
                            "No registered domain "
                            "RDAP object was found."
                        ),
                    }
                )

                continue

            registered_domain = result[
                "registered_domain"
            ]

            if (
                registered_domain
                not in domain_results_by_registered
            ):
                domain_results_by_registered[
                    registered_domain
                ] = {
                    "registered_domain": (
                        registered_domain
                    ),
                    "observed_hosts": [],
                    "rdap": result,
                }

            host_list = (
                domain_results_by_registered[
                    registered_domain
                ]["observed_hosts"]
            )

            if observed_host not in host_list:
                host_list.append(
                    observed_host
                )

        except (
            HTTPError,
            URLError,
            TimeoutError,
            RdapError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            errors.append(
                {
                    "type": "domain",
                    "target": observed_host,
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            )

    ip_results: list[
        dict[str, Any]
    ] = []

    for ip_value in candidates.get(
        "ip_candidates",
        [],
    ):
        try:
            result = client.query_ip(
                ip_value
            )

            ip_results.append(
                result
            )

        except (
            HTTPError,
            URLError,
            TimeoutError,
            RdapError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            errors.append(
                {
                    "type": "ip",
                    "target": ip_value,
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            )

    return {
        "network_access_performed": True,
        "domain_results": list(
            domain_results_by_registered.values()
        ),
        "ip_results": ip_results,
        "errors": errors,
    }


def build_rdap_summary(
    enrichment: dict[str, Any],
) -> dict[str, Any]:
    """Create a compact human-oriented RDAP summary."""

    domains: list[
        dict[str, Any]
    ] = []

    for item in enrichment.get(
        "domain_results",
        [],
    ):
        rdap = item[
            "rdap"
        ]

        domains.append(
            {
                "registered_domain": item[
                    "registered_domain"
                ],
                "observed_hosts": item[
                    "observed_hosts"
                ],
                "registrar": rdap.get(
                    "registrar"
                ),
                "registration_events": rdap.get(
                    "registration_events",
                    [],
                ),
                "statuses": rdap.get(
                    "statuses",
                    [],
                ),
                "nameservers": rdap.get(
                    "nameservers",
                    [],
                ),
            }
        )

    ip_addresses: list[
        dict[str, Any]
    ] = []

    for item in enrichment.get(
        "ip_results",
        [],
    ):
        ip_addresses.append(
            {
                "ip_address": item.get(
                    "ip_address"
                ),
                "bootstrap_rdap_service": item.get(
                    "bootstrap_rdap_service"
                ),
                "effective_rdap_service": item.get(
                    "effective_rdap_service"
                ),
                "effective_rdap_url": item.get(
                    "effective_rdap_url"
                ),
                "rir": item.get(
                    "rir"
                ),
                "network": item.get(
                    "network"
                ),
                "allocation_organization": item.get(
                    "allocation_organization"
                ),
                "abuse_contacts": item.get(
                    "abuse_contacts",
                    [],
                ),
            }
        )

    return {
        "network_access_performed": enrichment.get(
            "network_access_performed",
            False,
        ),
        "domains": domains,
        "ip_addresses": ip_addresses,
        "errors": enrichment.get(
            "errors",
            [],
        ),
    }