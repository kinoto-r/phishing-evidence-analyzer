"""Build RDAP lookup candidates from locally extracted indicators.

This module performs no network access.

It separates observed values from future RDAP lookup operations.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def refang_host(
    host: str,
) -> str:
    """Convert a defanged host back to a normalized lookup value.

    This function only transforms text.
    It does not resolve or access the host.
    """

    return (
        host
        .strip()
        .lower()
        .replace("[.]", ".")
    )


def normalize_domain_candidate(
    value: str | None,
) -> str | None:
    """Normalize a domain or hostname for future RDAP lookup."""

    if value is None:
        return None

    candidate = refang_host(
        value
    ).strip(".")

    if not candidate:
        return None

    if "://" in candidate:
        return None

    if candidate.startswith("."):
        return None

    return candidate


def normalize_ip_candidate(
    value: str | None,
) -> str | None:
    """Validate and normalize an IP address candidate."""

    if not value:
        return None

    try:
        return str(
            ipaddress.ip_address(
                value.strip()
            )
        )
    except ValueError:
        return None


def unique_values(
    values: list[str | None],
) -> list[str]:
    """Return unique non-empty values while preserving order."""

    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        if value is None:
            continue

        if value in seen:
            continue

        seen.add(
            value
        )

        result.append(
            value
        )

    return result


def build_rdap_candidates(
    indicators: dict[str, Any],
) -> dict[str, Any]:
    """Build local-only RDAP lookup candidates."""

    domains = indicators.get(
        "domains",
        {},
    )

    ip_addresses = indicators.get(
        "ip_addresses",
        {},
    )

    sender_domain_values = [
        normalize_domain_candidate(
            domains.get(
                "from_domain"
            )
        ),
        normalize_domain_candidate(
            domains.get(
                "return_path_domain"
            )
        ),
        normalize_domain_candidate(
            domains.get(
                "spf_mailfrom_domain"
            )
        ),
        normalize_domain_candidate(
            domains.get(
                "dkim_signing_domain"
            )
        ),
        normalize_domain_candidate(
            domains.get(
                "dmarc_header_from_domain"
            )
        ),
    ]

    sender_domains = unique_values(
        sender_domain_values
    )

    link_hosts = unique_values(
        [
            normalize_domain_candidate(
                value
            )
            for value in domains.get(
                "link_hosts",
                []
            )
        ]
    )

    ip_candidates = unique_values(
        [
            normalize_ip_candidate(
                ip_addresses.get(
                    "spf_client_ip"
                )
            ),
            *[
                normalize_ip_candidate(
                    value
                )
                for value in ip_addresses.get(
                    "received_ip_candidates",
                    []
                )
            ],
        ]
    )

    return {
        "domain_candidates": {
            "sender_domains": sender_domains,
            "link_hosts": link_hosts,
        },
        "ip_candidates": ip_candidates,
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
    }