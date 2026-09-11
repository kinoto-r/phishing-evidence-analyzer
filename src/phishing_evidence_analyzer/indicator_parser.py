"""Offline extraction of structured email indicators.

This module parses already available message headers and defanged URL
records. It performs no DNS lookups, RDAP queries, HTTP requests,
or other network activity.
"""

from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from typing import Any


def extract_address_domain(
    header_value: str | None,
) -> str | None:
    """Extract and normalize the domain part of an email address."""

    if not header_value:
        return None

    _, address = parseaddr(
        header_value
    )

    if "@" not in address:
        return None

    domain = address.rsplit(
        "@",
        1,
    )[1].strip().lower()

    return domain or None


def extract_auth_result(
    authentication_results: list[str],
    method: str,
) -> str | None:
    """Extract an authentication method result such as SPF or DKIM."""

    pattern = re.compile(
        rf"\b{re.escape(method)}=([A-Za-z0-9_-]+)",
        re.IGNORECASE,
    )

    for header in authentication_results:
        match = pattern.search(
            header
        )

        if match:
            return match.group(
                1
            ).lower()

    return None


def extract_parameter(
    values: list[str],
    parameter: str,
) -> str | None:
    """Extract a semicolon- or whitespace-delimited parameter value."""

    pattern = re.compile(
        rf"\b{re.escape(parameter)}=([^\s;]+)",
        re.IGNORECASE,
    )

    for value in values:
        match = pattern.search(
            value
        )

        if match:
            return match.group(
                1
            ).strip().strip("<>")

    return None


def extract_dkim_signing_domain(
    dkim_headers: list[str],
) -> str | None:
    """Extract the d= domain from DKIM-Signature."""

    pattern = re.compile(
        r"(?:^|;)\s*d=([^;\s]+)",
        re.IGNORECASE,
    )

    for header in dkim_headers:
        match = pattern.search(
            header
        )

        if match:
            return match.group(
                1
            ).lower()

    return None


def normalize_ip(
    value: str | None,
) -> str | None:
    """Return a normalized IP address when the value is valid."""

    if not value:
        return None

    candidate = value.strip().strip(
        "[]"
    )

    try:
        return str(
            ipaddress.ip_address(
                candidate
            )
        )
    except ValueError:
        return None


def extract_received_ips(
    received_headers: list[str],
) -> list[str]:
    """Extract unique IP address candidates from Received headers."""

    results: list[str] = []
    seen: set[str] = set()

    bracket_pattern = re.compile(
        r"\[([0-9A-Fa-f:.]+)\]"
    )

    for header in received_headers:
        for candidate in bracket_pattern.findall(
            header
        ):
            normalized = normalize_ip(
                candidate
            )

            if normalized is None:
                continue

            if normalized in seen:
                continue

            seen.add(
                normalized
            )
            results.append(
                normalized
            )

    return results


def extract_spf_client_ip(
    received_spf_headers: list[str],
) -> str | None:
    """Extract client-ip from Received-SPF."""

    value = extract_parameter(
        received_spf_headers,
        "client-ip",
    )

    return normalize_ip(
        value
    )


def extract_link_hosts(
    url_records: list[dict[str, str]],
) -> list[str]:
    """Extract unique defanged hosts from URL records."""

    hosts: list[str] = []
    seen: set[str] = set()

    for record in url_records:
        host = record.get(
            "host"
        )

        if not host:
            continue

        if host in seen:
            continue

        seen.add(
            host
        )
        hosts.append(
            host
        )

    return hosts


def build_structured_indicators(
    headers: dict[str, Any],
    url_records: list[dict[str, str]],
) -> dict[str, Any]:
    """Build normalized indicators from parsed message data."""

    authentication_results = headers.get(
        "Authentication-Results",
        [],
    )

    received_spf = headers.get(
        "Received-SPF",
        [],
    )

    dkim_headers = headers.get(
        "DKIM-Signature",
        [],
    )

    received_headers = headers.get(
        "Received",
        [],
    )

    from_domain = extract_address_domain(
        headers.get(
            "From"
        )
    )

    return_path_domain = extract_address_domain(
        headers.get(
            "Return-Path"
        )
    )

    smtp_mailfrom = extract_parameter(
        authentication_results,
        "smtp.mailfrom",
    )

    smtp_mailfrom_domain = extract_address_domain(
        smtp_mailfrom
    )

    dmarc_header_from = extract_parameter(
        authentication_results,
        "header.from",
    )

    if dmarc_header_from:
        dmarc_header_from = (
            dmarc_header_from
            .strip()
            .lower()
        )

    spf_client_ip = extract_spf_client_ip(
        received_spf
    )

    received_ip_candidates = extract_received_ips(
        received_headers
    )

    return {
        "domains": {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "spf_mailfrom_domain": smtp_mailfrom_domain,
            "dkim_signing_domain": extract_dkim_signing_domain(
                dkim_headers
            ),
            "dmarc_header_from_domain": dmarc_header_from,
            "link_hosts": extract_link_hosts(
                url_records
            ),
        },
        "ip_addresses": {
            "spf_client_ip": spf_client_ip,
            "received_ip_candidates": received_ip_candidates,
        },
        "authentication": {
            "spf": {
                "result": extract_auth_result(
                    authentication_results,
                    "spf",
                ),
                "smtp_mailfrom_domain": smtp_mailfrom_domain,
                "client_ip": spf_client_ip,
            },
            "dkim": {
                "result": extract_auth_result(
                    authentication_results,
                    "dkim",
                ),
                "signing_domain": extract_dkim_signing_domain(
                    dkim_headers
                ),
            },
            "dmarc": {
                "result": extract_auth_result(
                    authentication_results,
                    "dmarc",
                ),
                "header_from_domain": dmarc_header_from,
            },
        },
    }