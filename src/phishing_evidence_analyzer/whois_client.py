"""WHOIS fallback client for RDAP-unavailable domains.

WHOIS uses TCP port 43 and is not encrypted.

This module intentionally stores only registration metadata
needed for analysis. Registrant, admin, technical contact,
address, telephone, and other personal data are not included
in normalized output.
"""

from __future__ import annotations

import re
import socket
from typing import Any, Callable


IANA_WHOIS_SERVER = "whois.iana.org"
WHOIS_PORT = 43
MAX_WHOIS_BYTES = 1024 * 1024


class WhoisError(RuntimeError):
    """Base exception for WHOIS processing."""


class WhoisServerNotFoundError(
    WhoisError
):
    """Raised when IANA does not provide a WHOIS referral."""


def normalize_hostname(
    value: str,
) -> str:
    """Normalize and validate a hostname."""

    hostname = (
        value
        .strip()
        .strip(".")
        .lower()
    )

    if not hostname:
        raise ValueError(
            "Hostname must not be empty."
        )

    if "://" in hostname:
        raise ValueError(
            "WHOIS server must be a hostname, not a URL."
        )

    try:
        hostname = hostname.encode(
            "idna"
        ).decode(
            "ascii"
        )
    except UnicodeError as exc:
        raise ValueError(
            f"Invalid hostname: {value}"
        ) from exc

    labels = hostname.split(".")

    hostname_pattern = re.compile(
        r"^[a-z0-9-]+$"
    )

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not hostname_pattern.fullmatch(
                label
            )
        ):
            raise ValueError(
                f"Invalid hostname: {value}"
            )

    return hostname


def normalize_domain(
    value: str,
) -> str:
    """Normalize a domain name to ASCII IDNA form."""

    return normalize_hostname(
        value.replace(
            "[.]",
            ".",
        )
    )


def default_query_whois(
    server: str,
    query: str,
    timeout: float,
) -> str:
    """Query a WHOIS server over TCP port 43."""

    safe_server = normalize_hostname(
        server
    )

    safe_query = normalize_domain(
        query
    )

    request = (
        safe_query + "\r\n"
    ).encode(
        "ascii"
    )

    chunks: list[bytes] = []
    total_bytes = 0

    with socket.create_connection(
        (
            safe_server,
            WHOIS_PORT,
        ),
        timeout=timeout,
    ) as sock:
        sock.settimeout(
            timeout
        )

        sock.sendall(
            request
        )

        while True:
            chunk = sock.recv(
                4096
            )

            if not chunk:
                break

            total_bytes += len(
                chunk
            )

            if total_bytes > MAX_WHOIS_BYTES:
                raise WhoisError(
                    "WHOIS response exceeded "
                    "the maximum allowed size."
                )

            chunks.append(
                chunk
            )

    payload = b"".join(
        chunks
    )

    for encoding in (
        "utf-8",
        "latin-1",
    ):
        try:
            return payload.decode(
                encoding
            )
        except UnicodeDecodeError:
            continue

    return payload.decode(
        "utf-8",
        errors="replace",
    )


def parse_iana_whois_server(
    response: str,
) -> str:
    """Extract the registry WHOIS server from IANA output."""

    for line in response.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1,
        )

        if key.strip().lower() != "whois":
            continue

        server = value.strip()

        if server:
            return normalize_hostname(
                server
            )

    raise WhoisServerNotFoundError(
        "IANA WHOIS response did not contain "
        "a registry WHOIS server."
    )


def discover_registry_whois_server(
    domain: str,
    *,
    timeout: float = 10.0,
    query_whois: Callable[
        [str, str, float],
        str,
    ] = default_query_whois,
) -> str:
    """Discover the authoritative WHOIS server through IANA."""

    normalized = normalize_domain(
        domain
    )

    tld = normalized.rsplit(
        ".",
        1,
    )[-1]

    response = query_whois(
        IANA_WHOIS_SERVER,
        tld,
        timeout,
    )

    return parse_iana_whois_server(
        response
    )


def parse_it_whois(
    response: str,
) -> dict[str, Any]:
    """Parse public .it WHOIS output without personal data."""

    result: dict[str, Any] = {
        "domain": None,
        "status": None,
        "created": None,
        "last_update": None,
        "expire_date": None,
        "registrar": {
            "organization": None,
            "name": None,
            "web": None,
            "dnssec": None,
        },
        "nameservers": [],
    }

    section: str | None = None

    nameservers: list[str] = []

    for raw_line in response.splitlines():
        stripped = raw_line.strip()

        if not stripped:
            continue

        if stripped == "Registrar":
            section = "registrar"
            continue

        if stripped == "Nameservers":
            section = "nameservers"
            continue

        if stripped in {
            "Registrant",
            "Admin Contact",
            "Technical Contacts",
            "Tech Contact",
        }:
            section = "private"
            continue

        if section == "private":
            continue

        if section == "nameservers":
            if ":" not in stripped:
                try:
                    nameserver = normalize_hostname(
                        stripped
                    )
                except ValueError:
                    continue

                if nameserver not in nameservers:
                    nameservers.append(
                        nameserver
                    )

                continue

            section = None

        if ":" not in stripped:
            continue

        key, value = stripped.split(
            ":",
            1,
        )

        key = key.strip().lower()
        value = value.strip()

        if section == "registrar":
            registrar = result[
                "registrar"
            ]

            if key == "organization":
                registrar[
                    "organization"
                ] = value or None

            elif key == "name":
                registrar[
                    "name"
                ] = value or None

            elif key == "web":
                registrar[
                    "web"
                ] = value or None

            elif key == "dnssec":
                registrar[
                    "dnssec"
                ] = value or None

            continue

        field_map = {
            "domain": "domain",
            "status": "status",
            "created": "created",
            "last update": "last_update",
            "expire date": "expire_date",
        }

        destination = field_map.get(
            key
        )

        if destination is not None:
            result[
                destination
            ] = value or None

    result[
        "nameservers"
    ] = nameservers

    return result


def is_it_registered(
    parsed: dict[str, Any],
) -> bool:
    """Determine whether .it WHOIS describes a registered domain."""

    status = str(
        parsed.get(
            "status"
        )
        or ""
    ).strip().upper()

    if status in {
        "",
        "AVAILABLE",
        "UNASSIGNABLE",
    }:
        return False

    return bool(
        parsed.get(
            "domain"
        )
    )


class WhoisClient:
    """WHOIS fallback client with registry discovery caching."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        query_whois: Callable[
            [str, str, float],
            str,
        ] = default_query_whois,
    ) -> None:
        if timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        self.timeout = timeout
        self.query_whois = query_whois

        self._registry_server_cache: dict[
            str,
            str,
        ] = {}

        self._query_cache: dict[
            tuple[str, str],
            str,
        ] = {}

    def discover_registry_server(
        self,
        domain: str,
    ) -> str:
        normalized = normalize_domain(
            domain
        )

        tld = normalized.rsplit(
            ".",
            1,
        )[-1]

        if tld in self._registry_server_cache:
            return self._registry_server_cache[
                tld
            ]

        server = discover_registry_whois_server(
            normalized,
            timeout=self.timeout,
            query_whois=self.query_whois,
        )

        self._registry_server_cache[
            tld
        ] = server

        return server

    def _query_registry(
        self,
        server: str,
        domain: str,
    ) -> str:
        key = (
            server,
            domain,
        )

        if key in self._query_cache:
            return self._query_cache[
                key
            ]

        response = self.query_whois(
            server,
            domain,
            self.timeout,
        )

        self._query_cache[
            key
        ] = response

        return response

    def resolve_registered_it_domain(
        self,
        observed_host: str,
    ) -> dict[str, Any] | None:
        """Resolve an observed .it hostname to its registered domain."""

        normalized = normalize_domain(
            observed_host
        )

        if not normalized.endswith(
            ".it"
        ):
            raise ValueError(
                "This parser currently supports .it fallback only."
            )

        server = self.discover_registry_server(
            normalized
        )

        labels = normalized.split(
            "."
        )

        if len(labels) < 2:
            return None

        for index in range(
            0,
            len(labels) - 1,
        ):
            candidate = ".".join(
                labels[
                    index:
                ]
            )

            response = self._query_registry(
                server,
                candidate,
            )

            parsed = parse_it_whois(
                response
            )

            if not is_it_registered(
                parsed
            ):
                continue

            return {
                "registered_domain": (
                    parsed.get(
                        "domain"
                    )
                    or candidate
                ).lower(),
                "queried_domain": candidate,
                "whois_server": server,
                "transport": "tcp/43",
                "encrypted": False,
                "status": parsed.get(
                    "status"
                ),
                "created": parsed.get(
                    "created"
                ),
                "last_update": parsed.get(
                    "last_update"
                ),
                "expire_date": parsed.get(
                    "expire_date"
                ),
                "registrar": parsed.get(
                    "registrar"
                ),
                "nameservers": parsed.get(
                    "nameservers",
                    [],
                ),
            }

        return None