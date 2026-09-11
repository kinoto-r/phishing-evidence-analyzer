"""WHOIS fallback orchestration.

WHOIS is used only for domain targets whose RDAP lookup
reported that no bootstrap service was available.

Raw WHOIS responses are not preserved here.
"""

from __future__ import annotations

from typing import Any

from phishing_evidence_analyzer.whois_client import (
    WhoisClient,
    WhoisError,
)


RDAP_UNAVAILABLE_PREFIX = (
    "RdapServiceNotFoundError:"
)


def get_whois_fallback_targets(
    rdap_enrichment: dict[str, Any],
) -> list[str]:
    """Extract unique domain targets eligible for WHOIS fallback."""

    targets: list[str] = []
    seen: set[str] = set()

    for error in rdap_enrichment.get(
        "errors",
        [],
    ):
        if error.get(
            "type"
        ) != "domain":
            continue

        message = str(
            error.get(
                "error"
            )
            or ""
        )

        if not message.startswith(
            RDAP_UNAVAILABLE_PREFIX
        ):
            continue

        target = str(
            error.get(
                "target"
            )
            or ""
        ).strip()

        if not target:
            continue

        if target in seen:
            continue

        seen.add(
            target
        )

        targets.append(
            target
        )

    return targets


def enrich_whois_fallback(
    rdap_enrichment: dict[str, Any],
    client: WhoisClient,
) -> dict[str, Any]:
    """Perform explicit WHOIS fallback for RDAP-unavailable domains."""

    targets = get_whois_fallback_targets(
        rdap_enrichment
    )

    results_by_domain: dict[
        str,
        dict[str, Any],
    ] = {}

    errors: list[
        dict[str, Any]
    ] = []

    for target in targets:
        try:
            result = (
                client.resolve_registered_it_domain(
                    target
                )
            )

            if result is None:
                errors.append(
                    {
                        "type": "domain",
                        "target": target,
                        "error": (
                            "WHOIS lookup did not find "
                            "a registered domain."
                        ),
                    }
                )

                continue

            registered_domain = result[
                "registered_domain"
            ]

            if (
                registered_domain
                not in results_by_domain
            ):
                results_by_domain[
                    registered_domain
                ] = {
                    "registered_domain": (
                        registered_domain
                    ),
                    "observed_hosts": [],
                    "whois": result,
                }

            observed_hosts = (
                results_by_domain[
                    registered_domain
                ]["observed_hosts"]
            )

            if target not in observed_hosts:
                observed_hosts.append(
                    target
                )

        except (
            WhoisError,
            ValueError,
            OSError,
        ) as exc:
            errors.append(
                {
                    "type": "domain",
                    "target": target,
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            )

    return {
        "network_access_performed": (
            bool(
                targets
            )
        ),
        "transport": (
            "tcp/43"
            if targets
            else None
        ),
        "encrypted": False,
        "domain_results": list(
            results_by_domain.values()
        ),
        "errors": errors,
    }


def build_registration_summary(
    rdap_enrichment: dict[str, Any],
    whois_enrichment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Combine RDAP and optional WHOIS results."""

    whois_data = (
        whois_enrichment
        or {}
    )

    domains: list[
        dict[str, Any]
    ] = []

    for item in rdap_enrichment.get(
        "domain_results",
        [],
    ):
        rdap = item[
            "rdap"
        ]

        domains.append(
            {
                "source": "rdap",
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

    for item in whois_data.get(
        "domain_results",
        [],
    ):
        whois = item[
            "whois"
        ]

        registration_events = []

        event_map = (
            (
                "registration",
                whois.get(
                    "created"
                ),
            ),
            (
                "last changed",
                whois.get(
                    "last_update"
                ),
            ),
            (
                "expiration",
                whois.get(
                    "expire_date"
                ),
            ),
        )

        for action, date_value in event_map:
            if date_value:
                registration_events.append(
                    {
                        "action": action,
                        "date": date_value,
                    }
                )

        status = whois.get(
            "status"
        )

        domains.append(
            {
                "source": "whois",
                "registered_domain": item[
                    "registered_domain"
                ],
                "observed_hosts": item[
                    "observed_hosts"
                ],
                "whois_server": whois.get(
                    "whois_server"
                ),
                "transport": whois.get(
                    "transport"
                ),
                "encrypted": whois.get(
                    "encrypted"
                ),
                "registrar": whois.get(
                    "registrar"
                ),
                "registration_events": (
                    registration_events
                ),
                "statuses": (
                    [
                        status
                    ]
                    if status
                    else []
                ),
                "nameservers": whois.get(
                    "nameservers",
                    [],
                ),
            }
        )

    unresolved_rdap_errors = []

    resolved_whois_targets = {
        observed_host
        for item in whois_data.get(
            "domain_results",
            [],
        )
        for observed_host in item.get(
            "observed_hosts",
            [],
        )
    }

    for error in rdap_enrichment.get(
        "errors",
        [],
    ):
        target = error.get(
            "target"
        )

        if (
            error.get(
                "type"
            ) == "domain"
            and target in resolved_whois_targets
            and str(
                error.get(
                    "error"
                )
                or ""
            ).startswith(
                RDAP_UNAVAILABLE_PREFIX
            )
        ):
            continue

        unresolved_rdap_errors.append(
            error
        )

    return {
        "network_access_performed": (
            rdap_enrichment.get(
                "network_access_performed",
                False,
            )
            or whois_data.get(
                "network_access_performed",
                False,
            )
        ),
        "domains": domains,
        "ip_addresses": rdap_enrichment.get(
            "ip_results",
            [],
        ),
        "errors": (
            unresolved_rdap_errors
            + whois_data.get(
                "errors",
                [],
            )
        ),
    }