"""Explicit RDAP enrichment client.

Network access occurs only when this client is invoked explicitly.

The client connects only to:
- IANA RDAP bootstrap registries over HTTPS
- HTTPS RDAP services returned by those registries

It does not connect to observed suspicious hosts.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import quote, urljoin, urlparse
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


IANA_DNS_BOOTSTRAP = (
    "https://data.iana.org/rdap/dns.json"
)

IANA_IPV4_BOOTSTRAP = (
    "https://data.iana.org/rdap/ipv4.json"
)

IANA_IPV6_BOOTSTRAP = (
    "https://data.iana.org/rdap/ipv6.json"
)

USER_AGENT = (
    "phishing-evidence-analyzer/1.0 "
    "(RDAP research client)"
)


RIR_RDAP_HOSTS = frozenset(
    {
        "rdap.arin.net",
        "rdap.db.ripe.net",
        "rdap.apnic.net",
        "rdap.lacnic.net",
        "rdap.afrinic.net",
    }
)


@dataclass(frozen=True)
class JsonFetchResult:
    """JSON response together with the final effective URL."""

    data: dict[str, Any]
    effective_url: str


def unpack_fetch_result(
    result: dict[str, Any] | JsonFetchResult,
    requested_url: str,
) -> tuple[dict[str, Any], str]:
    """Normalize real and test fetcher return values.

    Test fetchers may continue returning plain dictionaries.
    Real network fetches return JsonFetchResult so the final
    response URL after redirects can be preserved.
    """

    if isinstance(
        result,
        JsonFetchResult,
    ):
        return (
            result.data,
            result.effective_url,
        )

    if isinstance(
        result,
        dict,
    ):
        return (
            result,
            requested_url,
        )

    raise RdapError(
        "RDAP fetcher returned an unsupported result type."
    )


def service_base_from_url(
    url: str,
) -> str:
    """Return the HTTPS service origin for an effective URL."""

    parsed = urlparse(
        url
    )

    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
    ):
        raise UnsafeRdapUrlError(
            f"Invalid effective RDAP URL: {url}"
        )

    return (
        f"https://{parsed.netloc}/"
    )

class RdapError(RuntimeError):
    """Base exception for RDAP processing."""


class RdapServiceNotFoundError(RdapError):
    """Raised when no authoritative RDAP service is found."""


class UnsafeRdapUrlError(RdapError):
    """Raised when an RDAP URL is not HTTPS."""


class HttpsOnlyRedirectHandler(
    HTTPRedirectHandler
):
    """Allow only explicitly approved HTTPS redirects."""

    def __init__(
        self,
        allowed_hosts: set[str] | frozenset[str],
    ) -> None:
        super().__init__()

        self.allowed_hosts = {
            host.lower()
            for host in allowed_hosts
        }

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        parsed = urlparse(
            newurl
        )

        if parsed.scheme.lower() != "https":
            raise UnsafeRdapUrlError(
                "RDAP redirect rejected because "
                "the destination is not HTTPS."
            )

        redirect_host = (
            parsed.hostname
            or ""
        ).lower()

        if redirect_host not in self.allowed_hosts:
            raise UnsafeRdapUrlError(
                "RDAP cross-host redirect rejected: "
                f"{redirect_host}"
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


def build_allowed_redirect_hosts(
    request_url: str,
) -> set[str]:
    """Build the HTTPS redirect allowlist for one request.

    Ordinary RDAP and IANA requests may redirect only to the
    same host.

    Requests sent to a known Regional Internet Registry RDAP
    service may also follow HTTPS referrals to another known
    RIR RDAP service.
    """

    parsed = urlparse(
        request_url
    )

    request_host = (
        parsed.hostname
        or ""
    ).lower()

    if not request_host:
        raise UnsafeRdapUrlError(
            "RDAP request URL does not contain a hostname."
        )

    allowed_hosts = {
        request_host
    }

    if request_host in RIR_RDAP_HOSTS:
        allowed_hosts.update(
            RIR_RDAP_HOSTS
        )

    return allowed_hosts

def ensure_https_url(
    url: str,
) -> str:
    """Require HTTPS for every external RDAP request."""

    parsed = urlparse(
        url
    )

    if parsed.scheme.lower() != "https":
        raise UnsafeRdapUrlError(
            f"Non-HTTPS RDAP URL rejected: {url}"
        )

    if not parsed.netloc:
        raise UnsafeRdapUrlError(
            f"Invalid RDAP URL rejected: {url}"
        )

    return url


def default_fetch_json(
    url: str,
    timeout: float,
) -> JsonFetchResult:
    """Retrieve one JSON resource and preserve its final URL."""

    safe_url = ensure_https_url(
        url
    )

    request = Request(
        safe_url,
        headers={
            "Accept": (
                "application/rdap+json, "
                "application/json"
            ),
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )

    allowed_redirect_hosts = (
        build_allowed_redirect_hosts(
            safe_url
        )
    )

    opener = build_opener(
        HttpsOnlyRedirectHandler(
            allowed_redirect_hosts
        )
    )

    with opener.open(
        request,
        timeout=timeout,
    ) as response:
        charset = (
            response.headers.get_content_charset()
            or "utf-8"
        )

        effective_url = response.geturl()

        ensure_https_url(
            effective_url
        )

        payload = response.read()

    parsed = json.loads(
        payload.decode(
            charset
        )
    )

    if not isinstance(
        parsed,
        dict,
    ):
        raise RdapError(
            "RDAP response was not a JSON object."
        )

    return JsonFetchResult(
        data=parsed,
        effective_url=effective_url,
    )


def normalize_domain(
    domain: str,
) -> str:
    """Normalize a domain to lower-case ASCII IDNA form."""

    normalized = (
        domain
        .strip()
        .strip(".")
        .lower()
        .replace("[.]", ".")
    )

    if not normalized:
        raise ValueError(
            "Domain must not be empty."
        )

    labels = normalized.split(".")

    if any(
        not label
        for label in labels
    ):
        raise ValueError(
            f"Invalid domain: {domain}"
        )

    try:
        ascii_domain = ".".join(
            label.encode(
                "idna"
            ).decode(
                "ascii"
            )
            for label in labels
        )
    except UnicodeError as exc:
        raise ValueError(
            f"Invalid internationalized domain: {domain}"
        ) from exc

    return ascii_domain


def choose_https_service(
    urls: list[str],
) -> str:
    """Choose the first HTTPS service URL.

    If service URLs are present but none use HTTPS, reject the
    bootstrap entry explicitly instead of treating it as missing.
    """

    if not urls:
        raise RdapServiceNotFoundError(
            "No RDAP service URL is available."
        )

    unsafe_urls: list[str] = []

    for url in urls:
        try:
            return ensure_https_url(
                url
            )
        except UnsafeRdapUrlError:
            unsafe_urls.append(
                url
            )

    if unsafe_urls:
        raise UnsafeRdapUrlError(
            "RDAP service URLs were found, but none use HTTPS."
        )

    raise RdapServiceNotFoundError(
        "No usable RDAP service is available."
    )


def find_domain_service(
    domain: str,
    bootstrap: dict[str, Any],
) -> str:
    """Find the authoritative RDAP service for a domain TLD."""

    normalized = normalize_domain(
        domain
    )

    tld = normalized.rsplit(
        ".",
        1,
    )[-1]

    for service in bootstrap.get(
        "services",
        [],
    ):
        if (
            not isinstance(service, list)
            or len(service) != 2
        ):
            continue

        keys, urls = service

        normalized_keys = {
            str(key).lower()
            for key in keys
        }

        if tld in normalized_keys:
            return choose_https_service(
                list(urls)
            )

    raise RdapServiceNotFoundError(
        f"No RDAP bootstrap service found "
        f"for TLD: {tld}"
    )


def find_ip_service(
    ip_value: str,
    bootstrap: dict[str, Any],
) -> str:
    """Find the most-specific RDAP service for an IP address."""

    ip_address = ipaddress.ip_address(
        ip_value
    )

    best_prefix_length = -1
    best_urls: list[str] | None = None

    for service in bootstrap.get(
        "services",
        [],
    ):
        if (
            not isinstance(service, list)
            or len(service) != 2
        ):
            continue

        prefixes, urls = service

        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(
                    prefix,
                    strict=False,
                )
            except ValueError:
                continue

            if (
                network.version
                != ip_address.version
            ):
                continue

            if (
                ip_address in network
                and network.prefixlen
                > best_prefix_length
            ):
                best_prefix_length = (
                    network.prefixlen
                )

                best_urls = list(
                    urls
                )

    if best_urls is None:
        raise RdapServiceNotFoundError(
            f"No RDAP bootstrap service found "
            f"for IP: {ip_value}"
        )

    return choose_https_service(
        best_urls
    )


def extract_vcard_values(
    entity: dict[str, Any],
    property_name: str,
) -> list[str]:
    """Extract string values from an RDAP vCard entity."""

    vcard_array = entity.get(
        "vcardArray"
    )

    if (
        not isinstance(vcard_array, list)
        or len(vcard_array) != 2
    ):
        return []

    properties = vcard_array[1]

    if not isinstance(
        properties,
        list,
    ):
        return []

    values: list[str] = []

    for item in properties:
        if (
            not isinstance(item, list)
            or len(item) < 4
        ):
            continue

        if (
            str(item[0]).lower()
            != property_name.lower()
        ):
            continue

        value = item[3]

        if isinstance(
            value,
            str,
        ):
            values.append(
                value
            )

        elif isinstance(
            value,
            list,
        ):
            values.extend(
                str(part)
                for part in value
                if part
            )

    return values


def entity_display_name(
    entity: dict[str, Any],
) -> str | None:
    """Get the best available organization/entity name."""

    for property_name in (
        "org",
        "fn",
    ):
        values = extract_vcard_values(
            entity,
            property_name,
        )

        if values:
            return values[0]

    handle = entity.get(
        "handle"
    )

    if handle:
        return str(
            handle
        )

    return None


def walk_entities(
    entities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flatten nested RDAP entities."""

    result: list[dict[str, Any]] = []

    def visit(
        entity: dict[str, Any],
    ) -> None:
        result.append(
            entity
        )

        nested = entity.get(
            "entities",
            [],
        )

        if isinstance(
            nested,
            list,
        ):
            for child in nested:
                if isinstance(
                    child,
                    dict,
                ):
                    visit(
                        child
                    )

    for entity in entities:
        if isinstance(
            entity,
            dict,
        ):
            visit(
                entity
            )

    return result


def extract_registrar(
    data: dict[str, Any],
) -> dict[str, Any] | None:
    """Extract the registrar entity from domain RDAP data."""

    entities = walk_entities(
        data.get(
            "entities",
            [],
        )
    )

    for entity in entities:
        roles = {
            str(role).lower()
            for role in entity.get(
                "roles",
                [],
            )
        }

        if "registrar" not in roles:
            continue

        return {
            "name": entity_display_name(
                entity
            ),
            "handle": entity.get(
                "handle"
            ),
            "public_ids": entity.get(
                "publicIds",
                [],
            ),
        }

    return None


def extract_events(
    data: dict[str, Any],
) -> list[dict[str, str | None]]:
    """Extract RDAP registration lifecycle events."""

    results: list[dict[str, str | None]] = []

    for event in data.get(
        "events",
        [],
    ):
        if not isinstance(
            event,
            dict,
        ):
            continue

        results.append(
            {
                "action": event.get(
                    "eventAction"
                ),
                "date": event.get(
                    "eventDate"
                ),
            }
        )

    return results


def extract_nameservers(
    data: dict[str, Any],
) -> list[str]:
    """Extract unique domain nameserver names."""

    results: list[str] = []
    seen: set[str] = set()

    for nameserver in data.get(
        "nameservers",
        [],
    ):
        if not isinstance(
            nameserver,
            dict,
        ):
            continue

        value = (
            nameserver.get(
                "ldhName"
            )
            or nameserver.get(
                "unicodeName"
            )
        )

        if not value:
            continue

        normalized = str(
            value
        ).lower()

        if normalized in seen:
            continue

        seen.add(
            normalized
        )

        results.append(
            normalized
        )

    return results


def identify_rir(
    service_url: str,
) -> str | None:
    """Infer the RIR from the authoritative bootstrap service URL."""

    hostname = (
        urlparse(
            service_url
        ).hostname
        or ""
    ).lower()

    rir_markers = {
        "arin.net": "ARIN",
        "ripe.net": "RIPE NCC",
        "apnic.net": "APNIC",
        "lacnic.net": "LACNIC",
        "afrinic.net": "AFRINIC",
    }

    for marker, name in rir_markers.items():
        if (
            hostname == marker
            or hostname.endswith(
                "." + marker
            )
        ):
            return name

    return None


def extract_allocation_organization(
    data: dict[str, Any],
) -> dict[str, Any] | None:
    """Extract the best available allocation organization.

    RDAP does not define one universal field named
    allocation_organization. This function prefers an entity
    whose role is registrant and records the evidence role.
    """

    entities = walk_entities(
        data.get(
            "entities",
            [],
        )
    )

    for entity in entities:
        roles = [
            str(role).lower()
            for role in entity.get(
                "roles",
                [],
            )
        ]

        if "registrant" not in roles:
            continue

        return {
            "name": entity_display_name(
                entity
            ),
            "handle": entity.get(
                "handle"
            ),
            "source_role": "registrant",
        }

    return None


def extract_abuse_contacts(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract abuse-role entities and their public contacts."""

    results: list[dict[str, Any]] = []

    entities = walk_entities(
        data.get(
            "entities",
            [],
        )
    )

    for entity in entities:
        roles = {
            str(role).lower()
            for role in entity.get(
                "roles",
                [],
            )
        }

        if "abuse" not in roles:
            continue

        results.append(
            {
                "name": entity_display_name(
                    entity
                ),
                "handle": entity.get(
                    "handle"
                ),
                "email": extract_vcard_values(
                    entity,
                    "email",
                ),
                "telephone": extract_vcard_values(
                    entity,
                    "tel",
                ),
            }
        )

    return results


def summarize_domain_rdap(
    queried_domain: str,
    service_url: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Normalize domain RDAP data."""

    registered_domain = (
        data.get(
            "ldhName"
        )
        or data.get(
            "unicodeName"
        )
        or queried_domain
    )

    return {
        "registered_domain": str(
            registered_domain
        ).lower(),
        "queried_domain": queried_domain,
        "rdap_service": service_url,
        "handle": data.get(
            "handle"
        ),
        "registrar": extract_registrar(
            data
        ),
        "registration_events": extract_events(
            data
        ),
        "statuses": data.get(
            "status",
            [],
        ),
        "nameservers": extract_nameservers(
            data
        ),
    }


def summarize_ip_rdap(
    ip_value: str,
    bootstrap_service_url: str,
    effective_url: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Normalize IP RDAP data and preserve referral metadata."""

    effective_service = service_base_from_url(
        effective_url
    )

    return {
        "ip_address": ip_value,
        "bootstrap_rdap_service": bootstrap_service_url,
        "effective_rdap_service": effective_service,
        "effective_rdap_url": effective_url,
        "rir": identify_rir(
            effective_url
        ),
        "network": {
            "handle": data.get(
                "handle"
            ),
            "name": data.get(
                "name"
            ),
            "type": data.get(
                "type"
            ),
            "country": data.get(
                "country"
            ),
            "start_address": data.get(
                "startAddress"
            ),
            "end_address": data.get(
                "endAddress"
            ),
            "cidr": data.get(
                "cidr0_cidrs",
                [],
            ),
        },
        "allocation_organization": (
            extract_allocation_organization(
                data
            )
        ),
        "abuse_contacts": extract_abuse_contacts(
            data
        ),
    }

class RdapClient:
    """RDAP client with bootstrap and query caching."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        fetch_json: Callable[
            [str, float],
            dict[str, Any],
        ] = default_fetch_json,
    ) -> None:
        if timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        self.timeout = timeout
        self.fetch_json = fetch_json

        self._bootstrap_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._domain_query_cache: dict[
            str,
            dict[str, Any] | None,
        ] = {}

        self._ip_query_cache: dict[
            str,
            dict[str, Any],
        ] = {}

    def _get_bootstrap(
        self,
        kind: str,
    ) -> dict[str, Any]:
        if kind in self._bootstrap_cache:
            return self._bootstrap_cache[
                kind
            ]

        urls = {
            "dns": IANA_DNS_BOOTSTRAP,
            "ipv4": IANA_IPV4_BOOTSTRAP,
            "ipv6": IANA_IPV6_BOOTSTRAP,
        }

        url = urls[
            kind
        ]

        fetched = self.fetch_json(
            url,
            self.timeout,
        )

        data, _ = unpack_fetch_result(
            fetched,
            url,
        )

        self._bootstrap_cache[
            kind
        ] = data

        return data

    def _query_domain_exact(
        self,
        domain: str,
    ) -> dict[str, Any] | None:
        normalized = normalize_domain(
            domain
        )

        if normalized in self._domain_query_cache:
            return self._domain_query_cache[
                normalized
            ]

        bootstrap = self._get_bootstrap(
            "dns"
        )

        service_url = find_domain_service(
            normalized,
            bootstrap,
        )

        query_url = urljoin(
            service_url.rstrip("/") + "/",
            "domain/"
            + quote(
                normalized,
                safe="",
            ),
        )

        try:
            fetched = self.fetch_json(
                query_url,
                self.timeout,
            )

            data, _ = unpack_fetch_result(
                fetched,
                query_url,
            )
        except HTTPError as exc:
            if exc.code == 404:
                self._domain_query_cache[
                    normalized
                ] = None

                return None

            raise

        result = summarize_domain_rdap(
            normalized,
            service_url,
            data,
        )

        self._domain_query_cache[
            normalized
        ] = result

        registered_domain = result[
            "registered_domain"
        ]

        self._domain_query_cache[
            registered_domain
        ] = result

        return result

    def resolve_registered_domain(
        self,
        observed_host: str,
    ) -> dict[str, Any] | None:
        """Find the registered domain for an observed hostname.

        The host is queried first. If RDAP returns 404, the
        left-most label is removed and the parent is tried.

        The first successful RDAP domain response is treated
        as the registered domain.
        """

        normalized = normalize_domain(
            observed_host
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

            result = self._query_domain_exact(
                candidate
            )

            if result is not None:
                return result

        return None

    def query_ip(
        self,
        ip_value: str,
    ) -> dict[str, Any]:
        """Retrieve and normalize RDAP data for an IP address."""

        normalized_ip = str(
            ipaddress.ip_address(
                ip_value
            )
        )

        if normalized_ip in self._ip_query_cache:
            return self._ip_query_cache[
                normalized_ip
            ]

        ip_object = ipaddress.ip_address(
            normalized_ip
        )

        bootstrap_kind = (
            "ipv4"
            if ip_object.version == 4
            else "ipv6"
        )

        bootstrap = self._get_bootstrap(
            bootstrap_kind
        )

        service_url = find_ip_service(
            normalized_ip,
            bootstrap,
        )

        query_url = urljoin(
            service_url.rstrip("/") + "/",
            "ip/"
            + quote(
                normalized_ip,
                safe=":",
            ),
        )

        fetched = self.fetch_json(
            query_url,
            self.timeout,
        )

        data, effective_url = unpack_fetch_result(
            fetched,
            query_url,
        )

        result = summarize_ip_rdap(
            normalized_ip,
            service_url,
            effective_url,
            data,
        )

        self._ip_query_cache[
            normalized_ip
        ] = result

        return result