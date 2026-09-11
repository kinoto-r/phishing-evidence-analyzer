"""Offline URL extraction and defanging utilities.

This module treats URLs as text only.
It does not open URLs, perform DNS resolution, or make network requests.
"""

from __future__ import annotations

import html
import re
from email.message import Message
from urllib.parse import urlsplit, urlunsplit


URL_PATTERN = re.compile(
    r"""https?://[^\s<>"']+""",
    re.IGNORECASE,
)


def extract_text_parts(message: Message) -> list[str]:
    """Extract text/plain and text/html MIME content without rendering it."""

    texts: list[str] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        disposition = part.get_content_disposition()

        if disposition == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in {
            "text/plain",
            "text/html",
        }:
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if isinstance(content, bytes):
            charset = part.get_content_charset() or "utf-8"

            content = content.decode(
                charset,
                errors="replace",
            )

        if not isinstance(content, str):
            continue

        texts.append(
            html.unescape(content)
        )

    return texts


def normalize_extracted_url(url: str) -> str:
    """Remove common trailing punctuation from extracted URL text."""

    return url.rstrip(
        ".,;!?"
    )


def extract_urls_from_message(message: Message) -> list[str]:
    """Extract unique HTTP(S) URL strings without accessing them."""

    urls: list[str] = []
    seen: set[str] = set()

    for text in extract_text_parts(message):
        for match in URL_PATTERN.findall(text):
            url = normalize_extracted_url(match)

            if not url:
                continue

            if url in seen:
                continue

            seen.add(url)
            urls.append(url)

    return urls


def defang_url(url: str) -> str:
    """Convert an HTTP(S) URL into a safer non-clickable representation."""

    parsed = urlsplit(url)

    scheme_lower = parsed.scheme.lower()

    if scheme_lower == "https":
        safe_scheme = "hxxps"
    elif scheme_lower == "http":
        safe_scheme = "hxxp"
    else:
        raise ValueError(
            f"Unsupported URL scheme: {parsed.scheme}"
        )

    safe_netloc = parsed.netloc.replace(
        ".",
        "[.]",
    )

    return urlunsplit(
        (
            safe_scheme,
            safe_netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def build_defanged_url_records(
    message: Message,
) -> list[dict[str, str]]:
    """Extract URLs and return only defanged representations for output."""

    records: list[dict[str, str]] = []

    for url in extract_urls_from_message(message):
        parsed = urlsplit(url)

        host = parsed.hostname or ""

        records.append(
            {
                "scheme": parsed.scheme.lower(),
                "host": host.replace(".", "[.]"),
                "defanged_url": defang_url(url),
            }
        )

    return records