"""Tests for offline URL extraction and defanging."""

from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from phishing_evidence_analyzer.url_extractor import (
    build_defanged_url_records,
    defang_url,
    extract_urls_from_message,
)


SAMPLE_MESSAGE = (
    b"From: sender@example.test\r\n"
    b"To: recipient@example.test\r\n"
    b"Subject: URL test\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: multipart/alternative; boundary=boundary42\r\n"
    b"\r\n"
    b"--boundary42\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Open https://example.test/login?token=123.\r\n"
    b"\r\n"
    b"--boundary42\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body>"
    b"<a href=\"https://example.test/login?token=123\">Login</a>"
    b"<img src=\"http://track.example.test/pixel.png\">"
    b"</body></html>\r\n"
    b"--boundary42--\r\n"
)


class UrlExtractorTests(unittest.TestCase):
    def parse_message(self):
        return BytesParser(
            policy=policy.default
        ).parsebytes(
            SAMPLE_MESSAGE
        )

    def test_extract_urls_without_duplicates(self) -> None:
        message = self.parse_message()

        urls = extract_urls_from_message(
            message
        )

        self.assertEqual(
            urls,
            [
                "https://example.test/login?token=123",
                "http://track.example.test/pixel.png",
            ],
        )

    def test_defang_https_url(self) -> None:
        self.assertEqual(
            defang_url(
                "https://example.test/login"
            ),
            "hxxps://example[.]test/login",
        )

    def test_defang_http_url(self) -> None:
        self.assertEqual(
            defang_url(
                "http://track.example.test/pixel"
            ),
            "hxxp://track[.]example[.]test/pixel",
        )

    def test_output_records_do_not_contain_live_urls(self) -> None:
        message = self.parse_message()

        records = build_defanged_url_records(
            message
        )

        serialized = str(
            records
        )

        self.assertNotIn(
            "https://",
            serialized,
        )

        self.assertNotIn(
            "http://",
            serialized,
        )

        self.assertIn(
            "hxxps://example[.]test",
            serialized,
        )


if __name__ == "__main__":
    unittest.main()