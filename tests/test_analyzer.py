"""Tests for the local EML analyzer."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from phishing_evidence_analyzer.analyzer import (
    analyze_eml,
    calculate_sha256,
)


SAMPLE_EML = (
    b"From: sender@example.test\r\n"
    b"To: recipient@example.test\r\n"
    b"Subject: =?utf-8?b?44OG44K544OI44Oh44O844Or?=\r\n"
    b"Date: Thu, 10 Sep 2026 01:11:45 +0000\r\n"
    b"Message-ID: <test-message@example.test>\r\n"
    b"Return-Path: <bounce@example.test>\r\n"
    b"Authentication-Results: mx.example.test; dkim=pass; spf=pass; dmarc=pass\r\n"
    b"Received-SPF: pass client-ip=192.0.2.10;\r\n"
    b"Received: from mail.example.test (mail.example.test [192.0.2.10]) by mx.example.test;\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Test message body.\r\n"
)


class AnalyzerTests(unittest.TestCase):
    def create_eml(self, directory: Path) -> Path:
        path = directory / "sample.eml"
        path.write_bytes(SAMPLE_EML)
        return path

    def test_calculate_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.create_eml(Path(temp_dir))

            expected = hashlib.sha256(SAMPLE_EML).hexdigest().upper()

            self.assertEqual(
                calculate_sha256(path),
                expected,
            )

    def test_analyze_eml_extracts_expected_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self.create_eml(Path(temp_dir))

            result = analyze_eml(path)

            self.assertEqual(
                result["file_name"],
                "sample.eml",
            )

            self.assertEqual(
                result["file_size_bytes"],
                len(SAMPLE_EML),
            )

            self.assertEqual(
                result["headers"]["From"],
                "sender@example.test",
            )

            self.assertEqual(
                result["headers"]["To"],
                "recipient@example.test",
            )

            self.assertEqual(
                result["headers"]["Subject"],
                "テストメール",
            )

            self.assertEqual(
                result["headers"]["Message-ID"],
                "<test-message@example.test>",
            )

            self.assertEqual(
                len(result["headers"]["Received"]),
                1,
            )

            self.assertEqual(
                len(result["headers"]["Authentication-Results"]),
                1,
            )

    def test_missing_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.eml"

            with self.assertRaises(FileNotFoundError):
                analyze_eml(missing)

    def test_non_eml_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.txt"
            path.write_text(
                "test",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                analyze_eml(path)


if __name__ == "__main__":
    unittest.main()