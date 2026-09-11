"""Markdown report generation for Phishing Evidence Analyzer.

Reports are generated entirely from locally parsed data.
This module performs no network access.
"""

from __future__ import annotations

from typing import Any


TICK = chr(96)


def code_value(
    value: Any,
) -> str:
    """Format a value as inline Markdown code safely."""

    if value is None:
        text = "（なし）"
    elif isinstance(value, str) and not value.strip():
        text = "（空）"
    else:
        text = str(value)

    return f"{TICK}{text}{TICK}"


def build_markdown_report(
    analysis: dict[str, Any],
    recorded_at_utc: str,
) -> str:
    """Build a human-readable Japanese Markdown analysis report."""

    headers = analysis["headers"]
    indicators = analysis["indicators"]

    domains = indicators["domains"]
    ip_addresses = indicators["ip_addresses"]
    authentication = indicators["authentication"]
    urls = analysis["urls"]

    lines: list[str] = []

    lines.extend(
        [
            "# 不審メール解析レポート",
            "",
            "## 解析情報",
            "",
            f"- ファイル名: {code_value(analysis['file_name'])}",
            f"- ファイルサイズ: {code_value(str(analysis['file_size_bytes']) + ' bytes')}",
            f"- SHA-256: {code_value(analysis['sha256'])}",
            f"- レポート生成日時（UTC）: {code_value(recorded_at_utc)}",
            "",
            "## メール概要",
            "",
            f"- Date: {code_value(headers.get('Date'))}",
            f"- From: {code_value(headers.get('From'))}",
            f"- To: {code_value(headers.get('To'))}",
            f"- Reply-To: {code_value(headers.get('Reply-To'))}",
            f"- Return-Path: {code_value(headers.get('Return-Path'))}",
            f"- Subject: {code_value(headers.get('Subject'))}",
            f"- Message-ID: {code_value(headers.get('Message-ID'))}",
            "",
            "## ドメイン情報",
            "",
            f"- Fromドメイン: {code_value(domains.get('from_domain'))}",
            f"- Return-Pathドメイン: {code_value(domains.get('return_path_domain'))}",
            f"- SPF mail-fromドメイン: {code_value(domains.get('spf_mailfrom_domain'))}",
            f"- DKIM署名ドメイン: {code_value(domains.get('dkim_signing_domain'))}",
            f"- DMARC header-fromドメイン: {code_value(domains.get('dmarc_header_from_domain'))}",
            "",
            "## メール認証結果",
            "",
            "| 認証方式 | 結果 | 関連する値 |",
            "| --- | --- | --- |",
            (
                "| SPF | "
                f"{code_value(authentication['spf'].get('result'))} | "
                f"{code_value(authentication['spf'].get('smtp_mailfrom_domain'))} |"
            ),
            (
                "| DKIM | "
                f"{code_value(authentication['dkim'].get('result'))} | "
                f"{code_value(authentication['dkim'].get('signing_domain'))} |"
            ),
            (
                "| DMARC | "
                f"{code_value(authentication['dmarc'].get('result'))} | "
                f"{code_value(authentication['dmarc'].get('header_from_domain'))} |"
            ),
            "",
            "## IPアドレス情報",
            "",
            f"- SPF client IP: {code_value(ip_addresses.get('spf_client_ip'))}",
            "",
            "### Receivedヘッダーから抽出したIPアドレス候補",
            "",
        ]
    )

    received_ips = ip_addresses.get(
        "received_ip_candidates",
        [],
    )

    if received_ips:
        for ip_address in received_ips:
            lines.append(
                f"- {code_value(ip_address)}"
            )
    else:
        lines.append(
            "- IPアドレス候補は抽出されませんでした。"
        )

    lines.extend(
        [
            "",
            "## リンク情報",
            "",
        ]
    )

    link_hosts = domains.get(
        "link_hosts",
        [],
    )

    if link_hosts:
        lines.extend(
            [
                "### リンク先ホスト",
                "",
            ]
        )

        for host in link_hosts:
            lines.append(
                f"- {code_value(host)}"
            )

        lines.append("")
    else:
        lines.extend(
            [
                "リンク先ホストは抽出されませんでした。",
                "",
            ]
        )

    if urls:
        lines.extend(
            [
                "### 無害化したURL",
                "",
            ]
        )

        for url_record in urls:
            lines.append(
                f"- {code_value(url_record['defanged_url'])}"
            )

        lines.append("")
    else:
        lines.extend(
            [
                "HTTPまたはHTTPSのURLは抽出されませんでした。",
                "",
            ]
        )

    lines.extend(
        [
            "## 観測事項",
            "",
            (
                "- 上記の値は、保存されたメール原本から抽出した情報であり、"
                "メール上で観測できた事実を整理したものです。"
            ),
            (
                "- SPF、DKIM、DMARCの認証結果は、受信メールシステムが評価した"
                "ドメインに対する結果です。認証結果がpassであっても、"
                "表示名に記載された企業・ブランドから送信された正規メールであることを"
                "単独で証明するものではありません。"
            ),
            (
                "- URLは無害化した形式で保存しています。"
                "本ツールは抽出したURLを開いたり、HTTP/HTTPSリクエストを送信したりしません。"
            ),
            (
                "- 本レポート生成処理では、DNS照会、RDAP照会、"
                "レピュテーションサービスへの照会、ブラウザーアクセスなどの"
                "外部通信は行いません。"
            ),
            "",
            "## 解析範囲",
            "",
            "本レポートは、ローカル環境で実施した静的解析の結果のみを記録しています。",
            "",
            "必要に応じた外部調査は、本ツールのローカル解析とは分離して実施してください。",
            "",
        ]
    )

    return "\n".join(lines)