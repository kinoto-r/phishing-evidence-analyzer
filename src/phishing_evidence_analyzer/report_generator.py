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


def append_registration_summary(
    lines: list[str],
    registration_summary: dict[str, Any],
) -> None:
    """Append normalized external registration information."""

    lines.extend(
        [
            "## 外部登録情報",
            "",
            (
                "このセクションは、明示的に実行された"
                "RDAPまたはWHOIS照会の結果を整理したものです。"
            ),
            "",
        ]
    )

    domains = registration_summary.get(
        "domains",
        [],
    )

    if domains:
        lines.extend(
            [
                "### ドメイン登録情報",
                "",
                "| 登録ドメイン | 情報源 | Registrar | Status | Name Server |",
                "| --- | --- | --- | --- | --- |",
            ]
        )

        for domain in domains:
            registrar = (
                domain.get(
                    "registrar"
                )
                or {}
            )

            registrar_name = (
                registrar.get(
                    "name"
                )
                or registrar.get(
                    "organization"
                )
            )

            statuses = domain.get(
                "statuses",
                [],
            )

            nameservers = domain.get(
                "nameservers",
                [],
            )

            lines.append(
                "| "
                + code_value(
                    domain.get(
                        "registered_domain"
                    )
                )
                + " | "
                + code_value(
                    domain.get(
                        "source"
                    )
                )
                + " | "
                + code_value(
                    registrar_name
                )
                + " | "
                + code_value(
                    ", ".join(
                        statuses
                    )
                    if statuses
                    else None
                )
                + " | "
                + code_value(
                    ", ".join(
                        nameservers
                    )
                    if nameservers
                    else None
                )
                + " |"
            )

        lines.append("")

        for domain in domains:
            registered_domain = domain.get(
                "registered_domain"
            )

            lines.extend(
                [
                    (
                        "#### "
                        + str(
                            registered_domain
                            or "（不明）"
                        )
                    ),
                    "",
                    (
                        "- 情報源: "
                        + code_value(
                            domain.get(
                                "source"
                            )
                        )
                    ),
                ]
            )

            observed_hosts = domain.get(
                "observed_hosts",
                [],
            )

            if observed_hosts:
                lines.append(
                    "- 観測ホスト: "
                    + ", ".join(
                        code_value(
                            host
                        )
                        for host in observed_hosts
                    )
                )

            events = domain.get(
                "registration_events",
                [],
            )

            if events:
                lines.extend(
                    [
                        "",
                        "| Event | Date |",
                        "| --- | --- |",
                    ]
                )

                for event in events:
                    lines.append(
                        "| "
                        + code_value(
                            event.get(
                                "action"
                            )
                        )
                        + " | "
                        + code_value(
                            event.get(
                                "date"
                            )
                        )
                        + " |"
                    )

            if domain.get(
                "source"
            ) == "whois":
                lines.extend(
                    [
                        "",
                        (
                            "- WHOIS transport: "
                            + code_value(
                                domain.get(
                                    "transport"
                                )
                            )
                        ),
                        (
                            "- WHOIS encrypted: "
                            + code_value(
                                domain.get(
                                    "encrypted"
                                )
                            )
                        ),
                    ]
                )

            lines.append("")

    else:
        lines.extend(
            [
                "ドメイン登録情報は取得されませんでした。",
                "",
            ]
        )

    ip_addresses = registration_summary.get(
        "ip_addresses",
        [],
    )

    if ip_addresses:
        lines.extend(
            [
                "### IPアドレス登録情報",
                "",
            ]
        )

        for item in ip_addresses:
            network = (
                item.get(
                    "network"
                )
                or {}
            )

            start_address = network.get(
                "start_address"
            )

            end_address = network.get(
                "end_address"
            )

            network_range = None

            if (
                start_address
                and end_address
            ):
                network_range = (
                    f"{start_address} - {end_address}"
                )

            lines.extend(
                [
                    (
                        "#### "
                        + str(
                            item.get(
                                "ip_address"
                            )
                            or "（不明）"
                        )
                    ),
                    "",
                    (
                        "- RIR: "
                        + code_value(
                            item.get(
                                "rir"
                            )
                        )
                    ),
                    (
                        "- Network name: "
                        + code_value(
                            network.get(
                                "name"
                            )
                        )
                    ),
                    (
                        "- Network range: "
                        + code_value(
                            network_range
                        )
                    ),
                    "",
                ]
            )

    else:
        lines.extend(
            [
                "IPアドレス登録情報は取得されませんでした。",
                "",
            ]
        )

    errors = registration_summary.get(
        "errors",
        [],
    )

    if errors:
        lines.extend(
            [
                "### 外部照会エラー",
                "",
            ]
        )

        for error in errors:
            lines.append(
                "- "
                + code_value(
                    error.get(
                        "target"
                    )
                )
                + ": "
                + code_value(
                    error.get(
                        "error"
                    )
                )
            )

        lines.append("")


def build_markdown_report(
    analysis: dict[str, Any],
    recorded_at_utc: str,
    registration_summary: dict[str, Any] | None = None,
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

    if registration_summary is not None:
        append_registration_summary(
            lines,
            registration_summary,
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
                (
                    "- 本レポート生成処理では、DNS照会、RDAP照会、"
                    "レピュテーションサービスへの照会、ブラウザーアクセスなどの"
                    "外部通信は行いません。"
                )
                if registration_summary is None
                else (
                    "- 外部登録情報には、明示的に実行された"
                    "RDAPまたはWHOIS照会の結果が含まれます。"
                    "メール本文中のURLへのアクセスや、"
                    "レピュテーションサービスへの照会は行っていません。"
                )
            ),
            "",
            "## 解析範囲",
            "",
            (
                "本レポートは、ローカル環境で実施した"
                "静的解析の結果のみを記録しています。"
                if registration_summary is None
                else (
                    "本レポートは、ローカル静的解析結果と、"
                    "明示的に実行された登録情報照会結果を記録しています。"
                )
            ),
            "",
            (
                "必要に応じた外部調査は、本ツールのローカル解析とは"
                "分離して実施してください。"
                if registration_summary is None
                else (
                    "登録情報は、送信元やリンク先の所有・運用主体、"
                    "またはメールの正当性を単独で証明するものではありません。"
                )
            ),
            "",
        ]
    )

    return "\n".join(lines)