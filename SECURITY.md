# Security Policy

## Security-first design

Phishing Evidence Analyzer is intended to process potentially malicious email content.

Potentially hostile content must be treated as data, not as executable or trusted content.

## Network access

Core analysis functionality must not automatically:

- open URLs extracted from email messages;
- send HTTP or HTTPS requests to extracted URLs;
- load remote images;
- resolve or visit tracking links;
- submit files or email content to third-party services.

If network-based enrichment is introduced in the future, it must be separated from the offline analysis component and require explicit user action.

## Email content

HTML email content should not be rendered in a browser during normal analysis.

URLs should be extracted as text only.

Potentially malicious indicators may be displayed in a defanged format, for example:

```text
hxxps://example[.]invalid/path
```

## Attachments

Attachments must not be automatically:

- opened;
- executed;
- previewed using external applications;
- uploaded to external services.

Attachment data must be treated as untrusted input.

## Evidence integrity

Original evidence should remain unchanged.

Analysis workflows should calculate a cryptographic hash such as SHA-256 before further processing.

Generated reports and extracted data should be written to separate output locations.

## Repository safety

Real phishing emails and investigation data must not be committed to this repository.

The repository `.gitignore` excludes common email evidence formats including:

```text
*.eml
*.msg
*.mbox
```

Before every public push, review staged files with:

```powershell
git status
git diff --cached
```

## Sensitive information

Public issues, documentation, test fixtures, and sample reports must not contain:

- real recipient email addresses;
- customer information;
- authentication credentials;
- API keys;
- session tokens;
- private server information;
- personally identifiable information;
- confidential business information.

Use synthetic or sanitized examples instead.

## Reporting a vulnerability

Do not publish sensitive vulnerability details, real phishing samples, personal information, or credentials in a public GitHub issue.

If GitHub private vulnerability reporting is enabled, use that mechanism for sensitive security reports.

Otherwise, provide only the minimum non-sensitive information necessary to request a private reporting channel.

## Supported versions

The project is currently in pre-alpha development.

There is not yet a supported production release.