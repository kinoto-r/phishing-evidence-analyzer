# Phishing Evidence Analyzer

Phishing Evidence Analyzer is a local-first project for safely extracting and structuring information from suspicious email files.

The project is designed to support repeatable analysis without automatically opening links, rendering remote content, or executing attachments.

## Project status

Pre-alpha / initial design stage.

No production analysis functionality has been implemented yet.

## Security principles

The project is designed around the following principles:

- Local processing by default
- No automatic access to URLs found in email messages
- No automatic execution of attachments
- No automatic rendering of remote HTML content
- Original evidence should remain unchanged
- SHA-256 hashes should be used to verify evidence integrity
- Real email evidence must not be committed to the Git repository
- Personal information and credentials must not be included in public test data

## Planned scope

Initial planned capabilities include:

1. Read `.eml` files locally
2. Calculate SHA-256 hashes
3. Extract relevant email headers
4. Extract authentication results such as SPF, DKIM, and DMARC
5. Extract URLs as text without accessing them
6. Extract host and domain information
7. Compare multiple suspicious messages
8. Produce structured CSV, JSON, and Markdown reports

## Repository structure

```text
phishing-evidence-analyzer/
├─ src/
│  └─ phishing_evidence_analyzer/
├─ tests/
├─ docs/
├─ samples/
├─ .gitignore
├─ pyproject.toml
├─ README.md
└─ SECURITY.md
```

## Evidence storage

Real suspicious email files should be stored outside this repository.

Example:

```text
C:\Security-Investigation\
├─ 01_Original_EML\
├─ 02_Hash_Records\
├─ 03_Header_Text\
├─ 04_RDAP\
└─ 05_Report\
```

The `01_Original_EML` directory should be treated as evidence storage.

Original evidence files should not be modified during analysis.

## Important notice

This project is intended for defensive security analysis.

It should not automatically access malicious infrastructure, execute suspicious content, or interact with phishing websites.

## License

A license has not yet been selected.
