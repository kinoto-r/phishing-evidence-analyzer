# Phishing Evidence Analyzer

Phishing Evidence Analyzer is a local-first Python CLI tool for extracting and structuring evidence from suspicious `.eml` email files.

It was developed from a practical phishing-email investigation workflow and is intended to make repeated static analysis safer and more consistent.

The tool does not automatically open URLs, render remote HTML content, or execute attachments.

## Project status

Current scope complete (`v1.0.0`).

The implemented workflow has been verified with 83 unit tests.

This repository is intended as a defensive security and research tool rather than a full malware-analysis or threat-intelligence platform.

## Features

### Local static analysis

The default analysis runs locally and includes:

- Reading `.eml` files without modifying the original evidence
- Calculating SHA-256
- Extracting selected email headers
- Extracting SPF, DKIM, and DMARC results recorded in the message headers
- Extracting sender-related domains
- Extracting IP address candidates
- Extracting HTTP/HTTPS URLs as text
- Defanging extracted URLs
- Building structured indicators
- Generating JSON records
- Generating a Japanese Markdown analysis report

### Optional registration enrichment

External registration lookups are disabled by default.

When explicitly enabled, the tool can perform:

- Domain RDAP lookups over HTTPS
- IP RDAP lookups
- RIR referral handling
- Registration-event extraction
- Registrar and name-server extraction
- IP network and allocation information extraction
- WHOIS fallback for supported RDAP-unavailable domains

WHOIS fallback currently supports `.it` domains.

WHOIS uses TCP port 43 and is not encrypted.

## Security principles

The project follows these principles:

- Local processing by default
- No automatic access to URLs found in email messages
- No automatic execution of attachments
- No automatic rendering of remote HTML content
- Original `.eml` evidence is opened read-only
- SHA-256 is calculated before analysis results are recorded
- Extracted URLs are stored in defanged form
- Real email evidence must not be committed to this repository
- Public tests use synthetic or documentation-safe data
- External RDAP access requires an explicit option
- WHOIS fallback requires an additional explicit option

Authentication results such as SPF, DKIM, and DMARC are observations from the received message headers.

A `pass` result does not by itself prove that an email was sent by the company or brand shown in its display name.

## Requirements

- Python 3.11 or later
- Windows, macOS, or Linux
- Internet access only when RDAP or WHOIS enrichment is explicitly used

The current project has no third-party Python runtime dependencies.

## Installation

Clone the repository:

```powershell
git clone https://github.com/kinoto-r/phishing-evidence-analyzer.git
cd phishing-evidence-analyzer
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the project in editable mode:

```powershell
python -m pip install -e .
```

## Evidence directory

Real suspicious emails should be stored outside the Git repository.

Example:

```text
C:\Phishing-Investigation\
├─ 01_Original_EML\
├─ 02_Hash_Records\
├─ 03_Header_Text\
├─ 04_RDAP\
└─ 05_Report\
```

Recommended usage:

- `01_Original_EML`: original `.eml` evidence
- `02_Hash_Records`: SHA-256 records
- `03_Header_Text`: extracted headers, URLs, and indicators
- `04_RDAP`: RDAP candidates and optional registration-enrichment results
- `05_Report`: Markdown analysis reports

The original `.eml` files should not be modified during analysis.

## Basic usage

### 1. Local analysis only

This is the default and safest mode.

No RDAP or WHOIS lookup is performed.

```powershell
python -m phishing_evidence_analyzer.cli `
    "C:\Phishing-Investigation\01_Original_EML\sample.eml" `
    --output-root "C:\Phishing-Investigation" `
    --case-name "2026-09-11_sample"
```

The case name may contain:

- letters
- numbers
- periods
- underscores
- hyphens

### 2. Enable RDAP enrichment

Use `--rdap` when domain and IP registration information is required.

```powershell
python -m phishing_evidence_analyzer.cli `
    "C:\Phishing-Investigation\01_Original_EML\sample.eml" `
    --output-root "C:\Phishing-Investigation" `
    --case-name "2026-09-11_sample" `
    --rdap
```

This performs external HTTPS requests to RDAP services.

The suspicious URL itself is not opened.

### 3. Enable WHOIS fallback

WHOIS fallback can be enabled together with RDAP:

```powershell
python -m phishing_evidence_analyzer.cli `
    "C:\Phishing-Investigation\01_Original_EML\sample.eml" `
    --output-root "C:\Phishing-Investigation" `
    --case-name "2026-09-11_sample" `
    --rdap `
    --whois-fallback
```

`--whois-fallback` requires `--rdap`.

WHOIS fallback:

- is currently implemented for `.it` domains
- discovers the registry WHOIS server through IANA
- uses TCP port 43
- is not encrypted
- does not preserve the raw WHOIS response
- stores only normalized registration information used by the tool

### 4. Overwrite existing generated files

Generated files are not overwritten by default.

To overwrite files for the same case name:

```powershell
python -m phishing_evidence_analyzer.cli `
    "C:\Phishing-Investigation\01_Original_EML\sample.eml" `
    --output-root "C:\Phishing-Investigation" `
    --case-name "2026-09-11_sample" `
    --rdap `
    --whois-fallback `
    --overwrite
```

Use this option carefully.

It affects generated analysis files, not the original `.eml` evidence.

## Generated files

A typical local analysis produces:

```text
02_Hash_Records\
└─ 2026-09-11_sample_sha256.txt

03_Header_Text\
├─ 2026-09-11_sample_headers.json
├─ 2026-09-11_sample_urls.json
└─ 2026-09-11_sample_indicators.json

04_RDAP\
└─ 2026-09-11_sample_rdap_candidates.json

05_Report\
└─ 2026-09-11_sample_report.md
```

When RDAP is enabled, additional files are generated:

```text
04_RDAP\
├─ 2026-09-11_sample_domain_rdap.json
├─ 2026-09-11_sample_ip_rdap.json
└─ 2026-09-11_sample_rdap_summary.json
```

When WHOIS fallback is also enabled:

```text
04_RDAP\
├─ 2026-09-11_sample_domain_whois.json
└─ 2026-09-11_sample_registration_summary.json
```

The Markdown report is updated with registration information when external enrichment is used.

## Report contents

The generated Markdown report can contain:

- file name
- SHA-256
- selected message headers
- sender-related domains
- SPF, DKIM, and DMARC results
- IP address candidates
- defanged URLs
- RDAP registration information
- WHOIS registration information
- IP allocation information

The tool records observed information and does not automatically declare that an email is phishing.

## Privacy notice

Analysis results may contain information from the original email, including:

- email addresses
- Message-ID values
- domains
- IP addresses
- subject lines
- URL paths or query parameters

Review generated reports and JSON files before sharing or publishing them.

In particular, URL query parameters may contain campaign identifiers, tracking values, or recipient-specific information.

Real investigation outputs should not be committed to the public repository.

## URL handling

URLs are extracted as text only.

For example:

```text
https://login.example.invalid/account
```

is stored in defanged form similar to:

```text
hxxps://login[.]example[.]invalid/account
```

The tool does not intentionally visit the extracted URL.

## Testing

Run the complete test suite with:

```powershell
$env:PYTHONPATH = "$PWD\src"

python -m unittest discover `
    -s ".\tests" `
    -p "test_*.py" `
    -v
```

At completion of the current project scope:

```text
Ran 83 tests
OK
```

## Repository structure

```text
phishing-evidence-analyzer/
├─ src/
│  └─ phishing_evidence_analyzer/
│     ├─ analyzer.py
│     ├─ cli.py
│     ├─ indicator_parser.py
│     ├─ output_writer.py
│     ├─ rdap_candidates.py
│     ├─ rdap_client.py
│     ├─ rdap_enrichment.py
│     ├─ report_generator.py
│     ├─ url_extractor.py
│     ├─ whois_client.py
│     └─ whois_enrichment.py
├─ tests/
├─ docs/
├─ samples/
├─ .gitattributes
├─ .gitignore
├─ pyproject.toml
├─ README.md
└─ SECURITY.md
```

## Limitations

The current version does not:

- execute or inspect attachments
- render HTML email content in a browser
- visit extracted URLs
- perform URL reputation checks
- perform malware scanning
- perform DNS-based threat hunting
- determine whether a message is malicious with certainty
- provide generic WHOIS parsing for every registry
- provide a browser-based interface

Registration information describes domain or IP registration and allocation data.

It does not by itself identify the actual sender or prove malicious intent.

## Disclaimer

This tool is provided for defensive security analysis, research, and educational purposes.

The analysis results are based on information contained in the supplied email file and, when explicitly enabled, external registration data such as RDAP or WHOIS records.

The tool does not guarantee that its results are complete, accurate, or sufficient to determine whether an email is legitimate or malicious.

Users are responsible for reviewing the generated results and deciding how to use them.

The author and KINOTO RESEARCH are not responsible for any loss, damage, or other consequences arising from the use of this software or its analysis results.

## Defensive-use notice

This project is intended for defensive security analysis, evidence organization, research, and education.

Do not use it to access or interact with phishing infrastructure beyond the explicit registration-information lookups implemented by the tool.

## Background

This tool was developed by KINOTO RESEARCH from a practical email-header investigation workflow.

The development approach follows:

```text
Question or operational challenge
→ Research
→ Information structuring
→ Requirement definition
→ Practical tool
```

## License

This project is licensed under the MIT License.

See the `LICENSE` file for details.
