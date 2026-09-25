# Reporting

Basilisk generates reports in 5 formats and 2 report types for different technical and executive use cases.

## Executive vs Detailed Report Types

You can control the depth and audience for HTML and Markdown reports using the `--report-type` flag:

- **`--report-type detailed` (default)**: Comprehensive technical findings with full payload evolution trees, raw prompt/response transcripts, and operator telemetry.
- **`--report-type executive`**: High-level, client-ready security summary designed for C-level leadership, management, and external clients. Includes executive risk scores, key findings overview, framework compliance indicators, and strategic remediation recommendations.

```bash
# Generate a client-ready executive HTML report
basilisk scan --target https://target.com --free --report-type executive
```

## Sample Client Reports

Sample client report artifacts are available in the [`examples/`](../examples/) directory:

- [examples/sample_executive_report.html](../examples/sample_executive_report.html)
- [examples/sample_executive_report.md](../examples/sample_executive_report.md)
- [examples/mock_session.json](../examples/mock_session.json)

To generate sample executive reports locally:

```bash
# Option 1: Run the built-in demo command
basilisk demo

# Option 2: Run the sample generator script
python examples/generate_demo.py --report-type executive
```

## Formats
### Standard Features Across Reports

All generated reports include:
- **Framework Mappings**: OWASP LLM Top 10, MITRE ATLAS IDs (`AML.T0051`, `AML.T0054`, `AML.T0055`, etc.), and NIST AI RMF subcategory alignments.
- **Actionable Remediation Guidance**: Detailed mitigation recommendations tailored to each finding and attack category.
- **Evidence Verdicts**: Calibrated proof classifications (Confirmed, Partial, Refused, Inconclusive) and downgrade reasoning.

### HTML
Professional dark-themed report with:
- Severity breakdown cards
- Finding details with expandable payloads and responses
- Conversation replay sections
- Target profile and OWASP mapping

```bash
basilisk scan --target https://target.com -o html
```

### SARIF 2.1.0
Static Analysis Results Interchange Format for CI/CD:
- GitHub Security tab integration
- GitLab SAST compatible
- Proper rule deduplication and fingerprints
- Conversation code flows

```bash
basilisk scan --target https://target.com -o sarif
```

#### GitHub Actions Integration
```yaml
- name: Basilisk AI Scan
  run: basilisk scan --target ${{ secrets.AI_ENDPOINT }} -o sarif --output-dir ./results --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./results/
```

### JSON
Machine-readable format:
- Full finding details with all metadata
- Profile data
- Session summary

```bash
basilisk scan --target https://target.com -o json
```

### Markdown
Documentation-friendly format:
- Target profile summary
- Formatted findings with code blocks
- Conversation transcripts

```bash
basilisk scan --target https://target.com -o markdown
```

### PDF
Client deliverables (requires `weasyprint` or `reportlab`):

```bash
pip install weasyprint  # recommended
basilisk scan --target https://target.com -o pdf
```

Falls back to reportlab, then text format if neither is installed.

## Export from Desktop App

The Electron desktop app can export reports for any completed session:
1. Navigate to the **Reports** tab
2. Select a session from the dropdown
3. Choose format (HTML, JSON, SARIF, Markdown)
4. Click **Generate & Export**

## Export from Interactive Mode

```bash
basilisk interactive --target https://target.com
# ... run attacks ...
/export html
/export sarif
```

## Export from Replay

```bash
basilisk replay <session_id> --export html
```
