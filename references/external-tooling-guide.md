# External Static Analysis Guide

Use this guide when you want to combine the skill's native repository heuristics with output from established static-analysis and supply-chain tools.

## Supported Normalization Inputs

The bundled normalizer can ingest:

- SARIF output from tools such as CodeQL and Semgrep
- Gitleaks JSON
- Trivy JSON
- OSV-Scanner JSON
- OpenSSF Scorecard JSON
- OWASP Dependency-Check JSON

## Why Normalize External Results

Normalization lets the skill:

- preserve one reporting contract across multiple scanners
- attach standards metadata consistently
- keep source-tool provenance visible in final findings
- merge native heuristics with external evidence in a single markdown or SARIF output

## Standards To Pair With External Results

Use these standards deliberately instead of treating them as decorative labels:

- `cwe-top-25-2025` for prioritizing weakness classes that tend to matter most
- `owasp-scvs` for supply-chain review and component integrity framing
- `slsa` for build provenance and release integrity posture
- `cyclonedx` when SBOM and software-component evidence are part of the workflow
- `sarif` when external rule metadata and code-scanning interoperability matter

## Normalization Examples

### SARIF from Semgrep or CodeQL

```powershell
node scripts/normalize-external-results.js --tool sarif --input sandbox/semgrep.sarif --output sandbox/semgrep-findings.json --target . --type repo --standard owasp-top10
```

### Gitleaks

```powershell
node scripts/normalize-external-results.js --tool gitleaks --input sandbox/gitleaks.json --output sandbox/gitleaks-findings.json --target . --type repo --standard nist-ssdf
```

### Trivy

```powershell
node scripts/normalize-external-results.js --tool trivy --input sandbox/trivy.json --output sandbox/trivy-findings.json --target . --type repo --standard owasp-scvs
```

### OSV-Scanner

```powershell
node scripts/normalize-external-results.js --tool osv-scanner --input sandbox/osv.json --output sandbox/osv-findings.json --target . --type repo --standard owasp-scvs
```

### OpenSSF Scorecard

```powershell
node scripts/normalize-external-results.js --tool scorecard --input sandbox/scorecard.json --output sandbox/scorecard-findings.json --target . --type pipeline --standard slsa
```

### OWASP Dependency-Check

```powershell
node scripts/normalize-external-results.js --tool dependency-check --input sandbox/dependency-check.json --output sandbox/dependency-check-findings.json --target . --type repo --standard owasp-scvs
```

## Merging Normalized Outputs

After normalization, merge one or more outputs with the existing report generator:

```powershell
node scripts/generate-report.js sandbox/raw-findings.json sandbox/semgrep-findings.json sandbox/trivy-findings.json --output sandbox/final-security-report.md
```

## Interpretation Rules

- Keep external tool results evidence-based, but do not treat them as self-validating truth.
- Preserve low-confidence or posture-oriented results as findings only when they still point to a concrete, reviewable weakness.
- Use blind spots explicitly when a tool reports posture gaps, advisory presence, or likely authorization issues that still require runtime confirmation.
