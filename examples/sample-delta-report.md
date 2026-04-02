# Security Assessment Report - sample-risky-repo

## Executive Summary

This report summarizes an authorized, non-destructive security assessment with 1 documented finding. The review emphasized evidence-backed observations, clear remediation, and explicit limits on what static review can prove on its own.

### Priority Trio

- Severity: 1 high-severity finding need first triage (0 Critical, 1 High).
- Category: Credential Management leads with 1 finding and a High ceiling.
- Framework: OWASP has the strongest pressure with 0 high-severity mapped and 1 high-severity gaps.

### Recommended First Action

- Validate and triage the 1 high-severity finding in Credential Management first, then close the biggest mapping gap in OWASP.

### Why This Is First

- Credential Management currently carries the most urgent business risk, and OWASP adds the strongest framework pressure through mapped exposure or missing high-severity coverage.

### Top Risk Categories

- [Credential Management](#category-credential-management): 1 finding with highest severity High; severity mix 1 High

### Top Risk Frameworks

- [OWASP](#framework-owasp): 0 mapped findings, 0 high-severity mapped; mapping pressure 1 high-severity gaps, 1 unmapped findings
- [OWASP SCVS](#framework-scvs): 0 mapped findings, 0 high-severity mapped; mapping pressure 1 high-severity gaps, 1 unmapped findings
- [SLSA](#framework-slsa): 0 mapped findings, 0 high-severity mapped; mapping pressure 1 high-severity gaps, 1 unmapped findings

## Change Over Time

- Baseline target: sample-risky-repo
- Baseline generated: Mar 18, 2026, 01:00 AM
- New findings: 0
- Fixed findings: 1
- Regressed findings: 1
- Improved findings: 0
- Unchanged findings: 0

### Notable Changes

- Fixed: Non-local plaintext HTTP endpoint referenced previously at src/client.js:14 (Medium)
- [Regressed: Potential hardcoded credential detected (inline secret assignment) moved from Medium to High at .env](#finding-1)

## Workflow Status

- New: 1
- Needs review: 0
- In progress: 0
- Accepted risk: 0
- Fixed: 0
- Deferred: 0

### Ownership and Due Dates

- Owner workload: Security Guild: 1
- Potential hardcoded credential detected (inline secret assignment): due 2026-04-15 (New, owner Security Guild)

## Scope and Methodology

- Target: sample-risky-repo
- Surface type: repo
- Standards applied: nist-ssdf
- Source tools: native-heuristic-scan
- OWASP SAMM maturity lens: OWASP SAMM Governance and Verification maturity framing
- Assessment mode: read-only review with deterministic helper tooling and analyst validation
- Constraints: no destructive testing, no exploit chaining, no claims beyond observed evidence

## Severity Snapshot

- Critical: 0
- High: 1
- Medium: 0
- Low: 0
- Informational: 0

## Coverage Profile

- Assessed theme: secrets exposure and dependency inventory

- Manual follow-up needed: runtime exploitability still requires validation

## What Was Tested

- Tested themes: secrets exposure and dependency inventory
- Security categories reviewed: Credential Management
- Verification methods observed: heuristic-static
- Source tools used: native-heuristic-scan
- Assets with evidence: 1
- Distinct asset examples: .env

<a id="category-browsing"></a>
## Category Browsing

- [Credential Management](#category-credential-management): 1 finding

- Distinct security categories: 1
- Categorized findings: 1/1
- Unclassified or coverage-only findings: 0/1

### Category Drill-Down

### <a id="category-credential-management"></a>Credential Management

- Findings in this category (1): [Finding 1](#finding-1) [High] Potential hardcoded credential detected (inline secret assignment)


<a id="framework-coverage"></a>
## Framework Coverage

- Primary control mapping: 1/1 findings mapped (100%)
- OWASP: 0/1 findings mapped (0%)
- OWASP ASVS: 1/1 findings mapped (100%)
- NIST SSDF: 1/1 findings mapped (100%)
- CIS Controls v8: 1/1 findings mapped (100%)
- OWASP SCVS: 0/1 findings mapped (0%)
- SLSA: 0/1 findings mapped (0%)

- Findings with any framework lens: 1/1
- Findings with a primary control mapping: 1/1
- Findings without any framework lens: 0/1

### Mapping Provenance

- Primary control mapping: 1 supplied, 0 inferred, 0 not recorded
- OWASP: 0 supplied, 0 inferred, 1 not recorded
- OWASP ASVS: 1 supplied, 0 inferred, 0 not recorded
- NIST SSDF: 1 supplied, 0 inferred, 0 not recorded
- CIS Controls v8: 1 supplied, 0 inferred, 0 not recorded
- OWASP SCVS: 0 supplied, 0 inferred, 1 not recorded
- SLSA: 0 supplied, 0 inferred, 1 not recorded

### Priority Mapping Gaps

- OWASP: missing on 1/1 findings, including 1 high-severity finding
- OWASP SCVS: missing on 1/1 findings, including 1 high-severity finding
- SLSA: missing on 1/1 findings, including 1 high-severity finding

### Severity by Framework

| Framework | Critical | High | Medium | Low | Informational | Mapped total | Supplied | Inferred | Not recorded |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [Primary control mapping](#framework-primary) | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| [OWASP](#framework-owasp) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| [OWASP ASVS](#framework-asvs) | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| [NIST SSDF](#framework-nist) | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| [CIS Controls v8](#framework-cis) | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| [OWASP SCVS](#framework-scvs) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| [SLSA](#framework-slsa) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |

### Framework Drill-Down

### <a id="framework-primary"></a>Primary control mapping

- Mapped findings (1): [Finding 1](#finding-1) Potential hardcoded credential detected (inline secret assignment)
- Missing mappings (0): No findings are currently missing this framework mapping.

### <a id="framework-owasp"></a>OWASP

- Mapped findings (0): No findings currently use this framework mapping.
- Missing mappings (1): [Finding 1](#finding-1) Potential hardcoded credential detected (inline secret assignment)

### <a id="framework-asvs"></a>OWASP ASVS

- Mapped findings (1): [Finding 1](#finding-1) Potential hardcoded credential detected (inline secret assignment)
- Missing mappings (0): No findings are currently missing this framework mapping.

### <a id="framework-nist"></a>NIST SSDF

- Mapped findings (1): [Finding 1](#finding-1) Potential hardcoded credential detected (inline secret assignment)
- Missing mappings (0): No findings are currently missing this framework mapping.

### <a id="framework-cis"></a>CIS Controls v8

- Mapped findings (1): [Finding 1](#finding-1) Potential hardcoded credential detected (inline secret assignment)
- Missing mappings (0): No findings are currently missing this framework mapping.

### <a id="framework-scvs"></a>OWASP SCVS

- Mapped findings (0): No findings currently use this framework mapping.
- Missing mappings (1): [Finding 1](#finding-1) Potential hardcoded credential detected (inline secret assignment)

### <a id="framework-slsa"></a>SLSA

- Mapped findings (0): No findings currently use this framework mapping.
- Missing mappings (1): [Finding 1](#finding-1) Potential hardcoded credential detected (inline secret assignment)


## Scan Telemetry

- Scan depth: quick
- Files discovered: 7
- Files scanned: 6
- Data scanned: 18.0 KB
- Heuristic checks run: 167
- Scan duration: 180 ms
- Dependency manifests detected: 1
- External findings imported: 0
- External sources loaded: None recorded
- External source failures: None recorded
- Excluded directories skipped: 1
- Support-material files skipped: 1
- Oversized files skipped: 0
- Unreadable files skipped: 0
- Sample skipped directories: node_modules
- Sample skipped files: README.md
- Top finding rules: Potential hardcoded credential detected (inline secret assignment): 1
- Finding categories observed: Credential Management: 1

## Findings

<a id="finding-1"></a>
### 1. [High] Potential hardcoded credential detected (inline secret assignment)

- Asset: `.env`
- Location: .env
- Category: Credential Management
- Weakness: CWE-798: Use of Hard-coded Credentials
- Severity: 8.6 (High)
- Confidence: Medium
- Status: New
- Owner: Security Guild
- Due date: 2026-04-15
- Fix effort: M
- Source tool: native-heuristic-scan
- Framework mapping: nist-ssdf - Secret exposure prevention
- Category navigation: [Category Browsing](#category-browsing); [Credential Management](#category-credential-management)
- Framework navigation: [Framework Coverage](#framework-coverage); [Primary control mapping](#framework-primary); [OWASP ASVS](#framework-asvs); [NIST SSDF](#framework-nist); [CIS Controls v8](#framework-cis)
- Mapping provenance: Primary control mapping: supplied explicitly; OWASP: not recorded; OWASP ASVS: supplied explicitly; NIST SSDF: supplied explicitly; CIS Controls v8: supplied explicitly; OWASP SCVS: not recorded; SLSA: not recorded
- ASVS mapping: OWASP ASVS V8 Data Protection
- NIST mapping: NIST SP 800-218 SSDF PS.1 Protect code, secrets, and related artifacts; NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification
- CIS mapping: CIS Controls v8 Control 3 Data Protection
- SCVS mapping: No per-finding SCVS mapping supplied by scanner
- SLSA mapping: No per-finding SLSA mapping supplied by scanner
- OWASP mapping: No per-finding OWASP mapping supplied by scanner
- Verification tier: heuristic-static

**Evidence**

```text
Matched inline secret assignment pattern in .env.
```

**How to reproduce or verify**

1. Open .env.
2. Review the committed secret-like value.

**Why it matters**

Live credentials in source code can enable unauthorized access.

**Recommended remediation**

Move credentials to a secret manager and rotate any exposed values.

---


## Recommended Next Steps

- Backfill OWASP mappings first for 1 high-severity finding. Focus on Credential Management first.
- Backfill OWASP SCVS mappings first for 1 high-severity finding. Focus on Credential Management first.
- Backfill SLSA mappings first for 1 high-severity finding. Focus on Credential Management first.

- Validate high-confidence findings in the owning engineering context.
- Prioritize remediation for credential exposure, authorization flaws, and overly broad CI or network permissions first.
- Rerun targeted verification after fixes to confirm closure and identify regressions.

## Residual Risk and Limitations

This report reflects the supplied evidence and any deterministic scan results available at generation time. Areas outside the declared scope, runtime-only behavior, environment-specific controls, and exploitability assumptions may require separate manual validation.
