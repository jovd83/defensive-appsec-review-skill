# Security Assessment Report - sample-risky-repo

## Executive Summary

This report summarizes an authorized, non-destructive security assessment with **1** documented findings. The review emphasized evidence-backed observations and remediation-oriented guidance rather than speculative risk claims.

## Scope and Methodology

- Target: sample-risky-repo
- Surface type: repo
- Standards applied: nist-ssdf
- Assessment mode: read-only review with deterministic helper tooling and analyst validation
- Constraints: no destructive testing, no exploit chaining, no claims beyond observed evidence

## Severity Snapshot

- Critical: 0
- High: 1
- Medium: 0
- Low: 0
- Informational: 0

## Findings

### 1. [High] Potential hardcoded credential detected (inline secret assignment)

- Asset: `.env`
- Location: .env
- Category: Credential Management
- Weakness: CWE-798: Use of Hard-coded Credentials
- Severity: 8.6 (High)
- Confidence: Medium
- Fix effort: M
- Framework mapping: nist-ssdf - Secret exposure prevention

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
