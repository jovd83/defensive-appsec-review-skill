# Security Standards Guide

Use this guide to choose the right verification lens and to map findings consistently.

## Recommended Reporting Layers

Use these layers together rather than forcing every audience into a single taxonomy.

- CWE for the underlying weakness statement
- OWASP Top 10 or OWASP API Top 10 for executive risk framing
- OWASP ASVS for control-level application guidance
- NIST SSDF for secure software development lifecycle alignment
- CIS Controls v8 for operational and hardening-oriented follow-up
- OWASP SCVS and SLSA for dependency, provenance, and build-chain findings
- OWASP SAMM for report-level maturity framing, not for every finding card

## Core Taxonomies

### CWE

Use CWE to describe the underlying weakness, not the exploit story.

- Example: `CWE-798` for hardcoded credentials
- Example: `CWE-862` for missing authorization

### CVSS v4.0

Use CVSS to express severity consistently. If you cannot justify a numeric vector, provide a severity band with a brief rationale and be explicit that analyst validation is still required.

## Surface-to-Standard Mapping

### Web Applications

Use:

- OWASP WSTG for test themes and verification structure
- OWASP ASVS for control-oriented validation
- OWASP Top 10 for executive framing

Typical focus:

- authentication and session management
- access control
- input handling and output encoding
- security headers and cookie posture
- sensitive data handling

### APIs

Use:

- OWASP API Security Top 10
- OWASP ASVS where control detail is helpful

Typical focus:

- broken object level authorization
- broken function level authorization
- excessive data exposure
- unsafe consumption of upstream APIs
- rate limiting and resource protections
- mass assignment, SSRF, and request-driven redirect or file access patterns when static evidence exists

### Mobile

Use:

- OWASP MASVS

Typical focus:

- secrets in mobile builds
- local storage and backup exposure
- transport security
- hardcoded endpoints and debug configuration

### Repositories, CI/CD, and SDLC

Use:

- NIST SSDF
- OWASP SAMM for maturity framing
- OWASP SCVS for supply-chain verification framing
- SLSA for build and provenance integrity
- CycloneDX when SBOM evidence is part of the review flow
- PTES or NIST SP 800-115 for disciplined assessment flow

Typical focus:

- secrets management
- dependency hygiene
- CI token exposure
- build permissions and trust boundaries
- insecure defaults in infrastructure definitions

### LLM-Enabled Systems

Use app-surface standards first, then add LLM-specific concerns as a secondary lens.

Typical focus:

- tool access boundaries
- prompt injection exposure
- cross-tenant data leakage
- excessive model or plugin privileges

## Reporting Guidance

- Distinguish observed findings from analyst hypotheses.
- Keep standards mapping useful, not decorative.
- Prefer separate mapping fields when a finding spans multiple lenses. Do not collapse ASVS, CIS, or SCVS into a generic OWASP note if the report format can keep them distinct.
- If a finding does not map cleanly to a headline framework, prefer a precise CWE and explain the context plainly.
- Use OWASP SAMM as a summary lens for repository and SDLC reports instead of pretending it is a one-to-one weakness catalog.
- For static repository review, include blind spots explicitly whenever runtime verification is still needed for authorization, rate limiting, or exploitability claims.
- When ingesting external results, preserve the originating tool and align it to the most relevant standard instead of pretending all findings came from one scanner.
