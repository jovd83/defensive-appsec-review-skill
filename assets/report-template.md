# [Assessment Title]

## Executive Summary

- Assessment date: [YYYY-MM-DD]
- Target: [repository / service / application]
- Surface type: [web / api / mobile / repo / iac / pipeline / mixed]
- Assessment mode: authorized, non-destructive, evidence-based review
- Standards applied: [OWASP / NIST / MASVS / SSDF / custom]
- Overall posture: [short narrative]

## Scope and Constraints

- In scope: [components, paths, services]
- Out of scope: [explicit exclusions]
- Constraints: [no network, read-only, timebox, etc.]

## Methodology

Describe the assessment approach in plain language. Note whether the work focused on code review, configuration review, dependency hygiene, CI/CD analysis, or limited runtime validation.

## Attack Surface Summary

- Primary entry points: [web routes, APIs, admin surfaces, uploads, jobs]
- Authentication surfaces: [login, OAuth, API keys, service accounts]
- Sensitive data paths: [payments, PII, tokens, logs, storage]
- External dependencies: [third-party APIs, cloud services, CI/CD, model or agent tools]
- Deferred active checks: [anything intentionally not exercised]

## Severity Snapshot

- Critical: 0
- High: 0
- Medium: 0
- Low: 0
- Informational: 0

## Key Findings

### [Severity] Finding Title

- Asset: `[path or component]`
- Category: [auth / secrets / config / dependency / logging / transport / other]
- Weakness: [CWE]
- Severity: [CVSS v4.0 string]
- Confidence: [Low / Medium / High]
- Framework mapping: [standard and control]

**Evidence**

```text
[observed evidence]
```

**Why it matters**

[impact in engineering and business terms]

**How to reproduce or verify**

1. [step]
2. [step]

**Recommended remediation**

[clear engineering action]

## Recommended Next Steps

- [highest-priority engineering action]
- [medium-term hardening action]
- [follow-up validation or retest]
- [deferred active verification if appropriate and authorized]

## Residual Risk and Limitations

State what was not tested, what requires manual validation, and what remains uncertain.
