# Defensive AppSec Review Skill

[![Version](https://img.shields.io/badge/version-4.0.0-blue)](https://github.com/jovd83/defensive-appsec-review-skill)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Validate Skills](https://github.com/jovd83/security-testing-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/jovd83/security-testing-skill/actions/workflows/ci.yml)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=flat&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/jovd83)

An enterprise-grade Agent Skill for authorized, non-destructive application security review.

This repository packages a reusable `SKILL.md`, deterministic helper scripts, references, schema, fixtures, and tests for defensive AppSec workflows. It is designed for engineers, security reviewers, and maintainers who need fast, evidence-based review outputs without drifting into offensive or unsafe behavior.

## Why This Repository Exists

Many security-review prompts fail in one of two ways:

- they are too vague to produce repeatable, auditable output
- they overreach into offensive behavior, speculation, or noisy findings

This skill is built to avoid both. It gives compatible coding agents a clear defensive operating boundary, a practical workflow for passive review, and tooling for normalized findings plus stakeholder-ready reporting.

## What The Skill Does

- scopes authorized security review requests safely
- supports repo, API, web, mobile, IaC, pipeline, and mixed-system reviews
- chooses an AppSec lens such as OWASP, ASVS, NIST SSDF, SCVS, or SLSA
- runs deterministic local review steps through bundled Node scripts
- normalizes external-tool outputs into one findings envelope
- generates markdown, HTML, and SARIF deliverables

## What It Does Not Do

- offensive exploitation or post-exploitation
- credential abuse or persistence
- destructive load, fuzzing, or denial-of-service activity
- implicit authorization decisions
- shared-memory infrastructure across unrelated projects

## Repository Structure

```text
defensive-appsec-review-skill/
|-- .github/                 GitHub automation and templates
|-- agents/                  Agent-facing metadata
|-- assets/                  Shared report templates
|-- evals/                   Skill and tooling evaluation artifacts
|-- examples/                Example findings and generated reports
|-- fixtures/                Deterministic sample inputs for tests
|-- references/              Deep guidance loaded on demand
|-- schemas/                 Machine-readable response contract
|-- scripts/                 Deterministic helper tooling
|-- tests/                   Node-based validation suite
|-- CHANGELOG.md
|-- CONTRIBUTING.md
|-- LICENSE
|-- README.md
|-- SECURITY.md
`-- SKILL.md
```

## Skill Contract

The authoritative skill instructions live in [SKILL.md](./SKILL.md).

The skill is intentionally structured for progressive disclosure:

- `SKILL.md` contains only activation-time instructions and the operational workflow
- `references/` holds deeper guidance that should be loaded only when needed
- `scripts/` contains deterministic helpers that reduce repeated agent work

This keeps the activation surface focused while preserving a robust implementation layer.

## Installation

### Agent Skills compatible agents

Install the repository so the agent can see the skill folder containing `SKILL.md`.

Typical local installation:

```text
<skills-root>/defensive-appsec-review-skill/
```

The exact skills root depends on the host product. The skill itself does not require a custom installer.

### Validate the package before publishing

Run:

```powershell
npm run validate
```

This repository also aligns its frontmatter and metadata to the published Agent Skills format. If you use the broader Agent Skills toolchain, you can additionally validate with the official tools from `agentskills.io`.

## Quick Start

### 1. Run a passive repo scan

```powershell
node scripts/audit-scan.js --target . --type repo --standard nist-ssdf --output sandbox/raw-findings.json
```

### 2. Run a deeper review with external results

```powershell
node scripts/audit-scan.js --target . --type repo --standard owasp-scvs --depth deep --deep-inputs sarif=sandbox/semgrep.sarif,trivy=sandbox/trivy.json --output sandbox/deep-findings.json
```

### 3. Normalize an external tool result

```powershell
node scripts/normalize-external-results.js --tool sarif --input sandbox/codeql.sarif --output sandbox/codeql-findings.json --target . --type repo --standard owasp-top10
```

### 4. Generate a report

```powershell
node scripts/generate-report.js sandbox/raw-findings.json --output sandbox/final-security-report.md
node scripts/generate-report.js sandbox/raw-findings.json --format html --output sandbox/final-security-report.html
node scripts/generate-report.js sandbox/raw-findings.json --format sarif --output sandbox/findings.sarif.json
```

### 5. Run the local deterministic eval harness

```powershell
npm run eval:local
```

By default this writes into a sibling workspace directory:

```text
../defensive-appsec-review-skill-workspace/local-iteration-1/
```

You can override the destination and iteration label:

```powershell
node scripts/run-local-evals.js --workspace ..\defensive-appsec-review-skill-workspace --iteration local-iteration-2
```

## Core Tooling

### `scripts/audit-scan.js`

Read-only repository scanner that emits normalized findings JSON.

Current coverage includes:

- secrets exposure
- dangerous code patterns
- insecure defaults and transport issues
- CI/CD permission and trust-boundary issues
- container and IaC hygiene signals
- API and authz-adjacent heuristics
- dependency manifest discovery and scan telemetry

### `scripts/normalize-external-results.js`

Normalizes results from:

- SARIF
- Gitleaks
- Trivy
- OSV-Scanner
- OpenSSF Scorecard
- OWASP Dependency-Check

### `scripts/generate-report.js`

Builds:

- markdown reports
- HTML reports
- SARIF output
- baseline-vs-current delta views

### `scripts/run-local-evals.js`

Runs deterministic offline validation of the bundled tooling and writes benchmark-style artifacts to a workspace directory.

## Findings Contract

Machine-readable findings use [schemas/security-assessment.schema.json](./schemas/security-assessment.schema.json).

The contract separates:

- metadata about scope, coverage, blind spots, and telemetry
- normalized findings with evidence, impact, remediation, and framework mappings

This repository intentionally distinguishes:

- runtime memory: temporary working context for the current assessment
- project-local persistent memory: repo files such as scripts, references, schema, examples, and evals
- shared memory: external to this skill and intentionally not embedded here

## Evaluation Strategy

This repository includes two evaluation layers:

### Tooling validation

The Node test suite verifies scanner behavior, report generation, normalization, and local eval output.

Run:

```powershell
npm test
```

### Skill activation and workflow validation

The repo includes:

- [evals/evals.json](./evals/evals.json) for representative user prompts
- [evals/local-evals.json](./evals/local-evals.json) for deterministic script checks
- [evals/trigger-evals.json](./evals/trigger-evals.json) for description-trigger review

The trigger eval set exists to support description tuning and to keep the skill's activation boundary honest as the repository evolves.

## Open-Source Maintainer Notes

This repo aims to be publishable and maintainable, not just internally useful.

Key maintainer expectations:

- keep `SKILL.md` concise and activation-friendly
- move deep detail into `references/`
- keep metadata synchronized across `SKILL.md`, `package.json`, and `agents/openai.yaml`
- prefer deterministic scripts over prompt bloat when work is repetitive
- treat generated examples as examples, not as the primary source of truth

See:

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CHANGELOG.md](./CHANGELOG.md)

## References

- [references/scope-intake-template.md](./references/scope-intake-template.md)
- [references/capability-matrix.md](./references/capability-matrix.md)
- [references/frameworks-guide.md](./references/frameworks-guide.md)
- [references/detection-methodology.md](./references/detection-methodology.md)
- [references/external-tooling-guide.md](./references/external-tooling-guide.md)
- [references/review-checklist.md](./references/review-checklist.md)

## Optional Future Work

These are deliberately out of scope for the current implementation:

- shared-memory integration for cross-project lessons
- scheduled CI wrappers around the scanner
- live enrichment against external package or advisory services
- organization-specific policy packs

If added later, keep them optional and clearly separated from the core skill.
