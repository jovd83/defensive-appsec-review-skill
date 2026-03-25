# Security Assessment Skill

Version: `3.1.0`
Author: `jovd83`
License: `MIT`

An AgentSkill for authorized, non-destructive, evidence-based application security assessments.

This repository packages a reusable skill plus lightweight tooling for defensive review workflows across repositories, APIs, mobile projects, infrastructure-as-code, and SDLC surfaces. It is designed for maintainers who want a clear operational boundary, deterministic helper scripts, and outputs that engineering teams can act on quickly.

## What This Skill Is

- A scoped defensive security-review skill
- A standards-aware prompt package aligned to common AppSec frameworks
- A small toolkit for repository scanning and markdown report generation
- A GitHub-friendly starting point for maintainable, auditable skill distribution

## What This Skill Is Not

- An offensive security framework
- An exploit-development toolkit
- A replacement for full manual penetration testing
- A shared-memory or cross-agent infrastructure layer

## Repository Layout

```text
security-testing-skill/
|-- .github/
|-- agents/
|-- assets/
|-- evals/
|-- examples/
|-- fixtures/
|-- references/
|-- schemas/
|-- scripts/
|-- tests/
|-- CHANGELOG.md
|-- CONTRIBUTING.md
|-- LICENSE
|-- README.md
|-- SKILL.md
`-- package.json
```

## Package Metadata

- Skill name: `security-testing-skill`
- Display name: `Security Assessment Skill`
- Version: `3.1.0`
- Author: `jovd83`
- License: `MIT`
- OpenAI metadata file: [`agents/openai.yaml`](./agents/openai.yaml)

## Responsibilities

The skill itself is responsible for:

- clarifying scope
- selecting the right assessment lens
- building an attack-surface-aware review plan
- running safe local review steps
- normalizing findings
- producing remediation-focused output

Related but separate concepts:

- shared memory across many skills or teams
- organization-wide policy engines
- live DAST, fuzzing, or active penetration testing platforms

Those are intentionally out of scope here and should stay external integrations, not implicit behavior inside this repository.

## Included Tooling

### `scripts/audit-scan.js`

Performs deterministic, read-only repository analysis and emits normalized findings JSON. Current checks include:

- hardcoded credential patterns
- risky `.env` usage
- wildcard CORS and insecure transport references
- weak cookie configuration hints
- dangerous CI/CD permission patterns
- container and IaC hygiene signals
- dangerous code patterns such as `eval`, unsafe HTML sinks, weak subprocess usage, and insecure JWT handling hints
- dependency manifest discovery and basic ecosystem context

This script is conservative by design. It produces candidate findings that still benefit from human validation.

### `scripts/generate-report.js`

Combines one or more JSON findings files into either:

- stakeholder-friendly markdown reports
- SARIF-style JSON output for CI and code-scanning ingestion

### `scripts/run-local-evals.js`

Runs a deterministic local evaluation suite for the bundled tooling and writes grading plus benchmark artifacts into a sibling workspace. This does not replace model-based skill benchmarking, but it does give the repository a repeatable offline eval loop for scanner and report quality.

## Strengthening Ideas Borrowed From Other Security Skills

After reviewing several published security-auditor skills and broader cybersecurity skill packs, this repository explicitly incorporates the strongest compatible patterns:

- two-layer detection to reduce false positives before reporting
- precise locations and engineer-friendly remediation effort estimates
- stronger emphasis on dependency, secret, and code-level review instead of vague security scanning
- explicit positioning for pre-PR review, pre-release audit, and CI gate use cases

Ideas intentionally left out:

- exploit execution or persistence workflows
- overly broad compliance-certification claims
- giant checklist sprawl without a deterministic implementation path
- framework or tool assumptions the repository does not actually bundle

## Incorporated Capability Areas

This version also integrates the strongest defensive-review capabilities from the external skeleton repository you pointed me to, reshaped into a safer and more maintainable skill boundary:

- broader intake for scope, authorization, environment, and compliance drivers
- attack-surface-oriented discovery before finding generation
- richer capability coverage across web, API, mobile, repo, container, cloud, and AI-enabled systems
- checklist-driven delivery quality
- clearer distinction between passive review, deferred active checks, and out-of-scope offensive work

Capabilities intentionally not imported:

- exploit frameworks and offensive tooling assumptions
- destructive or aggressive testing modes
- social engineering and physical testing flows
- zero-day detection claims that the repo cannot support credibly

## Quick Start

### 0. Inspect the packaged metadata

The core metadata surfaces for this repository are:

- [`SKILL.md`](./SKILL.md)
- [`agents/openai.yaml`](./agents/openai.yaml)
- [`package.json`](./package.json)

### 1. Run the scanner

```powershell
node scripts/audit-scan.js --target . --type repo --standard nist-ssdf --output sandbox/raw-findings.json
```

### 2. Optionally add manual findings

Create a JSON file shaped like [`schemas/security-assessment.schema.json`](./schemas/security-assessment.schema.json) if you need to add analyst-confirmed findings the scanner cannot express.

### 3. Generate a report

```powershell
node scripts/generate-report.js sandbox/raw-findings.json sandbox/manual-findings.json --output sandbox/final-security-report.md
```

### 4. Generate SARIF-style output for CI consumers

```powershell
node scripts/generate-report.js sandbox/raw-findings.json --format sarif --output sandbox/findings.sarif.json
```

### 5. Run the deterministic local eval harness

```powershell
npm run eval:local
```

## Skill Usage Guidance

Use this skill for prompts such as:

- "Review this repo for security issues and keep it read-only."
- "Assess this API codebase against OWASP API Top 10."
- "Check our CI/CD definitions for secrets handling and risky permissions."
- "Turn these raw findings into an engineering-ready security report."
- "Run a pre-PR security review and highlight the few issues that matter most."
- "Use this as a CI gate for dependency, secret, and risky-code checks."

Do not use it for:

- unauthorized testing
- exploitation of third-party targets
- persistence or evasion techniques
- destructive load or denial-of-service activity

## Installation-Friendly Notes

If you publish or package this repository, keep these files aligned:

- [`SKILL.md`](./SKILL.md) for the primary skill instructions and trigger description
- [`agents/openai.yaml`](./agents/openai.yaml) for OpenAI-facing display metadata
- [`README.md`](./README.md) for GitHub-facing documentation

Version and author values should stay consistent across all three.

## Reference Pack

- [`references/scope-intake-template.md`](./references/scope-intake-template.md)
- [`references/capability-matrix.md`](./references/capability-matrix.md)
- [`references/frameworks-guide.md`](./references/frameworks-guide.md)
- [`references/detection-methodology.md`](./references/detection-methodology.md)
- [`references/review-checklist.md`](./references/review-checklist.md)

## Memory Architecture

This repository intentionally uses a simple model:

- Runtime memory: current scope, active hypotheses, scan outputs, draft findings
- Project-local persistent memory: templates, schemas, scripts, evals, references in this repo
- Shared memory: out of scope here; integrate with an external shared-memory skill only when needed

Nothing in this repository automatically promotes runtime observations into persistent or shared memory.

## Quality and Validation

The repo includes:

- a JSON schema for findings envelopes
- example eval prompts for skill review
- fixtures and examples for scanner/report behavior
- Node-based tests for the bundled scripts
- GitHub Actions CI for validation on push and pull request
- a deterministic local eval harness that writes grading and benchmark artifacts

The intended operating pattern is:

1. detect candidate issues conservatively
2. validate context to reduce false positives
3. report only evidence-backed findings
4. call out gaps separately from confirmed issues

Run tests with:

```powershell
npm test
```

## Versioning

Current version: `3.1.0`
Maintainer / author: `jovd83`

The upgrade from the earlier draft focuses on clearer operating boundaries, stronger output contracts, better documentation, more useful helper scripts, and repository-level validation artifacts.

## Optional Future Integrations

These are intentionally conceptual and not implemented here:

- organization-specific policy packs
- external CVE enrichment
- shared-memory integration for durable cross-project lessons
- scheduled CI wrappers for repository scans

If you add them later, keep them explicitly optional and clearly separated from the core skill behavior.
