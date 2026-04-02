# Changelog

All notable changes to this project will be documented in this file.

## 4.0.0 - 2026-04-01

- Rewrote `SKILL.md` into a tighter operational contract aligned to progressive disclosure and the published Agent Skills format
- Added richer frontmatter metadata including `license`, `compatibility`, and structured package metadata
- Refactored `README.md` into GitHub-facing product documentation instead of duplicating the full skill prompt
- Added `CONTRIBUTING.md` and `SECURITY.md` to improve open-source maintainer readiness
- Added `evals/trigger-evals.json` to support trigger-description review and future skill-evaluation work
- Added `scripts/validate-skill-package.js` plus tests and CI wiring to catch metadata drift across `SKILL.md`, `package.json`, and `agents/openai.yaml`
- Upgraded `scripts/run-local-evals.js` to accept configurable eval config, workspace, and iteration arguments for more reusable local validation

## 3.4.0 - 2026-03-28

- Added a first-class HTML report format with a fixed professional template
- Added a reusable `assets/report-template.html` design system for consistent report presentation
- Added "What Was Tested" and scan telemetry sections to markdown and HTML reports
- Added explicit per-finding mappings for OWASP ASVS, NIST SSDF, CIS Controls v8, OWASP SCVS, and SLSA
- Added an OWASP SAMM overview lens for SDLC and repository-oriented reporting
- Added deep scan mode with external-result ingestion and merged report telemetry
- Regenerated sample and sandbox reports to reflect the richer framework output
- Expanded tests and local evals to validate HTML reporting alongside markdown and SARIF outputs
- Updated documentation to include HTML report generation in the supported workflow

## 3.3.0 - 2026-03-28

- Added external-result normalization for SARIF, Gitleaks, Trivy, OSV-Scanner, OpenSSF Scorecard, and OWASP Dependency-Check
- Added source-tool provenance to findings and report output
- Added documentation for SCVS, SLSA, CycloneDX, CWE Top 25, and external-tool workflows
- Expanded fixtures, tests, and local eval coverage for external scanner interoperability

## 3.2.0 - 2026-03-28

- Expanded the scanner with stronger OWASP-aligned heuristics for SSRF, mass assignment, open redirects, path traversal, weak crypto, and object-level authorization review targets
- Added explicit per-finding OWASP mappings plus verification-tier metadata
- Added metadata coverage profiles and declared static-analysis blind spots to keep reports honest about runtime limits
- Updated tests, fixtures, schema, and report output to reflect the richer AppSec review contract

## 3.1.0 - 2026-03-25

- Added OpenAI-facing metadata in `agents/openai.yaml`
- Added GitHub packaging files including templates, CODEOWNERS, and MIT licensing
- Added SARIF-style report output for CI and code scanning workflows
- Expanded scanner coverage with additional language-specific sink checks
- Added richer fixtures, examples, and test coverage for scanner and report generation

## 3.0.0 - 2026-03-25

- Rebuilt the skill into a publishable defensive security assessment package
- Added stronger guardrails, scope handling, and response contracts
- Added references, schemas, evals, contribution guidance, and report templates
- Upgraded the scanner and report generator with richer findings output
- Added tests, examples, fixtures, CI support, and GitHub community files
- Added author metadata for `jovd83` and licensed the project under MIT
