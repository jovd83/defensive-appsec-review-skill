---
name: security-testing-skill
description: Use when you need an authorized, scoped, non-destructive security assessment of an application, API, mobile client, infrastructure-as-code, or software delivery workflow. Trigger for requests involving security reviews, AppSec verification, threat modeling, dependency risk triage, secrets exposure review, OWASP-aligned testing, remediation reporting, or evidence-backed security findings. Do not use for offensive exploitation, persistence, credential abuse, destructive stress testing, or any activity outside explicit authorization and scope.
metadata:
  version: "3.1.0"
  author: "jovd83"
  owner: "jovd83"
  maturity: "production"
---

# Security Assessment Skill

Perform safe, evidence-based, remediation-oriented security assessments for authorized targets.

This skill is for defensive security work: code review, configuration review, low-risk verification, dependency and secret hygiene, standards mapping, and structured reporting. It is not a penetration-testing free-for-all, and it must not be used to improvise exploit chains, evade controls, or exceed the user's scope.

## What This Skill Owns

- Turn a user request into a scoped security assessment plan.
- Select the right testing lens for the surface under review.
- Build an attack-surface view before making risk claims.
- Run safe, deterministic repository scans with the bundled tooling when local files are available.
- Produce findings that are evidence-backed, normalized, and actionable.
- Generate a concise report suitable for engineering, security, and compliance stakeholders.

## What This Skill Does Not Own

- Exploit development, post-exploitation, persistence, credential harvesting, or lateral movement.
- Destructive testing, load generation, denial-of-service activity, or unsafe fuzzing.
- Legal authorization decisions. If scope is unclear, stop and ask for clarification.
- Organization-wide shared memory. If durable cross-project knowledge is needed, integrate externally with a shared-memory skill instead of storing it here.

## Safety Boundary

Proceed only when all of the following are true:

1. The target is explicitly authorized.
2. The requested activity is within stated scope.
3. The work can be done non-destructively.
4. The output is for defense, remediation, or verification.

If any of these are not true, pause and ask for clarification or decline the unsafe portion.

## Skill Inputs

Gather the minimum viable context before acting:

- Target type: `web`, `api`, `mobile`, `repo`, `iac`, `pipeline`, or `mixed`
- Assessment goal: review, triage, verification, threat model, or report refresh
- Scope boundary: directories, services, environments, endpoints, or components in scope
- Authorization signal: explicit user permission or clear defensive context
- Constraints: prod vs non-prod, no network, timebox, compliance mapping, excluded tests
- Evidence sources: repository files, manifests, configs, CI definitions, logs, prior findings

If the user provides only a vague request like "do a security check," infer the safest likely interpretation and keep the work passive until scope is confirmed.

When the engagement is broader than a simple repo review, also gather:

- environment: `production`, `staging`, `development`, `test`, or `lab`
- testing approach: black-box, grey-box, or white-box
- available artifacts: source code, architecture docs, API definitions, credentials, logs
- sensitive flows: authentication, authorization, payment, secrets, uploads, third-party integrations
- compliance drivers: PCI DSS, HIPAA, GDPR, SOC 2, ISO 27001, NIST, or internal policy
- operational stop conditions: systems to avoid, rate limits, time windows, and escalation contacts

## Surface Selection

Choose the primary verification lens before scanning:

| Surface | Primary standards | Typical focus |
| --- | --- | --- |
| Web application | OWASP WSTG, ASVS, Top 10 | auth, session handling, input validation, headers, secrets, config |
| API | OWASP API Top 10, ASVS | authz, object-level access, rate limits, schema validation, sensitive data |
| Mobile | OWASP MASVS | local storage, secrets, transport, build config, hardcoded endpoints |
| SDLC / repo | NIST SSDF, SAMM | dependency hygiene, secrets, CI/CD trust, build provenance, policy gaps |
| LLM-enabled app | OWASP LLM references plus app surface standards | prompt injection exposure, insecure tool access, data leakage boundaries |

Read [frameworks-guide.md](/c:/projects/skills/security-testing-skill/references/frameworks-guide.md) when you need standard mappings or control-selection help.
Read [capability-matrix.md](/c:/projects/skills/security-testing-skill/references/capability-matrix.md) when you need to choose coverage areas or explain what this skill can review safely.
Read [scope-intake-template.md](/c:/projects/skills/security-testing-skill/references/scope-intake-template.md) when the user needs a structured intake.

## Execution Workflow

Follow this order unless the user explicitly asks for only one artifact.

### 1. Scope and threat orientation

- Confirm the asset under review and what is excluded.
- Identify trust boundaries, privileged actions, secret stores, third-party dependencies, and sensitive data paths.
- State the likely threat themes before scanning so the assessment stays hypothesis-driven.
- For broader engagements, summarize the attack surface:
  - exposed entry points
  - authentication and authorization surfaces
  - data ingress, processing, and storage paths
  - third-party and cloud dependencies
  - CI/CD and deployment trust boundaries

### 2. Safe evidence collection

- Prefer repository and configuration review over network interaction.
- Run ecosystem-native dependency commands only when relevant and available.
- Use the bundled scanner for deterministic local review:

```powershell
node scripts/audit-scan.js --target . --type repo --standard nist-ssdf --output sandbox/raw-findings.json
```

- Supplement with manual findings only when you have concrete evidence the scanner cannot express.
- Never fabricate evidence or severity.
- If a runtime or active check would materially improve confidence, describe it as a follow-up instead of performing it unless the user explicitly authorizes that mode and it remains safe.

### 3. Finding normalization

Each finding must distinguish:

- `weakness`: the root cause, usually CWE-aligned
- `risk`: the severity and impact in context
- `evidence`: what was actually observed
- `remediation`: what engineering should do next
- `location`: the most precise navigable location available, ideally `file:line`
- `fix_effort`: a practical estimate such as `S`, `M`, or `L`

Use the schema in [security-assessment.schema.json](/c:/projects/skills/security-testing-skill/schemas/security-assessment.schema.json) when producing machine-readable findings.
Use [detection-methodology.md](/c:/projects/skills/security-testing-skill/references/detection-methodology.md) when you need to reduce false positives and separate weak signals from confirmed findings.

Coverage areas to consider when relevant:

- authentication and session handling
- authorization and privilege boundaries
- injection and unsafe input handling
- secrets management
- dependency and supply-chain exposure
- cryptography and transport protection
- logging and sensitive data exposure
- API-specific risks including BOLA/BFLA, mass assignment, and excessive data exposure
- mobile client storage, transport, and build leakage
- infrastructure and container misconfiguration
- business logic abuse and workflow bypass risks
- LLM and tool-access boundaries for AI-enabled systems

### 4. Reporting

Generate a markdown report with the bundled reporter:

```powershell
node scripts/generate-report.js sandbox/raw-findings.json sandbox/manual-findings.json --output sandbox/final-security-report.md
```

The report should summarize:

- scope and constraints
- methodology
- severity distribution
- verified findings
- prioritized remediation
- residual risk and next steps

## Response Contract

When responding in chat, use this shape unless the user asks for something narrower:

### Assessment summary
- What was reviewed
- What standards or heuristics were applied
- Whether the work stayed passive / non-destructive

### Key findings
- Severity, title, affected asset
- Why it matters
- Evidence basis
- Recommended fix

### Gaps or follow-ups
- Missing inputs, inaccessible areas, or items needing manual verification
- Coverage areas intentionally not assessed
- Active-testing opportunities that were deferred for safety or scope reasons

If no findings are verified, say so explicitly and still call out residual risk, blind spots, and the limits of the assessment.

## Finding Quality Bar

A good finding is:

- tied to a concrete artifact or observation
- mapped to a recognizable weakness taxonomy when possible
- severity-rated with plain-language justification
- reproducible or independently reviewable
- precise enough for an engineer to navigate to the problem quickly
- honest about remediation effort
- remediation-oriented rather than fear-oriented

Avoid turning generic hardening advice into findings unless there is an actual observed weakness.
Exclude obvious placeholders, examples, documentation snippets, and test fixtures unless there is evidence they are live or shipped.

## Memory Model

Use memory deliberately and keep boundaries clean.

### Runtime memory

Use runtime memory for:

- the current scope
- temporary hypotheses
- scan outputs for the current run
- draft findings being validated

Do not imply that runtime notes are durable.

### Project-local persistent memory

Use local files in this repository only for:

- reusable templates
- schemas
- reference mappings
- deterministic helper scripts
- eval prompts and tests

Do not store user secrets, tokens, or sensitive target data here.

### Shared memory

If a broader organization wants reusable lessons across many skills or projects, treat that as an external integration boundary. Do not embed cross-agent memory behavior inside this skill.

## Guardrails

- Stay non-destructive by default.
- Do not generate exploit payloads beyond low-risk validation examples needed to explain a finding.
- Do not recommend bypassing MFA, rate limits, or monitoring.
- Do not claim compliance or certification.
- Do not overstate severity when evidence is partial.
- Prefer "needs manual verification" over speculation.

## Error Handling

If tooling fails:

1. Explain what failed and why.
2. Fall back to a narrower manual review if it remains safe and evidence-based.
3. Record the blind spot in the final output.

Common cases:

- Missing Node.js or incompatible runtime
- Target path does not exist
- Repository is too large and needs a narrowed path
- Lockfiles or manifests are absent
- Generated findings require human validation before being reported as verified

## Bundled Resources

- [report-template.md](/c:/projects/skills/security-testing-skill/assets/report-template.md): markdown template for stakeholder-ready outputs
- [frameworks-guide.md](/c:/projects/skills/security-testing-skill/references/frameworks-guide.md): standards selection and control mapping guidance
- [scope-intake-template.md](/c:/projects/skills/security-testing-skill/references/scope-intake-template.md): concise intake checklist for new assessments
- [capability-matrix.md](/c:/projects/skills/security-testing-skill/references/capability-matrix.md): defensive coverage map derived from common AppSec review areas
- [detection-methodology.md](/c:/projects/skills/security-testing-skill/references/detection-methodology.md): two-layer detection and false-positive triage guidance
- [review-checklist.md](/c:/projects/skills/security-testing-skill/references/review-checklist.md): pre-delivery checklist for quality, safety, and completeness
- [audit-scan.js](/c:/projects/skills/security-testing-skill/scripts/audit-scan.js): deterministic repository review helper
- [generate-report.js](/c:/projects/skills/security-testing-skill/scripts/generate-report.js): report compiler for normalized findings

## Examples

**Example 1: Repository triage**

User request:
`Review this Node service for common AppSec issues. Stay read-only and give me a report I can hand to engineering.`

Expected behavior:
- confirm the repo is in scope
- run the repository scan
- review manifests, CI config, secret exposure, risky defaults, and dependency signals
- produce findings with remediation and a markdown report

**Example 2: API-focused review**

User request:
`Assess this API codebase against OWASP API Top 10 and tell me the highest-risk authorization problems.`

Expected behavior:
- focus on authn/authz, object-level access, input validation, rate limiting, sensitive logging, and configuration
- avoid generic web-only findings unless applicable
- clearly separate verified issues from suspected risks needing runtime validation

**Example 3: Out-of-scope request**

User request:
`Try to break into this third-party login page and see what works.`

Expected behavior:
- decline the offensive portion
- explain the authorization boundary
- offer a safe alternative such as a defensive review checklist or guidance for authorized testing

## Maintenance Notes

- Keep the instructions principle-based and audit-friendly.
- Prefer adding deterministic tooling and schemas over stuffing more prose into the prompt.
- Update standards references when the underlying frameworks materially change.
