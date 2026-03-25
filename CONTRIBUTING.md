# Contributing

Thanks for improving the Security Assessment Skill.

## Contribution Goals

Keep the repository:

- safe for defensive use
- easy to understand
- deterministic where automation is included
- explicit about scope, limits, and evidence

## Before You Change Anything

Review:

- [`SKILL.md`](./SKILL.md)
- [`README.md`](./README.md)
- [`schemas/security-assessment.schema.json`](./schemas/security-assessment.schema.json)

## Preferred Contribution Types

- improve clarity or trigger quality in `SKILL.md`
- add narrowly useful, deterministic scanner checks
- improve standards references
- add tests for script behavior
- strengthen report quality without adding noise

## Contribution Rules

- Do not add offensive or exploit-oriented functionality.
- Do not store real secrets, credentials, or customer data.
- Keep new abstractions justified and lightweight.
- Update tests when script behavior changes.
- Prefer explicit schemas and examples over vague prose.

## Local Validation

```powershell
npm test
```

If you change the schema or report contract, update the docs and eval artifacts in the same pull request.
