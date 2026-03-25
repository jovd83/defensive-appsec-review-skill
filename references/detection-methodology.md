# Detection Methodology

Use a two-layer approach so the skill stays useful without flooding the user with noise.

## Layer 1: Candidate Detection

First, identify candidate issues using deterministic signals such as:

- credential-like patterns
- dangerous APIs like `eval`, `innerHTML`, `subprocess(shell=True)`, or unsafe deserialization helpers
- insecure dependency audit results
- permissive CI, container, or IaC settings
- missing validation at obvious system boundaries

Treat this layer as signal collection, not proof.

## Layer 2: Context Validation

For each candidate, read enough surrounding context to classify it:

- placeholder or example value -> likely false positive
- test fixture or mocked credential -> usually downgrade or exclude
- docs snippet or tutorial code -> document only if it ships or is copied into production paths
- framework-protected sink -> downgrade if auto-escaping or parameterization is actually in effect
- production path with untrusted input and no nearby control -> confirm

## False Positive Triage Heuristics

- `.env.example`, demo configs, and docs examples are not equal to live secrets
- a vulnerable dependency matters more when the package is reachable in production paths
- an XSS sink matters less when the framework escapes by default and no unsafe bypass is used
- a suspected injection issue needs an untrusted-input path, not just string building in isolation

## Precision Rules

- Prefer `file:line` over only a file path when you can justify it
- Include one concise evidence snippet or description
- Use `fix_effort` only when you can estimate realistically:
  - `S`: localized change, usually under an hour
  - `M`: modest implementation or validation work
  - `L`: broad refactor, dependency migration, or cross-team change

## Reporting Rule

If confidence is low, say `needs manual verification` instead of reporting it as a confirmed issue.
