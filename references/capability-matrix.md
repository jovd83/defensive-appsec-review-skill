# Defensive Capability Matrix

Use this reference to choose a review lens and to explain the skill's safe capabilities without drifting into offensive testing.

## Core Assessment Modes

### Repository and SDLC Review

Focus on:

- dependency and supply-chain hygiene
- secrets exposure
- CI/CD permissions and trust boundaries
- IaC and container configuration
- logging, telemetry, and sensitive data handling

### Web Application Review

Focus on:

- authentication and session management
- authorization boundaries
- input handling and output encoding
- file upload and content-processing risks
- security headers, cookies, CORS, and transport posture

### API Review

Focus on:

- broken object and function level authorization
- schema validation and mass assignment
- excessive data exposure
- authentication token handling
- rate limiting, abuse controls, and auditability
- REST, GraphQL, SOAP, and gRPC contract review when artifacts are available

### Mobile Review

Focus on:

- insecure local data storage
- hardcoded secrets or endpoints
- transport security assumptions
- build and debug configuration leakage
- authentication token storage and logging

### Cloud, Container, and Infrastructure Review

Focus on:

- permissive network exposure
- IAM and token overreach
- risky defaults in Docker, Kubernetes, and Terraform
- exposed storage or admin surfaces
- deployment-time secret handling

### AI-Enabled System Review

Focus on:

- prompt injection exposure at trust boundaries
- unsafe tool invocation paths
- secret leakage through context or logs
- cross-tenant or cross-user data access
- overprivileged model or agent actions

## Cross-Cutting Review Themes

- authentication
- authorization
- injection and input handling
- cryptography and key management
- business logic abuse
- supply chain and third-party risk
- compliance-aligned control mapping

## Out of Scope for This Skill

- exploit development
- persistence or lateral movement
- credential theft
- destructive stress testing
- stealth or evasion techniques
