#!/usr/bin/env node

/**
 * Read-only repository security scanner.
 *
 * Usage:
 *   node scripts/audit-scan.js --target . --type repo --standard nist-ssdf --output sandbox/raw-findings.json
 */

const fs = require("fs");
const path = require("path");

const DEFAULT_EXCLUDED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  "out",
  "target",
  "bin",
  "obj",
  ".turbo"
]);

const args = process.argv.slice(2);
const options = {};

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (!arg.startsWith("--")) {
    continue;
  }

  const key = arg.slice(2);
  const next = args[i + 1];
  if (!next || next.startsWith("--")) {
    options[key] = true;
    continue;
  }

  options[key] = next;
  i += 1;
}

const target = path.resolve(process.cwd(), options.target || ".");
const surface = options.type || "repo";
const standard = options.standard || "nist-ssdf";
const output = path.resolve(process.cwd(), options.output || "findings.json");
const maxFileSizeBytes = Number(options.maxFileSizeBytes || 1024 * 1024);

if (!fs.existsSync(target)) {
  console.error(`[-] Target does not exist: ${target}`);
  process.exit(1);
}

if (!fs.statSync(target).isDirectory()) {
  console.error(`[-] Target must be a directory: ${target}`);
  process.exit(1);
}

function walk(dir, files = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (DEFAULT_EXCLUDED_DIRS.has(entry.name)) {
        continue;
      }
      walk(fullPath, files);
      continue;
    }

    files.push(fullPath);
  }

  return files;
}

function toRelative(filePath) {
  return (path.relative(target, filePath) || ".").split(path.sep).join("/");
}

function safeRead(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxFileSizeBytes) {
      return null;
    }
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function severityFromScore(score, label) {
  return `${score.toFixed(1)} (${label})`;
}

function createFinding(overrides) {
  return {
    title: overrides.title,
    asset: overrides.asset,
    location: overrides.location,
    category: overrides.category,
    cwe: overrides.cwe,
    cvss_v4: overrides.cvss_v4,
    confidence: overrides.confidence || "Medium",
    framework_mapping: {
      standard,
      control: overrides.control
    },
    evidence: overrides.evidence,
    reproduction_steps: overrides.reproduction_steps,
    business_impact: overrides.business_impact,
    remediation: overrides.remediation,
    fix_effort: overrides.fix_effort,
    references: overrides.references || []
  };
}

function pushUnique(findings, finding) {
  const key = `${finding.title}|${finding.asset}|${finding.cwe}`;
  if (!findings.some((item) => `${item.title}|${item.asset}|${item.cwe}` === key)) {
    findings.push(finding);
  }
}

function locateLine(contents, pattern) {
  const lines = contents.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.test(lines[index])) {
      return index + 1;
    }
  }
  return null;
}

function likelyExampleOrFixture(relativePath) {
  return /(^|\/)(example|examples|sample|samples|fixture|fixtures|test|tests|docs)\//i.test(relativePath) ||
    /\.example(\.|$)/i.test(relativePath);
}

function scanFiles(files) {
  const findings = [];
  const manifests = [];

  for (const filePath of files) {
    const relativePath = toRelative(filePath);
    const base = path.basename(filePath).toLowerCase();
    const contents = safeRead(filePath);

    if ([
      "package.json",
      "package-lock.json",
      "yarn.lock",
      "pnpm-lock.yaml",
      "requirements.txt",
      "poetry.lock",
      "pipfile",
      "cargo.toml",
      "cargo.lock",
      "pom.xml",
      "build.gradle",
      "go.mod",
      "gemfile.lock"
    ].includes(base)) {
      manifests.push(relativePath);
    }

    if (!contents) {
      continue;
    }

    const lines = contents.split(/\r?\n/);
    const exampleLike = likelyExampleOrFixture(relativePath);

    if (base === ".env" || base.endsWith(".env") || relativePath.includes(".env")) {
      pushUnique(findings, createFinding({
        title: "Environment file stored in repository path",
        asset: relativePath,
        category: "Secrets Management",
        cwe: "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
        cvss_v4: severityFromScore(6.3, "Medium"),
        confidence: "High",
        location: relativePath,
        control: "Repository secret hygiene",
        evidence: "An environment-style file is present in the repository path and may contain secrets or operational configuration.",
        reproduction_steps: `1. Open ${relativePath}.\n2. Review whether the file contains credentials, tokens, keys, or sensitive configuration.`,
        business_impact: "Secrets committed to source control can be copied, leaked, or reused across environments.",
        remediation: "Remove secrets from committed environment files, rotate any exposed credentials, and replace with secret-manager or deployment-time injection patterns.",
        fix_effort: "M"
      }));
    }

    const secretPatterns = [
      { pattern: /AKIA[0-9A-Z]{16}/g, name: "AWS access key identifier" },
      { pattern: /ghp_[A-Za-z0-9]{36,}/g, name: "GitHub personal access token" },
      { pattern: /AIza[0-9A-Za-z\-_]{35}/g, name: "Google API key" },
      { pattern: /(?:secret|token|api[_-]?key|password)\s*[:=]\s*['"][^'"\n]{8,}['"]/gi, name: "inline secret assignment" }
    ];

    for (const { pattern, name } of secretPatterns) {
      const match = contents.match(pattern);
      if (match && !exampleLike) {
        pushUnique(findings, createFinding({
          title: `Potential hardcoded credential detected (${name})`,
          asset: relativePath,
          category: "Credential Management",
          cwe: "CWE-798: Use of Hard-coded Credentials",
          cvss_v4: severityFromScore(8.6, "High"),
          confidence: "Medium",
          location: relativePath,
          control: "Secret exposure prevention",
          evidence: `Matched ${name} pattern in ${relativePath}. Representative token redacted for safety.`,
          reproduction_steps: `1. Open ${relativePath}.\n2. Search for the matched credential-like value.\n3. Verify whether the value is active, test-only, or placeholder data.`,
          business_impact: "Live credentials in source code can enable unauthorized access, service abuse, or downstream compromise.",
          remediation: "Move credentials to a managed secret store, rotate any exposed values, and add repository scanning or pre-commit controls.",
          fix_effort: "M"
        }));
      }
    }

    if (/access-control-allow-origin\s*[:=]\s*['"]\*['"]/i.test(contents) || /origin:\s*['"]\*['"]/i.test(contents)) {
      const lineNumber = locateLine(contents, /access-control-allow-origin\s*[:=]\s*['"]\*['"]/i) || locateLine(contents, /origin:\s*['"]\*['"]/i);
      pushUnique(findings, createFinding({
        title: "Wildcard CORS policy indicated in source or config",
        asset: relativePath,
        category: "Configuration",
        cwe: "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        cvss_v4: severityFromScore(6.8, "Medium"),
        confidence: "Medium",
        location: lineNumber ? `${relativePath}:${lineNumber}` : relativePath,
        control: "CORS policy hardening",
        evidence: `A wildcard origin pattern was detected in ${relativePath}.`,
        reproduction_steps: `1. Review the CORS configuration in ${relativePath}.\n2. Confirm whether all origins are allowed in deployed environments.`,
        business_impact: "Overly broad CORS can increase exposure of authenticated APIs or browser-accessible data to untrusted origins.",
        remediation: "Restrict allowed origins to trusted domains and align the policy to actual frontend usage.",
        fix_effort: "S"
      }));
    }

    if (/set-cookie/i.test(contents) && !/httponly/i.test(contents)) {
      const lineNumber = locateLine(contents, /set-cookie/i);
      pushUnique(findings, createFinding({
        title: "Cookie handling hint without HttpOnly flag",
        asset: relativePath,
        category: "Session Management",
        cwe: "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
        cvss_v4: severityFromScore(5.5, "Medium"),
        confidence: "Low",
        location: lineNumber ? `${relativePath}:${lineNumber}` : relativePath,
        control: "Cookie security flags",
        evidence: `Cookie-setting code or configuration appears in ${relativePath}, but no nearby HttpOnly marker was found.`,
        reproduction_steps: `1. Review cookie creation logic in ${relativePath}.\n2. Confirm whether HttpOnly, Secure, and SameSite are enforced at runtime.`,
        business_impact: "Weak cookie flags can increase session theft or cross-site exploitation risk.",
        remediation: "Ensure sensitive cookies set HttpOnly, Secure, and an appropriate SameSite value.",
        fix_effort: "S"
      }));
    }

    if (/http:\/\//i.test(contents) && !/localhost|127\.0\.0\.1/i.test(contents)) {
      const lineNumber = locateLine(contents, /http:\/\//i);
      pushUnique(findings, createFinding({
        title: "Non-local plaintext HTTP endpoint referenced",
        asset: relativePath,
        category: "Transport Security",
        cwe: "CWE-319: Cleartext Transmission of Sensitive Information",
        cvss_v4: severityFromScore(5.8, "Medium"),
        confidence: "Low",
        location: lineNumber ? `${relativePath}:${lineNumber}` : relativePath,
        control: "Transport security review",
        evidence: `A non-local HTTP URL reference was found in ${relativePath}.`,
        reproduction_steps: `1. Inspect URL references in ${relativePath}.\n2. Determine whether the plaintext endpoint is used in any deployed environment.`,
        business_impact: "Plaintext transport can expose credentials or sensitive application traffic to interception.",
        remediation: "Prefer HTTPS for all non-local endpoints and isolate any local-development exceptions.",
        fix_effort: "S"
      }));
    }

    if (relativePath.startsWith(".github/workflows/")) {
      if (/permissions:\s*\n\s*contents:\s*write/i.test(contents) || /permissions:\s*write-all/i.test(contents)) {
        pushUnique(findings, createFinding({
          title: "Broad GitHub Actions token permissions",
          asset: relativePath,
          category: "CI/CD Security",
          cwe: "CWE-732: Incorrect Permission Assignment for Critical Resource",
          cvss_v4: severityFromScore(6.7, "Medium"),
          confidence: "High",
          location: relativePath,
          control: "Least privilege in CI",
          evidence: `Workflow ${relativePath} appears to grant write-capable or broad token permissions.`,
          reproduction_steps: `1. Open ${relativePath}.\n2. Review the permissions block and job-level token requirements.`,
          business_impact: "Excessive CI token privileges can amplify the impact of workflow compromise or malicious pull request execution.",
          remediation: "Reduce workflow token permissions to the minimum required and prefer job-scoped permissions.",
          fix_effort: "S"
        }));
      }

      if (/pull_request_target/i.test(contents) && /checkout/i.test(contents)) {
        pushUnique(findings, createFinding({
          title: "Workflow uses pull_request_target with repository checkout",
          asset: relativePath,
          category: "CI/CD Security",
          cwe: "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
          cvss_v4: severityFromScore(8.0, "High"),
          confidence: "Medium",
          location: relativePath,
          control: "Untrusted workflow execution",
          evidence: `The workflow ${relativePath} references pull_request_target and checks out code, a pattern that requires careful isolation.`,
          reproduction_steps: `1. Review trigger conditions in ${relativePath}.\n2. Confirm whether untrusted fork code can influence privileged workflow steps.`,
          business_impact: "Unsafe CI trigger patterns can expose secrets or privileged automation to attacker-controlled changes.",
          remediation: "Avoid privileged checkout of untrusted pull request code or split privileged actions into separately gated workflows.",
          fix_effort: "M"
        }));
      }
    }

    if (base === "dockerfile" || base.endsWith(".dockerfile")) {
      if (/USER\s+root/i.test(contents)) {
        const lineNumber = locateLine(contents, /USER\s+root/i);
        pushUnique(findings, createFinding({
          title: "Container runs as root",
          asset: relativePath,
          category: "Container Security",
          cwe: "CWE-250: Execution with Unnecessary Privileges",
          cvss_v4: severityFromScore(5.9, "Medium"),
          confidence: "High",
          location: lineNumber ? `${relativePath}:${lineNumber}` : relativePath,
          control: "Least privilege for containers",
          evidence: `Docker build instructions in ${relativePath} set or retain root execution context.`,
          reproduction_steps: `1. Open ${relativePath}.\n2. Confirm the final runtime user for the container image.`,
          business_impact: "Root containers can increase blast radius if the application or container is compromised.",
          remediation: "Create and use a non-root runtime user unless a documented exception is required.",
          fix_effort: "S"
        }));
      }
    }

    if (base.endsWith(".tf") && /0\.0\.0\.0\/0/.test(contents)) {
      const lineNumber = locateLine(contents, /0\.0\.0\.0\/0/);
      pushUnique(findings, createFinding({
        title: "Infrastructure rule allows 0.0.0.0/0",
        asset: relativePath,
        category: "Infrastructure Security",
        cwe: "CWE-284: Improper Access Control",
        cvss_v4: severityFromScore(7.4, "High"),
        confidence: "Medium",
        location: lineNumber ? `${relativePath}:${lineNumber}` : relativePath,
        control: "Network exposure review",
        evidence: `Terraform configuration ${relativePath} includes a 0.0.0.0/0 rule.`,
        reproduction_steps: `1. Review ingress and egress rules in ${relativePath}.\n2. Verify which protocol and port are exposed and whether the rule is intentional.`,
        business_impact: "Unrestricted network exposure can significantly broaden attack surface.",
        remediation: "Constrain ingress and egress ranges to trusted networks and document any required public exposure.",
        fix_effort: "S"
      }));
    }

    if (!exampleLike) {
      const evalLine = locateLine(contents, /\beval\s*\(/);
      if (evalLine) {
        pushUnique(findings, createFinding({
          title: "Dynamic code execution via eval detected",
          asset: relativePath,
          location: `${relativePath}:${evalLine}`,
          category: "Code Injection Risk",
          cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
          cvss_v4: severityFromScore(7.8, "High"),
          confidence: "Medium",
          control: "Avoid dynamic evaluation",
          evidence: `Detected eval-style dynamic code execution at ${relativePath}:${evalLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${evalLine}.\n2. Confirm whether untrusted input can reach the dynamic evaluation sink.`,
          business_impact: "Dynamic evaluation can convert input validation gaps into code execution or severe injection exposure.",
          remediation: "Remove eval-style execution and replace it with safe parsing or explicit control flow.",
          fix_effort: "M"
        }));
      }

      const htmlSinkLine = locateLine(contents, /\b(innerHTML|dangerouslySetInnerHTML)\b/);
      if (htmlSinkLine) {
        pushUnique(findings, createFinding({
          title: "Unsafe HTML rendering sink detected",
          asset: relativePath,
          location: `${relativePath}:${htmlSinkLine}`,
          category: "Input Validation",
          cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation",
          cvss_v4: severityFromScore(6.9, "Medium"),
          confidence: "Medium",
          control: "Safe output encoding",
          evidence: `Detected HTML sink usage at ${relativePath}:${htmlSinkLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${htmlSinkLine}.\n2. Verify whether untrusted content reaches the sink without sanitization.`,
          business_impact: "Unsafe HTML sinks can enable stored or reflected client-side script execution.",
          remediation: "Prefer framework-safe rendering paths or sanitize input before rendering HTML.",
          fix_effort: "S"
        }));
      }

      const subprocessLine = locateLine(contents, /\b(exec|spawn|subprocess\.run|subprocess\.Popen)\b/);
      if (subprocessLine && /shell\s*[:=]\s*true|shell\s*=\s*True/.test(contents)) {
        pushUnique(findings, createFinding({
          title: "Shell-enabled subprocess execution detected",
          asset: relativePath,
          location: `${relativePath}:${subprocessLine}`,
          category: "Command Execution Risk",
          cwe: "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
          cvss_v4: severityFromScore(8.1, "High"),
          confidence: "Medium",
          control: "Safe process execution",
          evidence: `Detected subprocess execution with shell enabled near ${relativePath}:${subprocessLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${subprocessLine}.\n2. Confirm whether user-controlled values can influence the executed command.`,
          business_impact: "Shell-enabled subprocess calls can turn input handling mistakes into command injection or privilege abuse.",
          remediation: "Avoid shell-enabled execution, pass arguments as arrays, and validate or constrain any user-derived values.",
          fix_effort: "M"
        }));
      }

      const jwtLine = locateLine(contents, /jwt\.sign|jwt\.verify|jsonwebtoken/);
      if (jwtLine && (/algorithm\s*[:=]\s*['"]none['"]/i.test(contents) || /ignoreExpiration\s*[:=]\s*true/i.test(contents) || /verify\s*\([^)]*,\s*null/i.test(contents))) {
        pushUnique(findings, createFinding({
          title: "Potentially insecure JWT handling configuration",
          asset: relativePath,
          location: `${relativePath}:${jwtLine}`,
          category: "Authentication",
          cwe: "CWE-347: Improper Verification of Cryptographic Signature",
          cvss_v4: severityFromScore(7.1, "High"),
          confidence: "Medium",
          control: "Token validation hardening",
          evidence: `Detected JWT usage with potentially unsafe verification or algorithm settings near ${relativePath}:${jwtLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${jwtLine}.\n2. Verify token verification configuration, accepted algorithms, and expiration handling.`,
          business_impact: "Weak token verification can allow forgery, replay, or authentication bypass.",
          remediation: "Require explicit strong algorithms, validate signatures correctly, and avoid disabling expiration checks outside controlled tests.",
          fix_effort: "M"
        }));
      }

      const pickleLine = locateLine(contents, /\b(pickle\.loads|pickle\.load)\b/);
      if (pickleLine) {
        pushUnique(findings, createFinding({
          title: "Python pickle deserialization sink detected",
          asset: relativePath,
          location: `${relativePath}:${pickleLine}`,
          category: "Unsafe Deserialization",
          cwe: "CWE-502: Deserialization of Untrusted Data",
          cvss_v4: severityFromScore(7.7, "High"),
          confidence: "Medium",
          control: "Avoid unsafe deserialization",
          evidence: `Detected pickle deserialization usage at ${relativePath}:${pickleLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${pickleLine}.\n2. Confirm whether untrusted or externally supplied data reaches the pickle load call.`,
          business_impact: "Unsafe deserialization can allow code execution or integrity compromise when attacker-controlled data is processed.",
          remediation: "Avoid pickle for untrusted data and use safer serialization formats with strict validation.",
          fix_effort: "M"
        }));
      }

      const yamlLine = locateLine(contents, /\byaml\.load\s*\(/);
      if (yamlLine && !/safe_load\s*\(/.test(contents)) {
        pushUnique(findings, createFinding({
          title: "Unsafe YAML load detected",
          asset: relativePath,
          location: `${relativePath}:${yamlLine}`,
          category: "Unsafe Deserialization",
          cwe: "CWE-502: Deserialization of Untrusted Data",
          cvss_v4: severityFromScore(7.2, "High"),
          confidence: "Medium",
          control: "Safe YAML parsing",
          evidence: `Detected yaml.load usage at ${relativePath}:${yamlLine} without an obvious safe loader pattern nearby.`,
          reproduction_steps: `1. Inspect ${relativePath}:${yamlLine}.\n2. Verify whether attacker-controlled YAML can reach the parser and which loader is used.`,
          business_impact: "Unsafe YAML loading can enable deserialization-based compromise or dangerous object construction.",
          remediation: "Use safe YAML loading primitives and validate input before parsing.",
          fix_effort: "S"
        }));
      }

      const runtimeExecLine = locateLine(contents, /\bRuntime\.getRuntime\(\)\.exec\s*\(/);
      if (runtimeExecLine) {
        pushUnique(findings, createFinding({
          title: "Java Runtime.exec usage detected",
          asset: relativePath,
          location: `${relativePath}:${runtimeExecLine}`,
          category: "Command Execution Risk",
          cwe: "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
          cvss_v4: severityFromScore(7.9, "High"),
          confidence: "Medium",
          control: "Safe process execution",
          evidence: `Detected Runtime.exec invocation at ${relativePath}:${runtimeExecLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${runtimeExecLine}.\n2. Confirm whether untrusted input can influence the command string or arguments.`,
          business_impact: "Runtime command execution can allow command injection or unsafe privilege interactions when input is not tightly controlled.",
          remediation: "Avoid shell-like command construction, constrain arguments, and isolate process execution paths.",
          fix_effort: "M"
        }));
      }

      const sqlConcatLine = locateLine(contents, /\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\+|\$\{)/i);
      if (sqlConcatLine && /(query|executeQuery|executeUpdate|prepareStatement|sequelize\.query|cursor\.execute)/i.test(contents)) {
        pushUnique(findings, createFinding({
          title: "Potential SQL query string concatenation detected",
          asset: relativePath,
          location: `${relativePath}:${sqlConcatLine}`,
          category: "Injection",
          cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
          cvss_v4: severityFromScore(7.5, "High"),
          confidence: "Low",
          control: "Parameterized query usage",
          evidence: `Detected SQL text concatenation pattern near ${relativePath}:${sqlConcatLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${sqlConcatLine}.\n2. Confirm whether user-controlled values are interpolated into SQL rather than passed as parameters.`,
          business_impact: "Unparameterized SQL construction can expose the application to data access manipulation or broader database compromise.",
          remediation: "Use parameterized queries or ORM-safe bindings instead of dynamic SQL concatenation.",
          fix_effort: "M"
        }));
      }

      const flaskDebugLine = locateLine(contents, /\bapp\.run\s*\([^)]*debug\s*=\s*True/);
      if (flaskDebugLine) {
        pushUnique(findings, createFinding({
          title: "Flask debug mode enabled",
          asset: relativePath,
          location: `${relativePath}:${flaskDebugLine}`,
          category: "Configuration",
          cwe: "CWE-489: Active Debug Code",
          cvss_v4: severityFromScore(6.4, "Medium"),
          confidence: "Medium",
          control: "Production debug hardening",
          evidence: `Detected Flask debug mode enabled at ${relativePath}:${flaskDebugLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${flaskDebugLine}.\n2. Verify whether this configuration is reachable in non-development environments.`,
          business_impact: "Debug-enabled production services can expose sensitive diagnostics or unsafe interactive behavior.",
          remediation: "Disable debug mode outside local development and separate runtime configuration from source defaults.",
          fix_effort: "S"
        }));
      }

      const djangoDebugLine = locateLine(contents, /\bDEBUG\s*=\s*True/);
      if (djangoDebugLine) {
        pushUnique(findings, createFinding({
          title: "Django debug mode enabled",
          asset: relativePath,
          location: `${relativePath}:${djangoDebugLine}`,
          category: "Configuration",
          cwe: "CWE-489: Active Debug Code",
          cvss_v4: severityFromScore(6.4, "Medium"),
          confidence: "Medium",
          control: "Production debug hardening",
          evidence: `Detected DEBUG=True at ${relativePath}:${djangoDebugLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${djangoDebugLine}.\n2. Confirm whether production configuration can inherit this value.`,
          business_impact: "Debug-enabled deployments can expose sensitive errors, configuration details, or unsafe diagnostics.",
          remediation: "Set DEBUG to false outside development and inject environment-specific settings at deploy time.",
          fix_effort: "S"
        }));
      }

      const localStorageLine = locateLine(contents, /\blocalStorage\.setItem\s*\([^)]*(token|jwt|auth|session)/i);
      if (localStorageLine) {
        pushUnique(findings, createFinding({
          title: "Sensitive token stored in browser localStorage",
          asset: relativePath,
          location: `${relativePath}:${localStorageLine}`,
          category: "Session Management",
          cwe: "CWE-922: Insecure Storage of Sensitive Information",
          cvss_v4: severityFromScore(6.2, "Medium"),
          confidence: "Medium",
          control: "Client token storage review",
          evidence: `Detected token-like value stored in localStorage at ${relativePath}:${localStorageLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${localStorageLine}.\n2. Confirm whether access or refresh tokens are stored client-side in localStorage.`,
          business_impact: "Tokens in localStorage are more exposed to theft if XSS or browser extension compromise occurs.",
          remediation: "Prefer more constrained storage patterns such as secure cookies or short-lived in-memory tokens where appropriate.",
          fix_effort: "M"
        }));
      }

      const tlsBypassLine = locateLine(contents, /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/);
      if (tlsBypassLine) {
        pushUnique(findings, createFinding({
          title: "TLS certificate verification appears disabled",
          asset: relativePath,
          location: `${relativePath}:${tlsBypassLine}`,
          category: "Transport Security",
          cwe: "CWE-295: Improper Certificate Validation",
          cvss_v4: severityFromScore(7.0, "High"),
          confidence: "Medium",
          control: "TLS validation hardening",
          evidence: `Detected a TLS verification bypass pattern at ${relativePath}:${tlsBypassLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${tlsBypassLine}.\n2. Confirm whether certificate validation is disabled outside local test code.`,
          business_impact: "Disabled certificate validation increases exposure to man-in-the-middle attacks and unsafe upstream trust.",
          remediation: "Enable certificate verification by default and isolate any local-development exceptions from production code paths.",
          fix_effort: "S"
        }));
      }

      const springActuatorLine = locateLine(contents, /management\.endpoints\.web\.exposure\.include\s*[:=]\s*\*/);
      if (springActuatorLine) {
        pushUnique(findings, createFinding({
          title: "Spring actuator endpoints broadly exposed",
          asset: relativePath,
          location: `${relativePath}:${springActuatorLine}`,
          category: "Configuration",
          cwe: "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
          cvss_v4: severityFromScore(6.6, "Medium"),
          confidence: "Medium",
          control: "Operational endpoint exposure review",
          evidence: `Detected broad actuator exposure in ${relativePath}:${springActuatorLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${springActuatorLine}.\n2. Confirm which management endpoints are exposed and whether access controls protect them.`,
          business_impact: "Broadly exposed operational endpoints can leak diagnostics, environment details, or privileged service information.",
          remediation: "Expose only required actuator endpoints and restrict access with strong network and application controls.",
          fix_effort: "S"
        }));
      }
    }

    if (base === "deployment.yaml" || base === "deployment.yml" || base.endsWith(".k8s.yaml") || base.endsWith(".k8s.yml")) {
      const privilegedLine = locateLine(contents, /privileged\s*:\s*true/);
      if (privilegedLine) {
        pushUnique(findings, createFinding({
          title: "Kubernetes container runs in privileged mode",
          asset: relativePath,
          location: `${relativePath}:${privilegedLine}`,
          category: "Container Security",
          cwe: "CWE-250: Execution with Unnecessary Privileges",
          cvss_v4: severityFromScore(7.3, "High"),
          confidence: "High",
          control: "Least privilege in Kubernetes",
          evidence: `Detected privileged: true in ${relativePath}:${privilegedLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${privilegedLine}.\n2. Confirm whether the workload truly requires privileged execution.`,
          business_impact: "Privileged containers materially expand the blast radius of workload compromise.",
          remediation: "Remove privileged mode unless there is a documented exception and compensating controls are in place.",
          fix_effort: "M"
        }));
      }

      const hostPathLine = locateLine(contents, /hostPath\s*:/);
      if (hostPathLine) {
        pushUnique(findings, createFinding({
          title: "Kubernetes hostPath mount detected",
          asset: relativePath,
          location: `${relativePath}:${hostPathLine}`,
          category: "Container Security",
          cwe: "CWE-668: Exposure of Resource to Wrong Sphere",
          cvss_v4: severityFromScore(6.8, "Medium"),
          confidence: "Medium",
          control: "Host filesystem exposure review",
          evidence: `Detected hostPath usage in ${relativePath}:${hostPathLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${hostPathLine}.\n2. Verify whether the mounted host path is necessary and sufficiently constrained.`,
          business_impact: "Host mounts can expose sensitive node resources or weaken workload isolation.",
          remediation: "Avoid hostPath where possible or constrain mounts tightly with read-only and least-privilege settings.",
          fix_effort: "M"
        }));
      }
    }

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (/console\.log|logger\.(info|debug)|print\(/i.test(line) && /(authorization|token|secret|password|cookie|set-cookie)/i.test(line)) {
        pushUnique(findings, createFinding({
          title: "Sensitive value may be written to logs",
          asset: relativePath,
          category: "Logging and Monitoring",
          cwe: "CWE-532: Insertion of Sensitive Information into Log File",
          cvss_v4: severityFromScore(6.1, "Medium"),
          confidence: "Medium",
          location: `${relativePath}:${index + 1}`,
          control: "Sensitive logging review",
          evidence: `Potential sensitive logging pattern at ${relativePath}:${index + 1}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${index + 1}.\n2. Determine whether secrets, session tokens, or auth headers are logged in any environment.`,
          business_impact: "Sensitive logs can leak credentials or regulated data to operators, vendors, or attackers who gain log access.",
          remediation: "Redact or omit sensitive values before logging and review existing log retention for exposed data.",
          fix_effort: "S"
        }));
      }
    }
  }

  if (manifests.length === 0) {
    pushUnique(findings, createFinding({
      title: "No common dependency manifest discovered",
      asset: ".",
      category: "Assessment Coverage",
      cwe: "CWE-1104: Use of Unmaintained Third Party Components",
      cvss_v4: severityFromScore(0.0, "Info"),
      confidence: "Low",
      location: ".",
      control: "Dependency inventory coverage",
      evidence: "No common package manifest or lockfile was found during repository traversal.",
      reproduction_steps: "1. Confirm whether the scanned path is the actual project root.\n2. If manifests live elsewhere, rerun the scan with a narrower target path.",
      business_impact: "Missing inventory reduces confidence in dependency risk review rather than proving no dependency risk exists.",
      remediation: "Scan the actual project root or provide the relevant manifest and lockfile paths.",
      fix_effort: "S"
    }));
  }

  return findings;
}

const files = walk(target);
const findings = scanFiles(files);

const envelope = {
  metadata: {
    target,
    target_surface: surface,
    standard,
    timestamp: new Date().toISOString(),
    generated_by: "security-testing-skill/scripts/audit-scan.js",
    notes: "Read-only heuristic scan. Findings should be validated by an analyst before being treated as confirmed vulnerabilities."
  },
  findings
};

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, JSON.stringify(envelope, null, 2));

console.log(`[+] Scanned ${files.length} files under ${target}`);
console.log(`[+] Wrote ${findings.length} findings to ${output}`);
