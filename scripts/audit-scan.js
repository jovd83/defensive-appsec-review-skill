#!/usr/bin/env node

/**
 * Read-only repository security scanner.
 *
 * Usage:
 *   node scripts/audit-scan.js --target . --type repo --standard nist-ssdf --output sandbox/raw-findings.json
 */

const fs = require("fs");
const path = require("path");
const { normalizeExternalResults } = require("./normalize-external-results.js");

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
  ".turbo",
  "__pycache__"
]);

const MANIFEST_FILENAMES = new Set([
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
]);

const STANDARD_ALIASES = {
  "owasp-top10": "owasp-top-10-2021",
  "owasp-top-10": "owasp-top-10-2021",
  "owasp-top-10-2021": "owasp-top-10-2021",
  "owasp-api-top10": "owasp-api-top-10-2023",
  "owasp-api-top-10": "owasp-api-top-10-2023",
  "owasp-api-top-10-2023": "owasp-api-top-10-2023",
  "owasp-asvs": "owasp-asvs-5.0",
  "asvs": "owasp-asvs-5.0",
  "owasp-wstg": "owasp-wstg",
  "wstg": "owasp-wstg",
  "owasp-masvs": "owasp-masvs",
  "masvs": "owasp-masvs",
  "nist-ssdf": "nist-ssdf",
  "ssdf": "nist-ssdf",
  "samm": "owasp-samm"
};

const COVERAGE_PROFILES = {
  web: {
    coverage_areas: [
      "input validation and injection sinks",
      "authentication and session-related code paths",
      "transport and cookie configuration",
      "client-side token handling and unsafe HTML rendering",
      "file access, redirects, and outbound request patterns"
    ],
    blind_spots: [
      "runtime access control behavior and multi-step business logic abuse",
      "deployed header posture and reverse-proxy behavior",
      "real authentication flow weaknesses that require live verification"
    ]
  },
  api: {
    coverage_areas: [
      "authorization-adjacent object access patterns",
      "mass assignment and unsafe object updates",
      "injection and deserialization sinks",
      "server-side request forgery and open redirect patterns",
      "token handling, transport bypasses, and sensitive logging"
    ],
    blind_spots: [
      "confirmed BOLA or BFLA exploitability without runtime requests",
      "rate limiting and abuse protections enforced outside source code",
      "environment-specific gateway, WAF, or identity-provider controls"
    ]
  },
  mobile: {
    coverage_areas: [
      "hardcoded secrets and endpoints",
      "transport validation bypasses",
      "local storage of sensitive data",
      "debug and build-time leakage"
    ],
    blind_spots: [
      "runtime device hardening posture",
      "platform keystore behavior",
      "mobile backend authorization behavior"
    ]
  },
  repo: {
    coverage_areas: [
      "secrets exposure and dependency inventory",
      "dangerous code patterns and deserialization sinks",
      "CI/CD trust boundaries and permissions",
      "container, Kubernetes, and IaC misconfiguration hints"
    ],
    blind_spots: [
      "live dependency vulnerability enrichment",
      "runtime network reachability and exploitability",
      "authorization flows that require executing the application"
    ]
  },
  iac: {
    coverage_areas: [
      "public network exposure",
      "privilege and host access signals",
      "deployment-time secret handling",
      "cloud and cluster configuration anti-patterns"
    ],
    blind_spots: [
      "live cloud IAM state",
      "drift between deployed infra and repository definitions",
      "runtime guardrails enforced outside code"
    ]
  },
  pipeline: {
    coverage_areas: [
      "workflow permissions",
      "unsafe trigger usage",
      "secret handling in automation",
      "untrusted code execution paths"
    ],
    blind_spots: [
      "organization-level repository settings",
      "external secret store policies",
      "runtime runner isolation guarantees"
    ]
  },
  mixed: {
    coverage_areas: [
      "multi-surface static review across code, config, CI/CD, and infra artifacts"
    ],
    blind_spots: [
      "surface-specific runtime verification still required for full confidence"
    ]
  }
};

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
const surface = String(options.type || "repo").toLowerCase();
const standard = normalizeStandard(options.standard || "nist-ssdf");
const depth = normalizeDepth(options.depth || "quick");
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

function normalizeStandard(value) {
  const normalized = String(value || "nist-ssdf").trim().toLowerCase();
  return STANDARD_ALIASES[normalized] || normalized;
}

function normalizeDepth(value) {
  const normalized = String(value || "quick").trim().toLowerCase();
  return normalized === "deep" ? "deep" : "quick";
}

function mergeUnique(...values) {
  return [...new Set(values.flat().filter(Boolean))];
}

function buildCoverageProfile(targetSurface, selectedStandard) {
  const profile = COVERAGE_PROFILES[targetSurface] || COVERAGE_PROFILES.repo;
  const coverageAreas = [...profile.coverage_areas];
  const blindSpots = [...profile.blind_spots];

  if (selectedStandard.startsWith("owasp-api-top-10")) {
    coverageAreas.push("OWASP API Top 10-style review themes such as BOLA, mass assignment, and unsafe API consumption heuristics");
    blindSpots.push("confirmed object-level authorization bypasses still require runtime verification");
  } else if (selectedStandard.startsWith("owasp-top-10")) {
    coverageAreas.push("OWASP Top 10 2021-aligned classes such as injection, broken access control hints, SSRF, and security misconfiguration");
    blindSpots.push("full browser-session and exploit-chain validation remains outside deterministic repo scanning");
  } else if (selectedStandard.startsWith("owasp-asvs")) {
    coverageAreas.push("ASVS-style control review for authentication, validation, and configuration evidence in source");
  }

  return {
    standard_family: selectedStandard,
    coverage_areas: mergeUnique(coverageAreas),
    blind_spots: mergeUnique(blindSpots)
  };
}

function walk(dir, telemetry, files = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (DEFAULT_EXCLUDED_DIRS.has(entry.name)) {
        telemetry.directories_skipped += 1;
        addSample(telemetry.skipped_directories, (path.relative(target, fullPath) || entry.name).split(path.sep).join("/"));
        continue;
      }
      walk(fullPath, telemetry, files);
      continue;
    }

    telemetry.files_discovered += 1;
    files.push(fullPath);
  }

  return files;
}

function toRelative(filePath) {
  return (path.relative(target, filePath) || ".").split(path.sep).join("/");
}

function addSample(list, value, limit = 5) {
  if (!value || list.includes(value) || list.length >= limit) {
    return;
  }
  list.push(value);
}

function createScanTelemetry() {
  return {
    scan_started_at: new Date().toISOString(),
    scan_depth: depth,
    files_discovered: 0,
    files_scanned: 0,
    bytes_scanned: 0,
    heuristic_checks_run: 0,
    manifests_detected: 0,
    directories_skipped: 0,
    skipped_directories: [],
    skipped_files: {
      support_material: 0,
      oversized: 0,
      unreadable: 0
    },
    skipped_file_examples: {
      support_material: [],
      oversized: [],
      unreadable: []
    },
    external_inputs_provided: [],
    autodiscovered_external_inputs: [],
    external_sources_loaded: [],
    external_sources_failed: [],
    external_findings_imported: 0,
    findings_by_rule: {},
    findings_by_category: {}
  };
}

function parseLocation(location) {
  const match = String(location || "").match(/^(.*):(\d+)$/);
  if (!match) {
    return {
      asset: String(location || "").trim(),
      lineNumber: null
    };
  }

  return {
    asset: match[1],
    lineNumber: Number(match[2])
  };
}

function extractSnippet(contents, lineNumber, radius = 1) {
  const numericLine = Number(lineNumber);
  if (!Number.isFinite(numericLine) || numericLine < 1) {
    return "";
  }

  const lines = String(contents || "").split(/\r?\n/);
  if (!lines.length || numericLine > lines.length) {
    return "";
  }

  const start = Math.max(0, numericLine - radius - 1);
  const end = Math.min(lines.length, numericLine + radius);
  const width = String(end).length;

  return lines
    .slice(start, end)
    .map((line, index) => `${String(start + index + 1).padStart(width, " ")} | ${line}`)
    .join("\n")
    .trim();
}

function detectNearestClassName(contents, lineNumber) {
  const numericLine = Number(lineNumber);
  if (!Number.isFinite(numericLine) || numericLine < 1) {
    return "";
  }

  const lines = String(contents || "").split(/\r?\n/);
  const patterns = [
    /^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/,
    /^\s*(?:public|private|protected|internal)?\s*(?:abstract\s+|final\s+|sealed\s+|static\s+|partial\s+)*class\s+([A-Za-z_$][\w$]*)/,
    /^\s*(?:public|private|protected|internal)?\s*(?:abstract\s+|sealed\s+)?interface\s+([A-Za-z_$][\w$]*)/,
    /^\s*(?:public|private|protected|internal)?\s*enum\s+([A-Za-z_$][\w$]*)/,
    /^\s*class\s+([A-Za-z_$][\w$]*)/
  ];

  for (let index = Math.min(numericLine - 1, lines.length - 1); index >= Math.max(0, numericLine - 80); index -= 1) {
    for (const pattern of patterns) {
      const match = lines[index].match(pattern);
      if (match) {
        return match[1];
      }
    }
  }

  return "";
}

function enrichFindingsWithCodeContext(findings, fileContentsByAsset) {
  return findings.map((finding) => {
    const parsed = parseLocation(finding.location || finding.asset || "");
    const asset = finding.asset || parsed.asset || ".";
    const contents = fileContentsByAsset.get(asset);
    const lineNumber = Number.isFinite(Number(finding.line_number))
      ? Number(finding.line_number)
      : parsed.lineNumber;

    if (!contents) {
      return {
        ...finding,
        line_number: lineNumber || undefined
      };
    }

    const codeSnippet = finding.code_snippet || extractSnippet(contents, lineNumber);
    const className = finding.class_name || detectNearestClassName(contents, lineNumber);

    return {
      ...finding,
      line_number: lineNumber || undefined,
      class_name: className || undefined,
      code_snippet: codeSnippet || undefined
    };
  });
}

function recordSkippedFile(telemetry, kind, relativePath) {
  telemetry.skipped_files[kind] = (telemetry.skipped_files[kind] || 0) + 1;
  addSample(telemetry.skipped_file_examples[kind], relativePath);
}

function summarizeFindings(findings) {
  const findingsByRule = {};
  const findingsByCategory = {};

  for (const finding of findings) {
    findingsByRule[finding.title] = (findingsByRule[finding.title] || 0) + 1;
    findingsByCategory[finding.category] = (findingsByCategory[finding.category] || 0) + 1;
  }

  return { findingsByRule, findingsByCategory };
}

function parseDeepInputSpecs(value) {
  return String(value || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const separatorIndex = entry.indexOf("=");
      if (separatorIndex <= 0) {
        return null;
      }
      const tool = entry.slice(0, separatorIndex).trim().toLowerCase();
      const inputPath = entry.slice(separatorIndex + 1).trim();
      if (!tool || !inputPath) {
        return null;
      }
      return {
        tool,
        inputPath: path.resolve(process.cwd(), inputPath),
        discovered: false
      };
    })
    .filter(Boolean);
}

function discoverDeepInputs() {
  const candidateDirs = [...new Set([
    target,
    process.cwd(),
    path.join(process.cwd(), "sandbox")
  ])];
  const candidates = [
    { tool: "sarif", filename: "semgrep.sarif" },
    { tool: "sarif", filename: "codeql.sarif" },
    { tool: "sarif", filename: "results.sarif" },
    { tool: "gitleaks", filename: "gitleaks.json" },
    { tool: "trivy", filename: "trivy.json" },
    { tool: "osv-scanner", filename: "osv.json" },
    { tool: "scorecard", filename: "scorecard.json" },
    { tool: "dependency-check", filename: "dependency-check.json" }
  ];
  const discovered = [];

  for (const dir of candidateDirs) {
    for (const candidate of candidates) {
      const inputPath = path.join(dir, candidate.filename);
      if (fs.existsSync(inputPath) && fs.statSync(inputPath).isFile()) {
        discovered.push({
          tool: candidate.tool,
          inputPath,
          discovered: true
        });
      }
    }
  }

  const deduped = [];
  const seen = new Set();
  for (const item of discovered) {
    const key = `${item.tool}|${item.inputPath.toLowerCase()}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(item);
  }
  return deduped;
}

function loadDeepFindings(telemetry) {
  if (depth !== "deep") {
    return [];
  }

  const explicitInputs = parseDeepInputSpecs(options["deep-inputs"]);
  const discoveredInputs = discoverDeepInputs();
  const inputs = [];
  const seen = new Set();

  for (const item of [...explicitInputs, ...discoveredInputs]) {
    const key = `${item.tool}|${item.inputPath.toLowerCase()}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    inputs.push(item);
  }

  telemetry.external_inputs_provided = explicitInputs.map((item) => `${item.tool}=${path.relative(process.cwd(), item.inputPath)}`);
  telemetry.autodiscovered_external_inputs = discoveredInputs.map((item) => `${item.tool}=${path.relative(process.cwd(), item.inputPath)}`);

  const envelopes = [];

  for (const input of inputs) {
    try {
      const raw = JSON.parse(fs.readFileSync(input.inputPath, "utf8"));
      const envelope = normalizeExternalResults({
        tool: input.tool,
        document: raw,
        target,
        surface,
        standard
      });
      telemetry.external_sources_loaded.push({
        tool: input.tool,
        input: path.relative(process.cwd(), input.inputPath),
        findings: envelope.findings.length,
        discovered: input.discovered
      });
      telemetry.external_findings_imported += envelope.findings.length;
      envelopes.push(envelope);
    } catch (error) {
      telemetry.external_sources_failed.push({
        tool: input.tool,
        input: path.relative(process.cwd(), input.inputPath),
        error: error.message
      });
    }
  }

  return envelopes;
}

function safeRead(filePath, relativePath, telemetry) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxFileSizeBytes) {
      recordSkippedFile(telemetry, "oversized", relativePath);
      return null;
    }
    const contents = fs.readFileSync(filePath, "utf8");
    telemetry.files_scanned += 1;
    telemetry.bytes_scanned += stat.size;
    return contents;
  } catch {
    recordSkippedFile(telemetry, "unreadable", relativePath);
    return null;
  }
}

function severityFromScore(score, label) {
  return `${score.toFixed(1)} (${label})`;
}

function inferDefaultOwaspMappings(overrides) {
  const title = String(overrides.title || "");
  const category = String(overrides.category || "");
  const control = String(overrides.control || "");

  if (/^No common dependency manifest discovered$/i.test(title)) {
    return [];
  }

  if (/^Potential hardcoded credential detected\b/i.test(title)) {
    return [
      "OWASP Top 10 2021 A07 Identification and Authentication Failures",
      "OWASP ASVS V8 Data Protection"
    ];
  }

  if (/^Cookie handling hint without HttpOnly flag$/i.test(title)) {
    return [
      "OWASP Top 10 2021 A07 Identification and Authentication Failures",
      "OWASP ASVS V3 Session Management"
    ];
  }

  if (/^Non-local plaintext HTTP endpoint referenced$/i.test(title)) {
    return [
      "OWASP Top 10 2021 A02 Cryptographic Failures"
    ];
  }

  if (/^Broad GitHub Actions token permissions$/i.test(title)) {
    return [
      "OWASP Top 10 2021 A05 Security Misconfiguration"
    ];
  }

  if (/^Dynamic code execution via eval detected$/i.test(title)) {
    return [
      "OWASP Top 10 2021 A03 Injection",
      "OWASP ASVS V5 Validation, Sanitization and Encoding"
    ];
  }

  if (/^Sensitive value may be written to logs$/i.test(title)) {
    return [
      "OWASP Top 10 2021 A09 Security Logging and Monitoring Failures",
      "OWASP ASVS V8 Data Protection"
    ];
  }

  if (/debug mode enabled$/i.test(title) || /secure configuration review/i.test(control) || /Configuration/i.test(category)) {
    return [
      "OWASP Top 10 2021 A05 Security Misconfiguration"
    ];
  }

  return [];
}

function inferDefaultAsvsMappings(overrides) {
  const title = String(overrides.title || "");
  const category = String(overrides.category || "");
  const control = String(overrides.control || "");
  const owaspEntries = Array.isArray(overrides.owasp) ? overrides.owasp : [];
  const fromOwasp = owaspEntries.filter((entry) => /OWASP ASVS/i.test(entry));
  if (fromOwasp.length) {
    return [...new Set(fromOwasp)];
  }

  if (/Configuration|Container Security|Infrastructure Security|CI\/CD Security/i.test(category) || /configuration|hardening/i.test(control)) {
    return ["OWASP ASVS V14 Configuration"];
  }

  if (/Credential Management|Secrets Management/i.test(category) || /credential|secret/i.test(title)) {
    return ["OWASP ASVS V8 Data Protection"];
  }

  if (/Authentication/i.test(category) || /jwt|auth/i.test(title)) {
    return ["OWASP ASVS V2 Authentication"];
  }

  if (/Session Management/i.test(category) || /cookie|localStorage|token stored/i.test(title)) {
    return ["OWASP ASVS V3 Session Management"];
  }

  if (/Authorization|Redirect Handling|File Access Control/i.test(category)) {
    return ["OWASP ASVS V4 Access Control"];
  }

  if (/Injection|Unsafe Deserialization|Command Execution Risk|Code Injection Risk|Input Validation/i.test(category)) {
    return ["OWASP ASVS V5 Validation, Sanitization and Encoding"];
  }

  if (/Cryptography|Transport Security/i.test(category) || /cryptographic|TLS/i.test(title)) {
    return ["OWASP ASVS V6 Stored Cryptography"];
  }

  return [];
}

function inferDefaultNistMappings(overrides) {
  const title = String(overrides.title || "");
  const category = String(overrides.category || "");
  const control = String(overrides.control || "");

  if (/^No common dependency manifest discovered$/i.test(title)) {
    return [
      "NIST SP 800-218 SSDF PW.4 Code and dependency review",
      "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
    ];
  }

  if (/Configuration|Transport Security|Container Security|Infrastructure Security|CI\/CD Security/i.test(category) || /configuration|hardening|least privilege/i.test(control)) {
    return [
      "NIST SP 800-218 SSDF PW.6 Secure software configuration and deployment hardening",
      "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
    ];
  }

  if (/credential|secret|token/i.test(title) || /Credential Management|Secrets Management/i.test(category)) {
    return [
      "NIST SP 800-218 SSDF PS.1 Protect code, secrets, and related artifacts",
      "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
    ];
  }

  if (/Injection|Deserialization|Command Execution Risk|Authorization|Authentication|Session Management|File Access Control|Redirect Handling|Server-Side Request Forgery|Logging and Monitoring/i.test(category)) {
    return [
      "NIST SP 800-218 SSDF PW.4 Code review and static analysis",
      "NIST SP 800-218 SSDF PW.5 Security verification and testing"
    ];
  }

  return [
    "NIST SP 800-218 SSDF PW.4 Code review and static analysis",
    "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
  ];
}

function inferDefaultCisMappings(overrides) {
  const title = String(overrides.title || "");
  const category = String(overrides.category || "");

  if (/Configuration|Transport Security|Container Security|Infrastructure Security|CI\/CD Security/i.test(category) || /debug mode enabled|Broad GitHub Actions token permissions/i.test(title)) {
    return ["CIS Controls v8 Control 4 Secure Configuration of Enterprise Assets and Software"];
  }

  if (/Credential Management|Secrets Management/i.test(category) || /credential|secret|token/i.test(title)) {
    return ["CIS Controls v8 Control 3 Data Protection"];
  }

  if (/Authentication|Authorization|Session Management/i.test(category)) {
    return ["CIS Controls v8 Control 6 Access Control Management"];
  }

  if (/Logging and Monitoring/i.test(category)) {
    return ["CIS Controls v8 Control 8 Audit Log Management"];
  }

  return [];
}

function inferDefaultScvsMappings(overrides) {
  const title = String(overrides.title || "");
  const category = String(overrides.category || "");

  if (/Dependency Security|Assessment Coverage/i.test(category) || /dependency manifest/i.test(title)) {
    return [
      "OWASP SCVS V1 Inventory",
      "OWASP SCVS V5 Component Analysis"
    ];
  }

  if (/CI\/CD Security|Supply Chain Security/i.test(category)) {
    return [
      "OWASP SCVS V3 Build Environment",
      "OWASP SCVS V6 Pedigree and Provenance"
    ];
  }

  return [];
}

function inferDefaultSlsaMappings(overrides) {
  const title = String(overrides.title || "");
  const category = String(overrides.category || "");

  if (/CI\/CD Security|Supply Chain Security/i.test(category) || /workflow|provenance|release/i.test(title)) {
    return [
      "SLSA Build track provenance integrity",
      "SLSA Source track change and branch integrity"
    ];
  }

  if (/Dependency Security|Assessment Coverage/i.test(category) || /dependency manifest/i.test(title)) {
    return [
      "SLSA dependency and provenance verification support"
    ];
  }

  return [];
}

function normalizeMappingProvenance(value, fallback = "not-recorded") {
  return ["supplied", "inferred", "not-recorded"].includes(value) ? value : fallback;
}

function resolveFrameworkEntries(overrides, key, inferFn = () => []) {
  const explicitEntries = Array.isArray(overrides[key]) ? overrides[key] : null;
  const entries = explicitEntries || inferFn(overrides);
  const autoProvenance = explicitEntries
    ? (explicitEntries.length ? "supplied" : "not-recorded")
    : (entries.length ? "inferred" : "not-recorded");

  return {
    entries,
    provenance: normalizeMappingProvenance(overrides.mapping_provenance?.[key], autoProvenance)
  };
}

function createFinding(overrides) {
  const asvs = resolveFrameworkEntries(overrides, "asvs", inferDefaultAsvsMappings);
  const nist = resolveFrameworkEntries(overrides, "nist", inferDefaultNistMappings);
  const cis = resolveFrameworkEntries(overrides, "cis", inferDefaultCisMappings);
  const scvs = resolveFrameworkEntries(overrides, "scvs", inferDefaultScvsMappings);
  const slsa = resolveFrameworkEntries(overrides, "slsa", inferDefaultSlsaMappings);
  const owasp = resolveFrameworkEntries(overrides, "owasp", inferDefaultOwaspMappings);
  const primaryProvenance = normalizeMappingProvenance(
    overrides.mapping_provenance?.primary,
    overrides.control ? "supplied" : "not-recorded"
  );

  return {
    title: overrides.title,
    asset: overrides.asset,
    location: overrides.location,
    line_number: overrides.line_number,
    class_name: overrides.class_name,
    code_snippet: overrides.code_snippet,
    category: overrides.category,
    cwe: overrides.cwe,
    cvss_v4: overrides.cvss_v4,
    confidence: overrides.confidence || "Medium",
    framework_mapping: {
      standard,
      control: overrides.control,
      provenance: {
        primary: primaryProvenance,
        asvs: asvs.provenance,
        nist: nist.provenance,
        cis: cis.provenance,
        scvs: scvs.provenance,
        slsa: slsa.provenance,
        owasp: owasp.provenance
      },
      asvs: asvs.entries,
      nist: nist.entries,
      cis: cis.entries,
      scvs: scvs.entries,
      slsa: slsa.entries,
      owasp: owasp.entries,
      references: overrides.framework_references || []
    },
    verification_tier: overrides.verification_tier || "heuristic-static",
    source_tool: overrides.source_tool || "native-heuristic-scan",
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

function createComponentPosture(overrides = {}) {
  const name = String(overrides.name || "").trim();
  if (!name) {
    return null;
  }

  return {
    name,
    version: String(overrides.version || "").trim(),
    kind: overrides.kind || "library",
    ecosystem: String(overrides.ecosystem || "").trim(),
    manifest_path: String(overrides.manifest_path || "").trim(),
    origin: String(overrides.origin || "").trim(),
    review_status: overrides.review_status || "unknown",
    security_posture: overrides.security_posture || "unknown",
    maintenance_posture: overrides.maintenance_posture || "unknown",
    provenance_posture: overrides.provenance_posture || "unknown",
    confidence: overrides.confidence || "Low",
    evidence_mode: overrides.evidence_mode || "offline-only",
    checked_at: overrides.checked_at || new Date().toISOString(),
    evidence_sources: [...new Set((overrides.evidence_sources || []).filter(Boolean))],
    notes: String(overrides.notes || "").trim()
  };
}

function addComponentPosture(list, entry) {
  const normalized = createComponentPosture(entry);
  if (!normalized) {
    return;
  }

  const key = [
    normalized.kind,
    normalized.ecosystem,
    normalized.name.toLowerCase(),
    normalized.version,
    normalized.manifest_path
  ].join("|");

  if (!list.some((item) => [
    item.kind,
    item.ecosystem,
    String(item.name || "").toLowerCase(),
    item.version,
    item.manifest_path
  ].join("|") === key)) {
    list.push(normalized);
  }
}

function createUnknownDependencyPosture({ name, version, ecosystem, manifestPath, origin, checkedAt }) {
  return createComponentPosture({
    name,
    version,
    kind: "library",
    ecosystem,
    manifest_path: manifestPath,
    origin,
    review_status: "unknown",
    security_posture: "unknown",
    maintenance_posture: "unknown",
    provenance_posture: "unknown",
    confidence: "Low",
    evidence_mode: "offline-only",
    checked_at: checkedAt,
    evidence_sources: [manifestPath],
    notes: `Observed in ${manifestPath}${origin ? ` under ${origin}` : ""}. No live package-intel or advisory verdict was supplied in this run. Unknown is not treated as good or bad by default.`
  });
}

function collectPackageJsonComponents(contents, relativePath, checkedAt) {
  try {
    const document = JSON.parse(contents);
    const groups = [
      ["dependencies", "dependencies"],
      ["devDependencies", "devDependencies"],
      ["optionalDependencies", "optionalDependencies"],
      ["peerDependencies", "peerDependencies"]
    ];

    return groups.flatMap(([field, origin]) =>
      Object.entries(document[field] || {})
        .sort((left, right) => left[0].localeCompare(right[0]))
        .map(([name, version]) => createUnknownDependencyPosture({
          name,
          version,
          ecosystem: "npm",
          manifestPath: relativePath,
          origin,
          checkedAt
        }))
        .filter(Boolean)
    );
  } catch {
    return [];
  }
}

function collectRequirementsComponents(contents, relativePath, checkedAt) {
  return contents
    .split(/\r?\n/)
    .map((line) => line.replace(/\s+#.*$/, "").trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("--") && !line.startsWith("-e "))
    .map((line) => {
      const match = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([<>=!~]{1,2}\s*[^;,\s]+)?/);
      if (!match) {
        return null;
      }

      return createUnknownDependencyPosture({
        name: match[1],
        version: String(match[2] || "").replace(/\s+/g, ""),
        ecosystem: "pypi",
        manifestPath: relativePath,
        origin: "requirements",
        checkedAt
      });
    })
    .filter(Boolean);
}

function collectGoModComponents(contents, relativePath, checkedAt) {
  const components = [];
  const blockMatch = contents.match(/require\s*\(([\s\S]*?)\)/m);
  const lines = blockMatch ? blockMatch[1].split(/\r?\n/) : contents.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.replace(/\/\/.*$/, "").trim();
    if (!line || line === "require" || line === ")" || line === "(") {
      continue;
    }

    const inlineMatch = line.match(/^(?:require\s+)?([^\s]+)\s+([^\s]+)$/);
    if (!inlineMatch) {
      continue;
    }

    components.push(createUnknownDependencyPosture({
      name: inlineMatch[1],
      version: inlineMatch[2],
      ecosystem: "go",
      manifestPath: relativePath,
      origin: "require",
      checkedAt
    }));
  }

  return components.filter(Boolean);
}

function collectPomComponents(contents, relativePath, checkedAt) {
  const components = [];
  const dependencyPattern = /<dependency>([\s\S]*?)<\/dependency>/g;
  let match = dependencyPattern.exec(contents);
  while (match) {
    const block = match[1];
    const groupId = (block.match(/<groupId>([^<]+)<\/groupId>/) || [])[1] || "";
    const artifactId = (block.match(/<artifactId>([^<]+)<\/artifactId>/) || [])[1] || "";
    const version = (block.match(/<version>([^<]+)<\/version>/) || [])[1] || "";
    const name = [groupId, artifactId].filter(Boolean).join(":") || artifactId;

    if (name) {
      components.push(createUnknownDependencyPosture({
        name,
        version,
        ecosystem: "maven",
        manifestPath: relativePath,
        origin: "dependencies",
        checkedAt
      }));
    }

    match = dependencyPattern.exec(contents);
  }

  return components;
}

function collectObservedComponents(relativePath, base, contents, checkedAt) {
  if (base === "package.json") {
    return collectPackageJsonComponents(contents, relativePath, checkedAt);
  }
  if (base === "requirements.txt") {
    return collectRequirementsComponents(contents, relativePath, checkedAt);
  }
  if (base === "go.mod") {
    return collectGoModComponents(contents, relativePath, checkedAt);
  }
  if (base === "pom.xml") {
    return collectPomComponents(contents, relativePath, checkedAt);
  }
  return [];
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

function isSupportMaterialPath(relativePath) {
  return /^(fixtures|examples|references|evals|sandbox)\//i.test(relativePath) ||
    /(^|\/)repository-reports(\/|$)/i.test(relativePath) ||
    /(^|\/)__pycache__(\/|$)/i.test(relativePath) ||
    /(^|\/)(report\.html|report\.md|report\.data\.json|report\.sources\.json|official-pricing\.auto\.json)$/i.test(relativePath) ||
    /^(README|CHANGELOG|CONTRIBUTING)\.md$/i.test(relativePath);
}

function isMarkdownDocumentation(relativePath) {
  return /\.md$/i.test(relativePath);
}

function isScannerPatternDefinitionLine(line) {
  return /\b(locateLine|locateAnyLine|findLineIndex)\s*\(/.test(line) ||
    /^\s*(title|evidence|reproduction_steps|business_impact|remediation|control|category|cwe)\s*:/.test(line) ||
    /\/\\b\(/.test(line) ||
    /\/\.\*/.test(line);
}

function locateRelevantLine(contents, pattern, options = {}) {
  const { skipDocs = false, skipPatternDefinitions = false } = options;
  const lines = contents.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!pattern.test(line)) {
      continue;
    }
    if (skipDocs && /^\s*[-*]\s|^\s*#/.test(line)) {
      continue;
    }
    if (skipPatternDefinitions && isScannerPatternDefinitionLine(line)) {
      continue;
    }
    return index + 1;
  }
  return null;
}

function locateAnyLine(contents, patterns, options = {}) {
  for (const pattern of patterns) {
    const lineNumber = locateRelevantLine(contents, pattern, options);
    if (lineNumber) {
      return lineNumber;
    }
  }
  return null;
}

function findLineIndex(lines, pattern) {
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.test(lines[index])) {
      return index;
    }
  }
  return -1;
}

function hasNearbyMatch(lines, anchorIndex, pattern, radius = 12) {
  const start = Math.max(0, anchorIndex - radius);
  const end = Math.min(lines.length, anchorIndex + radius + 1);
  for (let index = start; index < end; index += 1) {
    if (pattern.test(lines[index])) {
      return true;
    }
  }
  return false;
}

function estimateHeuristicChecksForFile(relativePath, base, exampleLike) {
  let count = 9;

  if (relativePath.startsWith(".github/workflows/")) {
    count += 2;
  }

  if (base === "dockerfile" || base.endsWith(".dockerfile")) {
    count += 1;
  }

  if (base.endsWith(".tf")) {
    count += 1;
  }

  if (!exampleLike) {
    count += 19;
  }

  if (base === "deployment.yaml" || base === "deployment.yml" || base.endsWith(".k8s.yaml") || base.endsWith(".k8s.yml")) {
    count += 2;
  }

  return count;
}

function scanFiles(files, telemetry) {
  const findings = [];
  const manifests = [];
  const componentPosture = [];
  const fileContentsByAsset = new Map();
  const observedAt = new Date().toISOString();

  for (const filePath of files) {
    const relativePath = toRelative(filePath);
    const base = path.basename(filePath).toLowerCase();
    const supportMaterialPath = isSupportMaterialPath(relativePath);
    const markdownDocumentation = isMarkdownDocumentation(relativePath);

    if (MANIFEST_FILENAMES.has(base)) {
      manifests.push(relativePath);
    }

    if (supportMaterialPath) {
      recordSkippedFile(telemetry, "support_material", relativePath);
      continue;
    }

    const contents = safeRead(filePath, relativePath, telemetry);
    if (!contents) {
      continue;
    }
    fileContentsByAsset.set(relativePath, contents);

    const lines = contents.split(/\r?\n/);
    const exampleLike = likelyExampleOrFixture(relativePath);
    telemetry.heuristic_checks_run += estimateHeuristicChecksForFile(relativePath, base, exampleLike);

    if (MANIFEST_FILENAMES.has(base) && !exampleLike) {
      for (const item of collectObservedComponents(relativePath, base, contents, observedAt)) {
        addComponentPosture(componentPosture, item);
      }
    }

    if (base === ".env" || base.endsWith(".env") || relativePath.includes(".env")) {
      pushUnique(findings, createFinding({
        title: "Environment file stored in repository path",
        asset: relativePath,
        category: "Secrets Management",
        cwe: "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
        cvss_v4: severityFromScore(6.3, "Medium"),
        confidence: "High",
        location: `${relativePath}:1`,
        line_number: 1,
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
          location: (() => {
            const lineNumber = locateLine(contents, new RegExp(pattern.source, pattern.flags.replace(/g/g, "")));
            return lineNumber ? `${relativePath}:${lineNumber}` : relativePath;
          })(),
          line_number: locateLine(contents, new RegExp(pattern.source, pattern.flags.replace(/g/g, ""))) || undefined,
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
          fix_effort: "S",
          owasp: [
            "OWASP Top 10 2021 A05 Security Misconfiguration",
            "OWASP ASVS V14 Configuration"
          ]
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
          location: (() => {
            const lineNumber = locateLine(contents, /permissions:\s*\n\s*contents:\s*write/i) || locateLine(contents, /permissions:\s*write-all/i);
            return lineNumber ? `${relativePath}:${lineNumber}` : relativePath;
          })(),
          line_number: locateLine(contents, /permissions:\s*\n\s*contents:\s*write/i) || locateLine(contents, /permissions:\s*write-all/i) || undefined,
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
          location: (() => {
            const lineNumber = locateLine(contents, /pull_request_target/i) || locateLine(contents, /checkout/i);
            return lineNumber ? `${relativePath}:${lineNumber}` : relativePath;
          })(),
          line_number: locateLine(contents, /pull_request_target/i) || locateLine(contents, /checkout/i) || undefined,
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
      const evalLine = locateRelevantLine(contents, /\beval\s*\(/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

      const htmlSinkLine = locateRelevantLine(contents, /\b(innerHTML|dangerouslySetInnerHTML)\b/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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
          fix_effort: "S",
          owasp: [
            "OWASP Top 10 2021 A03 Injection",
            "OWASP ASVS V5 Validation, Sanitization and Encoding"
          ]
        }));
      }

      const subprocessLine = locateRelevantLine(contents, /\b(exec|spawn|subprocess\.run|subprocess\.Popen)\b/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

      const jwtLine = locateRelevantLine(contents, /jwt\.sign|jwt\.verify|jsonwebtoken/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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
          fix_effort: "M",
          owasp: [
            "OWASP Top 10 2021 A07 Identification and Authentication Failures",
            "OWASP ASVS V2 Authentication"
          ]
        }));
      }

      const pickleLine = locateRelevantLine(contents, /\b(pickle\.loads|pickle\.load)\b/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

      const yamlLine = locateRelevantLine(contents, /\byaml\.load\s*\(/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

      const runtimeExecLine = locateRelevantLine(contents, /\bRuntime\.getRuntime\(\)\.exec\s*\(/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

      const sqlConcatLine = locateAnyLine(contents, [
        /["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*\+/i,
        /`[^`\n]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^`\n]*\$\{/i
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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
          fix_effort: "M",
          owasp: [
            "OWASP Top 10 2021 A03 Injection",
            "OWASP ASVS V5 Validation, Sanitization and Encoding"
          ]
        }));
      }

      const weakCryptoLine = locateAnyLine(contents, [
        /\bcreateHash\(\s*['"]md5['"]\s*\)/i,
        /\bcreateHash\(\s*['"]sha1['"]\s*\)/i,
        /\bhashlib\.(md5|sha1)\s*\(/i,
        /\bMessageDigest\.getInstance\(\s*["'](?:MD5|SHA-1)["']\s*\)/i
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      if (weakCryptoLine) {
        pushUnique(findings, createFinding({
          title: "Weak cryptographic hash algorithm detected",
          asset: relativePath,
          location: `${relativePath}:${weakCryptoLine}`,
          category: "Cryptography",
          cwe: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
          cvss_v4: severityFromScore(6.8, "Medium"),
          confidence: "Medium",
          control: "Approved cryptography usage",
          evidence: `Detected use of an obsolete or collision-prone hash algorithm at ${relativePath}:${weakCryptoLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${weakCryptoLine}.\n2. Confirm whether the hash is used for passwords, security decisions, signatures, or integrity checks rather than non-security legacy compatibility.`,
          business_impact: "Weak cryptography can undermine password storage, integrity validation, or trust decisions.",
          remediation: "Replace MD5 or SHA-1 with stronger approved primitives such as Argon2, bcrypt, scrypt, SHA-256, or modern signature libraries based on the use case.",
          fix_effort: "M",
          owasp: [
            "OWASP Top 10 2021 A02 Cryptographic Failures",
            "OWASP ASVS V6 Stored Cryptography"
          ]
        }));
      }

      const massAssignmentLine = locateAnyLine(contents, [
        /\b(findByIdAndUpdate|findOneAndUpdate|update|create|upsert)\s*\([^)]*\breq\.body\b/i,
        /\bObject\.assign\s*\([^,]+,\s*req\.body\s*\)/i,
        /\bnew\s+[A-Z][A-Za-z0-9_]*\s*\(\s*req\.body\s*\)/,
        /\b(request\.json|ctx\.request\.body|request\.body)\b.*\b(update|create|upsert)\b/i
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      if (massAssignmentLine) {
        pushUnique(findings, createFinding({
          title: "Client-controlled object update pattern detected",
          asset: relativePath,
          location: `${relativePath}:${massAssignmentLine}`,
          category: "API Security",
          cwe: "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
          cvss_v4: severityFromScore(7.1, "High"),
          confidence: "Medium",
          control: "Allow-list model binding",
          evidence: `Detected an object creation or update flow that appears to pass request-controlled fields directly into a persistence or model binding operation at ${relativePath}:${massAssignmentLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${massAssignmentLine}.\n2. Verify whether sensitive properties such as roles, tenant identifiers, ownership flags, or pricing fields can be set from the incoming request body.\n3. Confirm whether a DTO or explicit allow-list constrains accepted fields.`,
          business_impact: "Mass assignment can let clients set privileged or integrity-sensitive attributes that were not meant to be user controlled.",
          remediation: "Introduce explicit request DTOs or field allow-lists before object creation and update operations, and reject unknown or sensitive properties.",
          fix_effort: "M",
          owasp: [
            "OWASP API Top 10 2023 API3 Broken Object Property Level Authorization",
            "OWASP API Top 10 2019 API6 Mass Assignment"
          ]
        }));
      }

      const ssrfInputLine = locateAnyLine(contents, [
        /\breq\.(query|body)\.(url|uri|target|endpoint|dest|destination)\b/i,
        /\brequest\.args\.get\(\s*['"](url|uri|target|endpoint|dest|destination)['"]\s*\)/i,
        /\b(request\.json|ctx\.request\.body)\.(url|uri|target|endpoint)\b/i
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      const ssrfCallLine = locateAnyLine(contents, [
        /\bfetch\s*\(/,
        /\baxios\.(get|post|request)\s*\(/,
        /\baxios\s*\(/,
        /\brequests\.(get|post|request)\s*\(/,
        /\bhttpx\.(get|post|request)\s*\(/,
        /\burllib\.request\.urlopen\s*\(/,
        /\bgot\s*\(/
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      if (ssrfInputLine && ssrfCallLine) {
        pushUnique(findings, createFinding({
          title: "User-controlled outbound request target detected",
          asset: relativePath,
          location: `${relativePath}:${ssrfCallLine}`,
          category: "Server-Side Request Forgery",
          cwe: "CWE-918: Server-Side Request Forgery (SSRF)",
          cvss_v4: severityFromScore(7.4, "High"),
          confidence: "Medium",
          control: "Outbound request allow-listing",
          evidence: `Detected a network request sink near ${relativePath}:${ssrfCallLine} and user-controlled URL-like input near ${relativePath}:${ssrfInputLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${ssrfCallLine}.\n2. Trace whether user-controlled endpoint values can reach the outbound request without host allow-listing, scheme validation, or internal-address blocking.\n3. Verify behavior with analyst-controlled safe test hosts only if active testing is authorized.`,
          business_impact: "SSRF can expose internal services, cloud metadata endpoints, or privileged network paths to attacker-controlled requests.",
          remediation: "Do not fetch arbitrary client-supplied URLs. Use destination allow-lists, canonicalization, DNS/IP validation, and network egress restrictions for any necessary proxy behavior.",
          fix_effort: "M",
          owasp: [
            "OWASP Top 10 2021 A10 Server-Side Request Forgery (SSRF)",
            "OWASP API Top 10 2023 API7 Server Side Request Forgery"
          ]
        }));
      }

      const redirectInputLine = locateAnyLine(contents, [
        /\breq\.(query|body)\.(next|returnTo|redirect|redirectTo|url)\b/i,
        /\brequest\.args\.get\(\s*['"](next|returnTo|redirect|redirectTo|url)['"]\s*\)/i
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      const redirectSinkLine = locateAnyLine(contents, [
        /\bres\.redirect\s*\(/i,
        /\bredirect\s*\(/i
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      if (redirectInputLine && redirectSinkLine) {
        pushUnique(findings, createFinding({
          title: "User-controlled redirect target detected",
          asset: relativePath,
          location: `${relativePath}:${redirectSinkLine}`,
          category: "Redirect Handling",
          cwe: "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
          cvss_v4: severityFromScore(5.9, "Medium"),
          confidence: "Medium",
          control: "Redirect allow-listing",
          evidence: `Detected redirect logic near ${relativePath}:${redirectSinkLine} and request-controlled redirect input near ${relativePath}:${redirectInputLine}.`,
          reproduction_steps: `1. Inspect ${relativePath}:${redirectSinkLine}.\n2. Confirm whether external redirect targets are allowed without validation or whether only relative, allow-listed paths are accepted.`,
          business_impact: "Open redirects can support phishing, token leakage, and trust-boundary confusion in authentication or account-recovery flows.",
          remediation: "Restrict redirects to relative paths or an explicit allow-list of trusted destinations, and reject fully qualified untrusted URLs.",
          fix_effort: "S",
          owasp: [
            "OWASP Top 10 2021 A01 Broken Access Control",
            "OWASP ASVS V4 Access Control"
          ]
        }));
      }

      const fileInputLine = locateAnyLine(contents, [
        /\breq\.(query|params|body)\.(file|path|name|filename)\b/i,
        /\brequest\.args\.get\(\s*['"](file|path|name|filename)['"]\s*\)/i
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      const fileSinkLine = locateAnyLine(contents, [
        /\b(fs\.)?(readFile|readFileSync|createReadStream)\s*\(/,
        /\b(res\.)?sendFile\s*\(/,
        /\bopen\s*\(/,
        /\bFiles\.(readAllBytes|readString)\s*\(/,
        /\bPath\.(of|get)\s*\(/
      ], { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
      if (fileInputLine && fileSinkLine && !/path\.normalize|safeJoin|normalize\(|resolve\(/i.test(contents)) {
        pushUnique(findings, createFinding({
          title: "User-controlled file path reaches filesystem sink",
          asset: relativePath,
          location: `${relativePath}:${fileSinkLine}`,
          category: "File Access Control",
          cwe: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
          cvss_v4: severityFromScore(7.0, "High"),
          confidence: "Medium",
          control: "Safe file path resolution",
          evidence: `Detected request-controlled file path input near ${relativePath}:${fileInputLine} and a filesystem sink near ${relativePath}:${fileSinkLine} without an obvious normalization or allow-listing pattern.`,
          reproduction_steps: `1. Inspect ${relativePath}:${fileSinkLine}.\n2. Trace whether user-supplied path segments can escape the intended base directory.\n3. Validate only with safe test payloads and authorized environments if active verification is needed.`,
          business_impact: "Path traversal can expose sensitive files, credentials, templates, or application source outside the intended directory boundary.",
          remediation: "Resolve paths against a fixed base directory, canonicalize them, enforce allow-listed filenames, and reject traversal sequences before any filesystem access.",
          fix_effort: "M",
          owasp: [
            "OWASP Top 10 2021 A01 Broken Access Control",
            "OWASP Top 10 2021 A05 Security Misconfiguration"
          ]
        }));
      }

      const objectRouteIndex = findLineIndex(lines, /\b(app|router)\.(get|put|patch|delete)\s*\(\s*['"`][^'"`]*\/:(id|userId|accountId|projectId|orderId|invoiceId|tenantId)\b/i);
      const objectLookupIndex = findLineIndex(lines, /\b(findById|findByPk|findUnique|findOne|findFirst|getById|where:\s*\{\s*(id|userId|accountId|projectId|orderId|tenantId)\b|SELECT\b.*\bWHERE\b.*\b(id|user_id|account_id|project_id|order_id)\b)\b/i);
      const authorizationGuardPattern = /\b(authorize|authorization|authz|preAuthorize|requireAuth|requireRole|requireAdmin|ensureOwner|ownership|canAccess|acl|rbac|hasRole|req\.user|currentUser|principal)\b/i;
      if (objectRouteIndex >= 0 && objectLookupIndex >= 0 && !hasNearbyMatch(lines, objectLookupIndex, authorizationGuardPattern)) {
        pushUnique(findings, createFinding({
          title: "Direct object access route lacks obvious authorization guard",
          asset: relativePath,
          location: `${relativePath}:${objectLookupIndex + 1}`,
          category: "Authorization",
          cwe: "CWE-862: Missing Authorization",
          cvss_v4: severityFromScore(7.6, "High"),
          confidence: "Low",
          control: "Object-level authorization enforcement",
          evidence: `Detected an identifier-based route near ${relativePath}:${objectRouteIndex + 1} and object lookup logic near ${relativePath}:${objectLookupIndex + 1} without an obvious nearby authorization or ownership check.`,
          reproduction_steps: `1. Inspect the route and lookup flow in ${relativePath}.\n2. Confirm whether object ownership or tenant scoping is enforced in middleware, service code, policy layers, or database filters outside the local file.\n3. Treat this as a high-value manual verification target rather than a confirmed bypass until runtime validation is complete.`,
          business_impact: "Missing object-level authorization can let one authenticated user access or modify another user's records.",
          remediation: "Enforce object ownership or policy checks on every identifier-based resource access and ensure service-layer filters scope records to the caller's tenant or identity.",
          fix_effort: "M",
          verification_tier: "manual-required",
          owasp: [
            "OWASP Top 10 2021 A01 Broken Access Control",
            "OWASP API Top 10 2023 API1 Broken Object Level Authorization"
          ]
        }));
      }

      const flaskDebugLine = locateRelevantLine(contents, /\bapp\.run\s*\([^)]*debug\s*=\s*True/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

      const djangoDebugLine = locateRelevantLine(contents, /\bDEBUG\s*=\s*True/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

      const localStorageLine = locateRelevantLine(contents, /\blocalStorage\.setItem\s*\([^)]*(token|jwt|auth|session)/i, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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
          fix_effort: "M",
          owasp: [
            "OWASP Top 10 2021 A07 Identification and Authentication Failures",
            "OWASP ASVS V3 Session Management"
          ]
        }));
      }

      const tlsBypassLine = locateRelevantLine(contents, /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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
          fix_effort: "S",
          owasp: [
            "OWASP Top 10 2021 A02 Cryptographic Failures",
            "OWASP Top 10 2021 A05 Security Misconfiguration"
          ]
        }));
      }

      const springActuatorLine = locateRelevantLine(contents, /management\.endpoints\.web\.exposure\.include\s*[:=]\s*\*/, { skipDocs: markdownDocumentation, skipPatternDefinitions: true });
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

  return {
    findings,
    manifests,
    component_posture: componentPosture,
    file_contents_by_asset: fileContentsByAsset
  };
}

const scanStart = Date.now();
const telemetry = createScanTelemetry();
const files = walk(target, telemetry);
const scanResult = scanFiles(files, telemetry);
const findings = enrichFindingsWithCodeContext(scanResult.findings, scanResult.file_contents_by_asset || new Map());
const externalEnvelopes = loadDeepFindings(telemetry);
const coverageProfile = buildCoverageProfile(surface, standard);
const allFindings = findings.concat(...externalEnvelopes.map((envelope) => envelope.findings || []));
const externalCoverageAreas = mergeUnique(...externalEnvelopes.map((envelope) => envelope.metadata?.coverage_areas || []));
const externalBlindSpots = mergeUnique(...externalEnvelopes.map((envelope) => envelope.metadata?.blind_spots || []));
const sourceTools = mergeUnique(
  ["native-heuristic-scan"],
  ...externalEnvelopes.map((envelope) => envelope.metadata?.source_tools || [])
);
const componentPosture = [];
for (const item of scanResult.component_posture || []) {
  addComponentPosture(componentPosture, item);
}
addComponentPosture(componentPosture, {
  name: "native-heuristic-scan",
  kind: "analysis-source",
  ecosystem: "internal",
  origin: "scan runtime",
  review_status: "unknown",
  security_posture: "unknown",
  maintenance_posture: "unknown",
  provenance_posture: "unknown",
  confidence: "Low",
  evidence_mode: "offline-only",
  checked_at: new Date().toISOString(),
  evidence_sources: ["defensive-appsec-review-skill/scripts/audit-scan.js"],
  notes: "Observed as the built-in analysis source for this report. This row records provenance only and does not rate the scanner as safe or unsafe."
});
for (const envelopeItem of externalEnvelopes.flatMap((envelope) => envelope.metadata?.component_posture || [])) {
  addComponentPosture(componentPosture, envelopeItem);
}
const findingSummary = summarizeFindings(allFindings);
telemetry.manifests_detected = [...new Set(scanResult.manifests)].length;
telemetry.findings_by_rule = findingSummary.findingsByRule;
telemetry.findings_by_category = findingSummary.findingsByCategory;
telemetry.elapsed_ms = Date.now() - scanStart;
telemetry.scan_completed_at = new Date().toISOString();

const envelope = {
  metadata: {
    target,
    target_surface: surface,
    standard,
    standard_family: coverageProfile.standard_family,
    coverage_areas: mergeUnique(coverageProfile.coverage_areas, externalCoverageAreas),
    blind_spots: mergeUnique(coverageProfile.blind_spots, externalBlindSpots),
    source_tools: sourceTools,
    component_posture: componentPosture,
    timestamp: new Date().toISOString(),
    generated_by: "defensive-appsec-review-skill/scripts/audit-scan.js",
    notes: depth === "deep"
      ? "Deep read-only scan. Native heuristics were combined with any discoverable external static-analysis results. Findings should still be validated by an analyst before being treated as confirmed vulnerabilities."
      : "Read-only heuristic scan. Findings should be validated by an analyst before being treated as confirmed vulnerabilities.",
    scan_telemetry: telemetry
  },
  findings: allFindings
};

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, JSON.stringify(envelope, null, 2));

console.log(`[+] Scanned ${telemetry.files_scanned} files under ${target} (${telemetry.bytes_scanned} bytes read, ${telemetry.heuristic_checks_run} heuristic checks)`);
console.log(`[+] Wrote ${allFindings.length} findings to ${output}`);
