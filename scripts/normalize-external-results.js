#!/usr/bin/env node

/**
 * Normalize external static-analysis tool output into the security assessment schema.
 *
 * Usage examples:
 *   node scripts/normalize-external-results.js --tool sarif --input semgrep.sarif --output sandbox/semgrep.json --target . --type repo --standard owasp-top10
 *   node scripts/normalize-external-results.js --tool gitleaks --input gitleaks.json --output sandbox/gitleaks.json --target . --type repo --standard nist-ssdf
 */

const fs = require("fs");
const path = require("path");

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
  "owasp-masvs": "owasp-masvs",
  "nist-ssdf": "nist-ssdf",
  "ssdf": "nist-ssdf",
  "samm": "owasp-samm",
  "owasp-scvs": "owasp-scvs",
  "scvs": "owasp-scvs",
  "cwe-top-25": "cwe-top-25-2025",
  "cwe-top-25-2025": "cwe-top-25-2025",
  "slsa": "slsa",
  "cyclonedx": "cyclonedx",
  "sarif": "sarif"
};

function normalizeStandard(value) {
  const normalized = String(value || "nist-ssdf").trim().toLowerCase();
  return STANDARD_ALIASES[normalized] || normalized;
}

function severityBandFromLabel(value, fallback = "Medium") {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("critical")) return "Critical";
  if (normalized.includes("high")) return "High";
  if (normalized.includes("medium")) return "Medium";
  if (normalized.includes("low")) return "Low";
  if (normalized.includes("info") || normalized.includes("note")) return "Informational";
  return fallback;
}

function severityBandFromSarifLevel(value) {
  return {
    error: "High",
    warning: "Medium",
    note: "Low",
    none: "Informational"
  }[String(value || "").toLowerCase()] || "Medium";
}

function severityFromScore(score, fallbackLabel = "Medium") {
  const numeric = Number(score);
  if (!Number.isFinite(numeric)) {
    return fallbackLabel;
  }

  let label = fallbackLabel;
  if (numeric >= 9) label = "Critical";
  else if (numeric >= 7) label = "High";
  else if (numeric >= 4) label = "Medium";
  else if (numeric > 0) label = "Low";
  else label = "Informational";

  return `${numeric.toFixed(1)} (${label})`;
}

function severityToCvssString(value) {
  if (typeof value === "number") {
    return severityFromScore(value);
  }

  const normalized = String(value || "").trim();
  if (!normalized) {
    return "Medium";
  }

  const numeric = Number(normalized);
  if (Number.isFinite(numeric)) {
    return severityFromScore(numeric);
  }

  const band = severityBandFromLabel(normalized, "Medium");
  return band;
}

function extractCwe(text, fallback = "CWE-693: Protection Mechanism Failure") {
  const match = String(text || "").match(/CWE-\d+/i);
  if (match) {
    return match[0].toUpperCase();
  }
  return fallback;
}

function extractOwasp(entries) {
  return [...new Set(
    entries
      .flat()
      .filter(Boolean)
      .map((entry) => String(entry).trim())
      .filter((entry) => /OWASP/i.test(entry))
  )];
}

function buildLocation(uri, line) {
  if (!uri && !line) {
    return ".";
  }
  if (uri && Number.isFinite(Number(line))) {
    return `${uri}:${Number(line)}`;
  }
  return uri || ".";
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

function resolveCodeContext(overrides, context = {}) {
  const parsed = parseLocation(overrides.location || overrides.asset || "");
  const asset = overrides.asset || parsed.asset || ".";
  const lineNumber = Number.isFinite(Number(overrides.line_number))
    ? Number(overrides.line_number)
    : parsed.lineNumber;

  const absolutePath = asset && asset !== "."
    ? path.resolve(context.target || process.cwd(), asset)
    : "";

  let contents = "";
  if (absolutePath && fs.existsSync(absolutePath)) {
    try {
      contents = fs.readFileSync(absolutePath, "utf8");
    } catch {
      contents = "";
    }
  }

  const codeSnippet = overrides.code_snippet ||
    (contents ? extractSnippet(contents, lineNumber) : "");
  const className = overrides.class_name ||
    (contents ? detectNearestClassName(contents, lineNumber) : "");

  return {
    line_number: lineNumber || undefined,
    class_name: className || undefined,
    code_snippet: codeSnippet || undefined
  };
}

function inferDefaultNistMappings(overrides) {
  const title = String(overrides.title || "");
  const category = String(overrides.category || "");
  const control = String(overrides.control || "");

  if (/credential|secret|token/i.test(title) || /Secrets Management/i.test(category)) {
    return [
      "NIST SP 800-218 SSDF PS.1 Protect code, secrets, and related artifacts",
      "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
    ];
  }

  if (/Dependency Security|Supply Chain Security/i.test(category)) {
    return [
      "NIST SP 800-218 SSDF PW.4 Code and dependency review",
      "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
    ];
  }

  if (/Configuration/i.test(category) || /configuration|hardening|integrity|review/i.test(control)) {
    return [
      "NIST SP 800-218 SSDF PW.6 Secure software configuration and deployment hardening",
      "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
    ];
  }

  return [
    "NIST SP 800-218 SSDF PW.4 Code review and static analysis",
    "NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"
  ];
}

function inferDefaultAsvsMappings(overrides) {
  const category = String(overrides.category || "");
  const title = String(overrides.title || "");
  const owaspEntries = Array.isArray(overrides.owasp) ? overrides.owasp : [];
  const fromOwasp = owaspEntries.filter((entry) => /OWASP ASVS/i.test(entry));
  if (fromOwasp.length) {
    return [...new Set(fromOwasp)];
  }

  if (/Secrets Management/i.test(category) || /secret|token|credential/i.test(title)) {
    return ["OWASP ASVS V8 Data Protection"];
  }

  if (/Configuration/i.test(category)) {
    return ["OWASP ASVS V14 Configuration"];
  }

  return [];
}

function inferDefaultCisMappings(overrides) {
  const category = String(overrides.category || "");
  const title = String(overrides.title || "");

  if (/Secrets Management/i.test(category) || /secret|token|credential/i.test(title)) {
    return ["CIS Controls v8 Control 3 Data Protection"];
  }

  if (/Configuration|Supply Chain Security/i.test(category)) {
    return ["CIS Controls v8 Control 4 Secure Configuration of Enterprise Assets and Software"];
  }

  if (/Dependency Security/i.test(category)) {
    return ["CIS Controls v8 Control 2 Inventory and Control of Software Assets"];
  }

  return [];
}

function inferDefaultScvsMappings(overrides) {
  const category = String(overrides.category || "");

  if (/Dependency Security/i.test(category)) {
    return [
      "OWASP SCVS V1 Inventory",
      "OWASP SCVS V5 Component Analysis"
    ];
  }

  if (/Supply Chain Security/i.test(category)) {
    return [
      "OWASP SCVS V3 Build Environment",
      "OWASP SCVS V6 Pedigree and Provenance"
    ];
  }

  return [];
}

function inferDefaultSlsaMappings(overrides) {
  const category = String(overrides.category || "");

  if (/Supply Chain Security/i.test(category)) {
    return [
      "SLSA Build track provenance integrity",
      "SLSA Source track change and branch integrity"
    ];
  }

  if (/Dependency Security/i.test(category)) {
    return ["SLSA dependency and provenance verification support"];
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

function makeFinding(overrides, context = {}) {
  const asvs = resolveFrameworkEntries(overrides, "asvs", inferDefaultAsvsMappings);
  const nist = resolveFrameworkEntries(overrides, "nist", inferDefaultNistMappings);
  const cis = resolveFrameworkEntries(overrides, "cis", inferDefaultCisMappings);
  const scvs = resolveFrameworkEntries(overrides, "scvs", inferDefaultScvsMappings);
  const slsa = resolveFrameworkEntries(overrides, "slsa", inferDefaultSlsaMappings);
  const owasp = resolveFrameworkEntries(overrides, "owasp", () => []);
  const primaryProvenance = normalizeMappingProvenance(
    overrides.mapping_provenance?.primary,
    overrides.control ? "supplied" : "not-recorded"
  );

  const codeContext = resolveCodeContext(overrides, context);

  return {
    title: overrides.title,
    asset: overrides.asset || ".",
    location: overrides.location || overrides.asset || ".",
    line_number: codeContext.line_number,
    class_name: codeContext.class_name,
    code_snippet: codeContext.code_snippet,
    category: overrides.category || "Static Analysis",
    cwe: overrides.cwe || "CWE-693: Protection Mechanism Failure",
    cvss_v4: overrides.cvss_v4 || "Medium",
    confidence: overrides.confidence || "Medium",
    framework_mapping: {
      standard: context.standard || "nist-ssdf",
      control: overrides.control || "",
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
      references: overrides.references || []
    },
    verification_tier: overrides.verification_tier || "deterministic-static",
    source_tool: overrides.source_tool || context.tool || "external-tool",
    evidence: overrides.evidence || "Tool reported a static-analysis issue.",
    reproduction_steps: overrides.reproduction_steps || "Review the referenced artifact and validate the reported condition in code or configuration.",
    business_impact: overrides.business_impact || "The reported issue can weaken the security posture of the reviewed asset.",
    remediation: overrides.remediation || "Review the flagged location, validate the context, and apply the owning tool's remediation guidance.",
    fix_effort: overrides.fix_effort || "M",
    references: overrides.references || []
  };
}

function createComponentPosture(overrides = {}) {
  const name = String(overrides.name || "").trim();
  if (!name) {
    return null;
  }

  return {
    name,
    version: String(overrides.version || "").trim(),
    kind: overrides.kind || "analysis-source",
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

function sarifRuleIndex(run) {
  const rules = run.tool?.driver?.rules || [];
  return new Map(rules.map((rule) => [rule.id, rule]));
}

function normalizeSarif(document, context = {}) {
  const findings = [];

  for (const run of document.runs || []) {
    const rules = sarifRuleIndex(run);
    const driverName = context.sourceLabel || run.tool?.driver?.name || "sarif";

    for (const result of run.results || []) {
      const rule = rules.get(result.ruleId) || {};
      const firstLocation = result.locations?.[0]?.physicalLocation || {};
      const uri = firstLocation.artifactLocation?.uri || ".";
      const line = firstLocation.region?.startLine;
      const snippet = firstLocation.region?.snippet?.text || result.locations?.[0]?.message?.text || "";
      const tags = [
        ...(rule.properties?.tags || []),
        ...(result.properties?.tags || [])
      ];
      const securitySeverity = Number(result.properties?.["security-severity"] || rule.properties?.["security-severity"]);
      const band = Number.isFinite(securitySeverity) ? severityFromScore(securitySeverity) : severityBandFromSarifLevel(result.level);
      const cwe = extractCwe(
        [result.ruleId, rule.id, ...tags].join(" "),
        /^[A-Z]+-\d+/.test(String(result.ruleId || "")) ? String(result.ruleId) : "CWE-693: Protection Mechanism Failure"
      );
      const references = [rule.helpUri].filter(Boolean);
      findings.push(makeFinding({
        title: rule.name || result.ruleId || "Static analysis finding",
        asset: uri,
        location: buildLocation(uri, line),
        line_number: line,
        code_snippet: snippet || undefined,
        category: rule.properties?.precision || "Static Analysis",
        cwe,
        cvss_v4: band,
        confidence: result.level === "error" ? "High" : "Medium",
        control: rule.shortDescription?.text || "External static-analysis rule",
        owasp: extractOwasp(tags),
        references,
        source_tool: driverName,
        evidence: result.message?.text || rule.fullDescription?.text || "SARIF result reported an issue.",
        reproduction_steps: `1. Inspect ${buildLocation(uri, line)}.\n2. Review the rule guidance from ${driverName}.\n3. Validate whether the issue is reachable in the reviewed code path.`,
        business_impact: rule.help?.text || "The SARIF result indicates a static-analysis weakness that merits review.",
        remediation: rule.fullDescription?.text || rule.help?.text || "Use the associated tool guidance to remediate the flagged weakness.",
        fix_effort: result.level === "error" ? "M" : "S"
      }, context));
    }
  }

  return findings;
}

function normalizeGitleaks(document, context = {}) {
  return (Array.isArray(document) ? document : []).map((item) => {
    const file = item.File || item.file || ".";
    const line = item.StartLine || item.startLine;
    const tags = item.Tags || item.tags || [];
    return makeFinding({
      title: item.Description || `Potential secret detected (${item.RuleID || "gitleaks-rule"})`,
      asset: file,
      location: buildLocation(file, line),
      line_number: line,
      category: "Secrets Management",
      cwe: "CWE-798: Use of Hard-coded Credentials",
      cvss_v4: "High",
      confidence: "Medium",
      control: "Secret exposure prevention",
      owasp: extractOwasp(tags),
      source_tool: context.sourceLabel || "gitleaks",
      evidence: `Gitleaks reported a secret-like value in ${file}${line ? ` at line ${line}` : ""}.`,
      reproduction_steps: `1. Inspect ${buildLocation(file, line)}.\n2. Confirm whether the value is active, test-only, or already revoked.\n3. Rotate and remove any live credentials.`,
      business_impact: "Committed secrets can enable unauthorized access, lateral movement, or long-lived credential leakage.",
      remediation: "Move secrets into managed secret storage, purge them from the repository history where appropriate, and rotate any active values.",
      fix_effort: "M",
      references: []
    }, context);
  });
}

function normalizeTrivy(document, context = {}) {
  const findings = [];

  for (const result of document.Results || document.results || []) {
    for (const vuln of result.Vulnerabilities || result.vulnerabilities || []) {
      const score = vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score || vuln.CVSS?.ghsa?.V3Score;
      findings.push(makeFinding({
        title: `${vuln.VulnerabilityID || vuln.VulnID || "Vulnerability"} in ${vuln.PkgName || result.Target || "dependency"}`,
        asset: result.Target || vuln.PkgName || ".",
        location: result.Target || vuln.PkgName || ".",
        category: "Dependency Security",
        cwe: extractCwe((vuln.PrimaryURL || "") + " " + (vuln.Title || ""), "CWE-1104: Use of Unmaintained Third Party Components"),
        cvss_v4: score ? severityFromScore(score) : severityToCvssString(vuln.Severity),
        confidence: "High",
        control: "Dependency vulnerability management",
        owasp: ["OWASP Top 10 2021 A06 Vulnerable and Outdated Components", ...extractOwasp([vuln.Title, vuln.Description])],
        source_tool: context.sourceLabel || "trivy",
        evidence: vuln.Title || vuln.Description || `${vuln.VulnerabilityID} reported by Trivy.`,
        reproduction_steps: `1. Inspect dependency target ${result.Target || vuln.PkgName}.\n2. Verify the installed version and the fixed version ${vuln.FixedVersion || "if available"}.\n3. Update or mitigate according to package ownership constraints.`,
        business_impact: vuln.Description || "Known vulnerable dependencies can expose the application to published exploitation paths or compliance risk.",
        remediation: vuln.FixedVersion
          ? `Upgrade ${vuln.PkgName || "the affected package"} to ${vuln.FixedVersion} or later.`
          : `Review upgrade, pinning, or compensating-control options for ${vuln.PkgName || "the affected package"}.`,
        fix_effort: "M",
        references: [vuln.PrimaryURL].filter(Boolean)
      }, context));
    }

    for (const misconfig of result.Misconfigurations || result.misconfigurations || []) {
      findings.push(makeFinding({
        title: `${misconfig.ID || "Misconfiguration"}: ${misconfig.Title || "Configuration issue"}`,
        asset: result.Target || ".",
        location: result.Target || ".",
        category: "Configuration",
        cwe: extractCwe((misconfig.PrimaryURL || "") + " " + (misconfig.Title || ""), "CWE-16: Configuration"),
        cvss_v4: severityToCvssString(misconfig.Severity),
        confidence: "Medium",
        control: "Secure configuration review",
        owasp: ["OWASP Top 10 2021 A05 Security Misconfiguration", ...extractOwasp([misconfig.Title, misconfig.Description])],
        source_tool: context.sourceLabel || "trivy",
        evidence: misconfig.Message || misconfig.Description || "Trivy reported a configuration issue.",
        reproduction_steps: `1. Inspect configuration target ${result.Target || "."}.\n2. Review the policy described by ${misconfig.ID || "the Trivy rule"}.\n3. Align the configuration with the secure baseline.`,
        business_impact: misconfig.Description || "Security misconfiguration can enlarge attack surface or weaken hardening controls.",
        remediation: misconfig.Resolution || "Update the configuration to satisfy the reported security control.",
        fix_effort: "S",
        references: [misconfig.PrimaryURL].filter(Boolean)
      }, context));
    }

    for (const secret of result.Secrets || result.secrets || []) {
      findings.push(makeFinding({
        title: secret.Title || `Potential secret detected (${secret.RuleID || "trivy-secret"})`,
        asset: result.Target || secret.Target || ".",
        location: buildLocation(result.Target || secret.Target || ".", secret.StartLine),
        line_number: secret.StartLine,
        category: "Secrets Management",
        cwe: "CWE-798: Use of Hard-coded Credentials",
        cvss_v4: "High",
        confidence: "Medium",
        control: "Secret exposure prevention",
        owasp: extractOwasp([secret.Title, secret.RuleID]),
        source_tool: context.sourceLabel || "trivy",
        evidence: secret.Match || secret.Title || "Trivy secret scan reported a credential-like value.",
        reproduction_steps: `1. Inspect ${buildLocation(result.Target || secret.Target || ".", secret.StartLine)}.\n2. Confirm whether the secret is valid or test data.\n3. Rotate and remove any live credential.`,
        business_impact: "Exposed secrets can permit unauthorized access to internal systems or third-party services.",
        remediation: "Remove the secret from source, rotate it, and use managed secret delivery for future deployments.",
        fix_effort: "M"
      }, context));
    }
  }

  return findings;
}

function normalizeOsv(document, context = {}) {
  const findings = [];

  for (const result of document.results || []) {
    for (const pkg of result.packages || []) {
      for (const vulnerability of pkg.vulnerabilities || []) {
        const severity = vulnerability.database_specific?.severity || vulnerability.severity?.[0]?.type || "Medium";
        findings.push(makeFinding({
          title: `${vulnerability.id || "OSV advisory"} in ${pkg.package?.name || "dependency"}`,
          asset: pkg.package?.name || ".",
          location: pkg.package?.name || ".",
          category: "Dependency Security",
          cwe: extractCwe((vulnerability.summary || "") + " " + (vulnerability.details || ""), "CWE-1104: Use of Unmaintained Third Party Components"),
          cvss_v4: severityToCvssString(severity),
          confidence: "High",
          control: "Dependency vulnerability management",
          owasp: ["OWASP Top 10 2021 A06 Vulnerable and Outdated Components"],
          source_tool: context.sourceLabel || "osv-scanner",
          evidence: vulnerability.summary || vulnerability.details || "OSV-Scanner reported a vulnerable component.",
          reproduction_steps: `1. Inspect package ${pkg.package?.name || "dependency"} version ${pkg.package?.version || "unknown"}.\n2. Review the OSV advisory ${vulnerability.id || ""}.\n3. Upgrade, replace, or mitigate the affected component.`,
          business_impact: vulnerability.details || "Known vulnerable components can expose published exploit paths or inherited product risk.",
          remediation: "Upgrade the affected dependency to a fixed version or apply an accepted compensating control with owner sign-off.",
          fix_effort: "M",
          references: [vulnerability.id ? `https://osv.dev/vulnerability/${vulnerability.id}` : null].filter(Boolean)
        }, context));
      }
    }
  }

  return findings;
}

const SCORECARD_CHECK_MAPPINGS = {
  "Binary-Artifacts": { cwe: "CWE-494: Download of Code Without Integrity Check", severity: "Medium" },
  "Dangerous-Workflow": { cwe: "CWE-829: Inclusion of Functionality from Untrusted Control Sphere", severity: "High" },
  "Token-Permissions": { cwe: "CWE-732: Incorrect Permission Assignment for Critical Resource", severity: "High" },
  "Pinned-Dependencies": { cwe: "CWE-1104: Use of Unmaintained Third Party Components", severity: "Medium" },
  "Signed-Releases": { cwe: "CWE-347: Improper Verification of Cryptographic Signature", severity: "Medium" },
  "Branch-Protection": { cwe: "CWE-693: Protection Mechanism Failure", severity: "Medium" },
  "Code-Review": { cwe: "CWE-284: Improper Access Control", severity: "Low" }
};

function normalizeScorecard(document, context = {}) {
  const findings = [];

  for (const check of document.checks || []) {
    if (Number(check.score) >= 7) {
      continue;
    }

    const mapping = SCORECARD_CHECK_MAPPINGS[check.name] || { cwe: "CWE-693: Protection Mechanism Failure", severity: "Medium" };
    const score = Number(check.score);
    const severity = Number.isFinite(score) ? (score < 4 ? "High" : "Medium") : mapping.severity;
    findings.push(makeFinding({
      title: `Repository posture gap: ${check.name}`,
      asset: document.repo?.name || document.repo?.url || ".",
      location: document.repo?.name || document.repo?.url || ".",
      category: "Supply Chain Security",
      cwe: mapping.cwe,
      cvss_v4: severity,
      confidence: "Medium",
      control: "OpenSSF Scorecard posture review",
      owasp: [],
      source_tool: context.sourceLabel || "openssf-scorecard",
      evidence: check.reason || `Scorecard reported a score of ${check.score} for ${check.name}.`,
      reproduction_steps: `1. Review the ${check.name} Scorecard check for the repository.\n2. Confirm whether the repository policy, workflow, or release process already compensates for the reported gap.\n3. Improve the repository posture if the gap is real.`,
      business_impact: check.documentation?.short || "Repository posture weaknesses can increase supply-chain risk, release tampering exposure, or trust gaps.",
      remediation: check.details || `Improve the repository configuration so the ${check.name} check meets the team's required threshold.`,
      fix_effort: "M",
      references: [check.documentation?.url].filter(Boolean)
    }, context));
  }

  return findings;
}

function normalizeDependencyCheck(document, context = {}) {
  const findings = [];

  for (const dependency of document.dependencies || []) {
    for (const vulnerability of dependency.vulnerabilities || []) {
      const score = vulnerability.cvssv3?.baseScore || vulnerability.cvssv2?.score;
      findings.push(makeFinding({
        title: `${vulnerability.name || vulnerability.source || "Dependency vulnerability"} in ${dependency.fileName || dependency.filePath || "dependency"}`,
        asset: dependency.filePath || dependency.fileName || ".",
        location: dependency.filePath || dependency.fileName || ".",
        category: "Dependency Security",
        cwe: vulnerability.cwes?.[0] || "CWE-1104: Use of Unmaintained Third Party Components",
        cvss_v4: score ? severityFromScore(score) : severityToCvssString(vulnerability.severity),
        confidence: "High",
        control: "Dependency vulnerability management",
        owasp: ["OWASP Top 10 2021 A06 Vulnerable and Outdated Components"],
        source_tool: context.sourceLabel || "dependency-check",
        evidence: vulnerability.description || `${vulnerability.name || vulnerability.source} reported by Dependency-Check.`,
        reproduction_steps: `1. Inspect dependency manifest entry ${dependency.fileName || dependency.filePath || "dependency"}.\n2. Review the advisory ${vulnerability.name || vulnerability.source || ""}.\n3. Upgrade or replace the affected component.`,
        business_impact: vulnerability.description || "Known vulnerable dependencies can introduce published weaknesses into the application or build pipeline.",
        remediation: "Upgrade the affected dependency to a fixed version or remove the vulnerable transitive path where possible.",
        fix_effort: "M",
        references: [vulnerability.references?.[0]?.url].filter(Boolean)
      }, context));
    }
  }

  return findings;
}

function coverageProfileForTool(selectedTool) {
  const map = {
    sarif: {
      coverage_areas: ["semantic and rule-based static-analysis findings imported through SARIF"],
      blind_spots: ["tool-specific rule reachability and runtime exploitability still require analyst review"]
    },
    gitleaks: {
      coverage_areas: ["secret and credential exposure detection"],
      blind_spots: ["revocation status and runtime secret usage still require validation"]
    },
    trivy: {
      coverage_areas: ["dependency vulnerabilities, misconfiguration, and secret signals"],
      blind_spots: ["fix applicability and deployed-runtime reachability still require owner review"]
    },
    "osv-scanner": {
      coverage_areas: ["dependency vulnerability enrichment from OSV advisories"],
      blind_spots: ["runtime exploitability and package reachability are not proven by advisory presence alone"]
    },
    "openssf-scorecard": {
      coverage_areas: ["repository and supply-chain posture checks"],
      blind_spots: ["low repository posture scores do not by themselves prove a concrete exploitable vulnerability"]
    },
    "dependency-check": {
      coverage_areas: ["dependency vulnerability identification from manifests and package metadata"],
      blind_spots: ["transitive reachability and runtime exploitability still require review"]
    }
  };

  return map[selectedTool] || {
    coverage_areas: ["external static-analysis result ingestion"],
    blind_spots: ["tool findings still require human validation in context"]
  };
}

const NORMALIZERS = {
  sarif: normalizeSarif,
  gitleaks: normalizeGitleaks,
  trivy: normalizeTrivy,
  "osv-scanner": normalizeOsv,
  scorecard: normalizeScorecard,
  "dependency-check": normalizeDependencyCheck
};

function normalizeExternalResults({ tool, document, target = ".", surface = "repo", standard = "nist-ssdf", sourceLabel = "" }) {
  const normalizedTool = String(tool || "").trim().toLowerCase();
  const normalizedSurface = String(surface || "repo").toLowerCase();
  const normalizedStandard = normalizeStandard(standard || "nist-ssdf");

  if (!NORMALIZERS[normalizedTool]) {
    throw new Error(`Unsupported tool: ${normalizedTool}`);
  }

  const findings = NORMALIZERS[normalizedTool](document, {
    tool: normalizedTool,
    sourceLabel,
    standard: normalizedStandard,
    surface: normalizedSurface,
    target
  });
  const coverage = coverageProfileForTool(normalizedTool === "scorecard" ? "openssf-scorecard" : normalizedTool);

  return {
    metadata: {
      target: path.resolve(process.cwd(), target),
      target_surface: normalizedSurface,
      standard: normalizedStandard,
      standard_family: normalizedStandard,
      coverage_areas: coverage.coverage_areas,
      blind_spots: coverage.blind_spots,
      source_tools: [normalizedTool === "scorecard" ? "openssf-scorecard" : normalizedTool],
      component_posture: [
        createComponentPosture({
          name: normalizedTool === "scorecard" ? "openssf-scorecard" : normalizedTool,
          kind: "analysis-source",
          ecosystem: "external-tool",
          origin: "external result ingestion",
          review_status: "unknown",
          security_posture: "unknown",
          maintenance_posture: "unknown",
          provenance_posture: "unknown",
          confidence: "Low",
          evidence_mode: "offline-only",
          checked_at: new Date().toISOString(),
          evidence_sources: [normalizedTool],
          notes: "Observed as an external analysis source for this report. This row records provenance only and does not rate the tool as safe or unsafe."
        })
      ].filter(Boolean),
      timestamp: new Date().toISOString(),
      generated_by: "defensive-appsec-review-skill/scripts/normalize-external-results.js",
      notes: `Normalized ${findings.length} findings from ${normalizedTool}.`
    },
    findings
  };
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = {};

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith("--")) {
      continue;
    }

    const key = arg.slice(2);
    const next = args[index + 1];
    if (!next || next.startsWith("--")) {
      options[key] = true;
      continue;
    }

    options[key] = next;
    index += 1;
  }

  return options;
}

function main() {
  const options = parseArgs(process.argv);
  const tool = String(options.tool || "").trim().toLowerCase();
  const inputPath = options.input ? path.resolve(process.cwd(), options.input) : null;
  const outputPath = path.resolve(process.cwd(), options.output || "normalized-findings.json");

  if (!tool) {
    console.error("[-] Provide --tool.");
    process.exit(1);
  }

  if (!inputPath || !fs.existsSync(inputPath)) {
    console.error("[-] Provide an existing --input file.");
    process.exit(1);
  }

  const raw = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  const envelope = normalizeExternalResults({
    tool,
    document: raw,
    target: options.target || ".",
    surface: options.type || "repo",
    standard: options.standard || "nist-ssdf",
    sourceLabel: options.source || ""
  });

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(envelope, null, 2), "utf8");

  console.log(`[+] Normalized ${envelope.findings.length} findings from ${tool} to ${outputPath}`);
}

module.exports = {
  normalizeExternalResults,
  normalizeStandard,
  coverageProfileForTool,
  NORMALIZERS
};

if (require.main === module) {
  main();
}
