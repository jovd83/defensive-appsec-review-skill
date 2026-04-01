const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function copyDir(source, destination) {
  fs.mkdirSync(destination, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (entry.isDirectory()) {
      copyDir(sourcePath, destinationPath);
    } else {
      fs.copyFileSync(sourcePath, destinationPath);
    }
  }
}

test("audit-scan emits findings for common risky patterns and code-level checks", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-scan-"));
  const repoDir = path.join(tempDir, "repo");
  copyDir(path.join(process.cwd(), "fixtures", "sample-risky-repo"), repoDir);

  const outputFile = path.join(tempDir, "findings.json");

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "audit-scan.js"),
    "--target",
    repoDir,
    "--type",
    "repo",
    "--standard",
    "nist-ssdf",
    "--output",
    outputFile
  ], { cwd: process.cwd() });

  const report = JSON.parse(fs.readFileSync(outputFile, "utf8"));
  assert.equal(report.metadata.target_surface, "repo");
  assert.equal(report.metadata.standard_family, "nist-ssdf");
  assert.ok(Array.isArray(report.findings));
  assert.ok(Array.isArray(report.metadata.coverage_areas));
  assert.ok(Array.isArray(report.metadata.blind_spots));
  assert.ok(Array.isArray(report.metadata.component_posture));
  assert.ok(report.metadata.scan_telemetry);
  assert.ok(report.metadata.scan_telemetry.files_discovered >= report.metadata.scan_telemetry.files_scanned);
  assert.ok(report.metadata.scan_telemetry.files_scanned > 0);
  assert.ok(report.metadata.scan_telemetry.bytes_scanned > 0);
  assert.ok(report.metadata.scan_telemetry.heuristic_checks_run > 0);
  assert.ok(Number.isFinite(report.metadata.scan_telemetry.elapsed_ms));
  assert.ok(typeof report.metadata.scan_telemetry.findings_by_rule === "object");
  assert.ok(typeof report.metadata.scan_telemetry.findings_by_category === "object");
  assert.ok(report.findings.some((finding) => finding.title.includes("Environment file")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Wildcard CORS")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Broad GitHub Actions token permissions")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Dynamic code execution via eval")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Unsafe HTML rendering sink")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Shell-enabled subprocess execution")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Potentially insecure JWT handling")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Python pickle deserialization sink")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Unsafe YAML load")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Java Runtime.exec usage")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Potential SQL query string concatenation")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Flask debug mode enabled")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Django debug mode enabled")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Sensitive token stored in browser localStorage")));
  assert.ok(report.findings.some((finding) => finding.title.includes("TLS certificate verification appears disabled")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Spring actuator endpoints broadly exposed")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Kubernetes container runs in privileged mode")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Kubernetes hostPath mount detected")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Weak cryptographic hash algorithm")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Client-controlled object update pattern")));
  assert.ok(report.findings.some((finding) => finding.title.includes("User-controlled outbound request target")));
  assert.ok(report.findings.some((finding) => finding.title.includes("User-controlled redirect target")));
  assert.ok(report.findings.some((finding) => finding.title.includes("User-controlled file path reaches filesystem sink")));
  assert.ok(report.findings.some((finding) => finding.title.includes("Direct object access route lacks obvious authorization guard")));
  assert.ok(report.findings.every((finding) => typeof finding.location === "string" && finding.location.length > 0));
  assert.ok(report.findings.every((finding) => !finding.line_number || Number.isInteger(finding.line_number)));
  assert.ok(report.findings.some((finding) => typeof finding.code_snippet === "string" && finding.code_snippet.includes("|")));
  assert.ok(report.findings.some((finding) =>
    Array.isArray(finding.framework_mapping?.owasp) &&
    finding.framework_mapping.owasp.some((entry) => entry.includes("OWASP"))
  ));
  assert.ok(report.findings.some((finding) =>
    Array.isArray(finding.framework_mapping?.nist) &&
    finding.framework_mapping.nist.some((entry) => /NIST SP 800-218 SSDF/i.test(entry))
  ));
  assert.ok(report.findings.some((finding) =>
    Array.isArray(finding.framework_mapping?.asvs) &&
    finding.framework_mapping.asvs.some((entry) => /OWASP ASVS/i.test(entry))
  ));
  assert.ok(report.findings.some((finding) =>
    Array.isArray(finding.framework_mapping?.cis) &&
    finding.framework_mapping.cis.some((entry) => /CIS Controls v8/i.test(entry))
  ));
  assert.ok(report.findings.some((finding) => finding.framework_mapping?.provenance));
  assert.ok(report.metadata.component_posture.some((item) => item.name === "express" && item.kind === "library" && item.review_status === "unknown"));
  assert.ok(report.metadata.component_posture.some((item) => item.name === "lodash" && item.kind === "library"));
  assert.ok(report.metadata.component_posture.some((item) => item.name === "jest" && item.kind === "library"));
  assert.ok(report.metadata.component_posture.some((item) =>
    item.name === "native-heuristic-scan" &&
    item.kind === "analysis-source" &&
    item.review_status === "unknown"
  ));

  const broadPermissionsFinding = report.findings.find((finding) => finding.title.includes("Broad GitHub Actions token permissions"));
  assert.ok(broadPermissionsFinding);
  assert.ok(broadPermissionsFinding.framework_mapping.owasp.some((entry) => /A05 Security Misconfiguration/i.test(entry)));
  assert.equal(broadPermissionsFinding.framework_mapping.provenance.owasp, "inferred");
  assert.equal(broadPermissionsFinding.framework_mapping.provenance.cis, "inferred");

  const evalFinding = report.findings.find((finding) => finding.title.includes("Dynamic code execution via eval"));
  assert.ok(evalFinding);
  assert.ok(evalFinding.framework_mapping.owasp.some((entry) => /A03 Injection/i.test(entry)));
  assert.ok(evalFinding.framework_mapping.asvs.some((entry) => /OWASP ASVS V5/i.test(entry)));
  assert.equal(evalFinding.framework_mapping.provenance.owasp, "inferred");

  const ciFinding = report.findings.find((finding) => finding.title.includes("Broad GitHub Actions token permissions"));
  assert.ok(ciFinding.framework_mapping.cis.some((entry) => /CIS Controls v8 Control 4/i.test(entry)));
});

test("audit-scan normalizes OWASP API standard names and emits API coverage metadata", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-api-scan-"));
  const repoDir = path.join(tempDir, "repo");
  copyDir(path.join(process.cwd(), "fixtures", "sample-risky-repo"), repoDir);

  const outputFile = path.join(tempDir, "findings.json");

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "audit-scan.js"),
    "--target",
    repoDir,
    "--type",
    "api",
    "--standard",
    "owasp-api-top10",
    "--output",
    outputFile
  ], { cwd: process.cwd() });

  const report = JSON.parse(fs.readFileSync(outputFile, "utf8"));
  assert.equal(report.metadata.target_surface, "api");
  assert.equal(report.metadata.standard, "owasp-api-top-10-2023");
  assert.equal(report.metadata.standard_family, "owasp-api-top-10-2023");
  assert.ok(report.metadata.coverage_areas.some((entry) => /OWASP API Top 10/i.test(entry)));
  assert.ok(report.metadata.blind_spots.some((entry) => /object-level authorization/i.test(entry)));
  assert.ok(report.findings.some((finding) =>
    Array.isArray(finding.framework_mapping?.owasp) &&
    finding.framework_mapping.owasp.some((entry) => /OWASP API Top 10/i.test(entry))
  ));
});

test("audit-scan suppresses support-material false positives on the skill repository itself", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-self-scan-"));
  const outputFile = path.join(tempDir, "findings.json");

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "audit-scan.js"),
    "--target",
    process.cwd(),
    "--type",
    "repo",
    "--standard",
    "owasp-scvs",
    "--output",
    outputFile
  ], { cwd: process.cwd() });

  const report = JSON.parse(fs.readFileSync(outputFile, "utf8"));
  assert.ok(report.findings.every((finding) => !finding.asset.startsWith("fixtures/")));
  assert.ok(report.findings.every((finding) => !finding.asset.startsWith("references/")));
  assert.ok(report.findings.every((finding) => finding.asset !== "README.md"));
  assert.ok(report.findings.every((finding) => !finding.asset.includes("repository-reports/")));
  assert.ok(report.findings.every((finding) => !finding.asset.includes("__pycache__/")));
  assert.ok(report.findings.every((finding) =>
    !(finding.asset === "scripts/audit-scan.js" && /Unsafe HTML rendering|Potential SQL query|string concatenation|Django debug mode/i.test(finding.title))
  ));
});

test("audit-scan deep mode imports external static-analysis findings", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-deep-scan-"));
  const repoDir = path.join(tempDir, "repo");
  copyDir(path.join(process.cwd(), "fixtures", "sample-risky-repo"), repoDir);

  const outputFile = path.join(tempDir, "findings.json");
  const sarifFixture = path.join(process.cwd(), "fixtures", "external-tools", "semgrep.sarif");

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "audit-scan.js"),
    "--target",
    repoDir,
    "--type",
    "repo",
    "--standard",
    "owasp-top10",
    "--depth",
    "deep",
    "--deep-inputs",
    `sarif=${sarifFixture}`,
    "--output",
    outputFile
  ], { cwd: process.cwd() });

  const report = JSON.parse(fs.readFileSync(outputFile, "utf8"));
  assert.equal(report.metadata.scan_telemetry.scan_depth, "deep");
  assert.ok(report.metadata.source_tools.some((tool) => tool === "native-heuristic-scan"));
  assert.ok(report.metadata.source_tools.some((tool) => tool === "sarif"));
  assert.ok(report.metadata.component_posture.some((item) => item.name === "sarif" && item.kind === "analysis-source"));
  assert.ok(report.metadata.scan_telemetry.external_findings_imported > 0);
  assert.ok(report.metadata.scan_telemetry.external_sources_loaded.some((item) => item.tool === "sarif"));
  assert.ok(report.findings.some((finding) => finding.source_tool === "Semgrep OSS"));
});
