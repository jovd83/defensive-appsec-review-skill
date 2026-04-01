const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function runNormalizer(tool, inputFile, extraArgs = []) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `security-normalize-${tool}-`));
  const outputFile = path.join(tempDir, "normalized.json");

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "normalize-external-results.js"),
    "--tool",
    tool,
    "--input",
    inputFile,
    "--output",
    outputFile,
    "--target",
    ".",
    "--type",
    "repo",
    "--standard",
    "owasp-top10",
    ...extraArgs
  ], { cwd: process.cwd() });

  return JSON.parse(fs.readFileSync(outputFile, "utf8"));
}

test("normalize-external-results ingests SARIF output", () => {
  const report = runNormalizer("sarif", path.join("fixtures", "external-tools", "semgrep.sarif"));

  assert.equal(report.metadata.standard, "owasp-top-10-2021");
  assert.equal(report.findings[0].source_tool, "Semgrep OSS");
  assert.match(report.findings[0].title, /open redirect/i);
  assert.ok(report.findings[0].framework_mapping.owasp.some((entry) => /OWASP/i.test(entry)));
  assert.equal(report.findings[0].framework_mapping.provenance.owasp, "supplied");
  assert.equal(report.findings[0].location, "api.js:22");
  assert.equal(report.findings[0].line_number, 22);
  assert.ok(report.findings[0].code_snippet === undefined || typeof report.findings[0].code_snippet === "string");
});

test("normalize-external-results ingests Gitleaks output", () => {
  const report = runNormalizer("gitleaks", path.join("fixtures", "external-tools", "gitleaks.json"));

  assert.equal(report.metadata.source_tools[0], "gitleaks");
  assert.match(report.findings[0].title, /API key/i);
  assert.equal(report.findings[0].cwe, "CWE-798: Use of Hard-coded Credentials");
});

test("normalize-external-results ingests Trivy output", () => {
  const report = runNormalizer("trivy", path.join("fixtures", "external-tools", "trivy.json"));

  assert.ok(report.findings.some((finding) => /CVE-2024-9999/i.test(finding.title)));
  assert.ok(report.findings.some((finding) => /running as root/i.test(finding.title)));
  assert.ok(report.findings.some((finding) => /AWS access key/i.test(finding.title)));
});

test("normalize-external-results ingests OSV-Scanner output", () => {
  const report = runNormalizer("osv-scanner", path.join("fixtures", "external-tools", "osv-scanner.json"));

  assert.equal(report.findings[0].source_tool, "osv-scanner");
  assert.match(report.findings[0].title, /GHSA-9wx4-h78v-vm56/);
  assert.ok(report.findings[0].framework_mapping.owasp.some((entry) => /A06/i.test(entry)));
});

test("normalize-external-results ingests OpenSSF Scorecard output", () => {
  const report = runNormalizer("scorecard", path.join("fixtures", "external-tools", "scorecard.json"));

  assert.equal(report.metadata.source_tools[0], "openssf-scorecard");
  assert.equal(report.findings.length, 1);
  assert.match(report.findings[0].title, /Dangerous-Workflow/);
  assert.match(report.findings[0].cwe, /CWE-829/);
  assert.ok(report.findings[0].framework_mapping.slsa.some((entry) => /SLSA/i.test(entry)));
});

test("normalize-external-results ingests Dependency-Check output", () => {
  const report = runNormalizer("dependency-check", path.join("fixtures", "external-tools", "dependency-check.json"));

  assert.equal(report.findings[0].source_tool, "dependency-check");
  assert.match(report.findings[0].title, /CVE-2023-12345/);
  assert.match(report.findings[0].cwe, /CWE-1104/);
  assert.ok(report.findings[0].framework_mapping.scvs.some((entry) => /OWASP SCVS/i.test(entry)));
  assert.equal(report.findings[0].framework_mapping.provenance.scvs, "inferred");
});
