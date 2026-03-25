const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

test("generate-report builds a markdown report from findings input", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-report-"));
  const inputFile = path.join(tempDir, "input.json");
  const outputFile = path.join(tempDir, "report.md");

  fs.writeFileSync(inputFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      target_surface: "repo",
      standard: "nist-ssdf",
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "Potential hardcoded credential detected",
        asset: "src/config.js",
        location: "src/config.js:12",
        category: "Credential Management",
        cwe: "CWE-798: Use of Hard-coded Credentials",
        cvss_v4: "8.6 (High)",
        confidence: "Medium",
        fix_effort: "M",
        framework_mapping: {
          standard: "nist-ssdf",
          control: "Secret exposure prevention"
        },
        evidence: "Matched credential-like value in source.",
        reproduction_steps: "1. Open file\n2. Review value",
        business_impact: "Credential compromise risk.",
        remediation: "Move secret to a manager and rotate."
      }
    ]
  }, null, 2));

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--output",
    outputFile
  ], { cwd: process.cwd() });

  const markdown = fs.readFileSync(outputFile, "utf8");
  assert.match(markdown, /Security Assessment Report - demo-repo/);
  assert.match(markdown, /Potential hardcoded credential detected/);
  assert.match(markdown, /Severity Snapshot/);
  assert.match(markdown, /Location: src\/config\.js:12/);
  assert.match(markdown, /Fix effort: M/);
});

test("generate-report builds a SARIF-style JSON report", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-sarif-"));
  const inputFile = path.join(tempDir, "input.json");
  const outputFile = path.join(tempDir, "report.sarif.json");

  fs.writeFileSync(inputFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      target_surface: "repo",
      standard: "nist-ssdf",
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "Dynamic code execution via eval detected",
        asset: "src/index.js",
        location: "src/index.js:3",
        category: "Code Injection Risk",
        cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        cvss_v4: "7.8 (High)",
        confidence: "Medium",
        fix_effort: "M",
        framework_mapping: {
          standard: "nist-ssdf",
          control: "Avoid dynamic evaluation"
        },
        evidence: "Detected eval-style usage in source.",
        reproduction_steps: "1. Open file\n2. Inspect sink",
        business_impact: "Can enable severe injection exposure.",
        remediation: "Remove eval."
      }
    ]
  }, null, 2));

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--format",
    "sarif",
    "--output",
    outputFile
  ], { cwd: process.cwd() });

  const sarif = JSON.parse(fs.readFileSync(outputFile, "utf8"));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "security-testing-skill");
  assert.equal(sarif.runs[0].results[0].ruleId, "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/index.js");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
});
