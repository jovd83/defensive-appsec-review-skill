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
  assert.ok(Array.isArray(report.findings));
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
  assert.ok(report.findings.every((finding) => typeof finding.location === "string" && finding.location.length > 0));
});
