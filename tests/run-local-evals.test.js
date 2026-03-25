const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync } = require("node:child_process");

test("run-local-evals generates benchmark and grading artifacts", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-local-evals-"));
  const repoDir = path.join(tempDir, "repo");

  fs.cpSync(process.cwd(), repoDir, { recursive: true });

  execFileSync("node", [
    path.join(repoDir, "scripts", "run-local-evals.js")
  ], { cwd: repoDir });

  const workspaceDir = path.join(tempDir, "security-testing-skill-workspace", "local-iteration-1");
  const benchmarkPath = path.join(workspaceDir, "benchmark.json");
  const gradingPath = path.join(workspaceDir, "scan-risky-repo", "grading.json");

  assert.ok(fs.existsSync(benchmarkPath));
  assert.ok(fs.existsSync(gradingPath));

  const benchmark = JSON.parse(fs.readFileSync(benchmarkPath, "utf8"));
  const grading = JSON.parse(fs.readFileSync(gradingPath, "utf8"));

  assert.equal(benchmark.metadata.skill_name, "security-testing-skill");
  assert.equal(benchmark.metadata.version, "3.1.0");
  assert.ok(Array.isArray(benchmark.runs));
  assert.ok(grading.summary.total > 0);
});
