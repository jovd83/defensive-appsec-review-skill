const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync } = require("node:child_process");

test("run-local-evals generates benchmark and grading artifacts", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-local-evals-"));
  const repoDir = path.join(tempDir, "repo");
  const workspaceDir = path.join(tempDir, "custom-workspace");

  fs.cpSync(process.cwd(), repoDir, { recursive: true });

  execFileSync("node", [
    path.join(repoDir, "scripts", "run-local-evals.js"),
    "--workspace",
    workspaceDir,
    "--iteration",
    "local-iteration-test"
  ], { cwd: repoDir });

  const iterationDir = path.join(workspaceDir, "local-iteration-test");
  const benchmarkPath = path.join(iterationDir, "benchmark.json");
  const gradingPath = path.join(iterationDir, "scan-risky-repo", "grading.json");

  assert.ok(fs.existsSync(benchmarkPath));
  assert.ok(fs.existsSync(gradingPath));

  const benchmark = JSON.parse(fs.readFileSync(benchmarkPath, "utf8"));
  const grading = JSON.parse(fs.readFileSync(gradingPath, "utf8"));

  assert.equal(benchmark.metadata.skill_name, "defensive-appsec-review-skill");
  assert.equal(benchmark.metadata.version, "4.0.0");
  assert.equal(benchmark.metadata.iteration, "local-iteration-test");
  assert.equal(benchmark.metadata.eval_config, "evals/local-evals.json");
  assert.ok(Array.isArray(benchmark.runs));
  assert.ok(grading.summary.total > 0);
});
