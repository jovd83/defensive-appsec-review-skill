#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = process.cwd();
const PACKAGE_PATH = path.join(ROOT, "package.json");

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

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function runNode(args) {
  const result = spawnSync("node", args, { cwd: ROOT, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `Command failed: node ${args.join(" ")}`);
  }
  return result;
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function gradeScan(outputJson) {
  const findings = outputJson.findings || [];
  const expectations = [
    {
      text: "Findings include hardcoded credential or environment-file exposure",
      passed: findings.some((finding) => /credential|Environment file/i.test(finding.title)),
      evidence: "Checked findings titles for credential or environment-file signals."
    },
    {
      text: "Findings include unsafe HTML rendering detection",
      passed: findings.some((finding) => /Unsafe HTML rendering/i.test(finding.title)),
      evidence: "Checked findings titles for unsafe HTML rendering sink detection."
    },
    {
      text: "Findings include shell-enabled subprocess execution detection",
      passed: findings.some((finding) => /Shell-enabled subprocess execution/i.test(finding.title)),
      evidence: "Checked findings titles for shell-enabled subprocess detection."
    },
    {
      text: "Findings include insecure JWT handling detection",
      passed: findings.some((finding) => /JWT handling/i.test(finding.title)),
      evidence: "Checked findings titles for insecure JWT handling detection."
    },
    {
      text: "Findings include at least one file:line style location",
      passed: findings.some((finding) => typeof finding.location === "string" && finding.location.includes(":")),
      evidence: "Checked findings for at least one file:line style location."
    }
  ];
  return expectations;
}

function gradeMarkdown(markdown) {
  return [
    {
      text: "Markdown report contains the target title",
      passed: /Security Assessment Report - sample-risky-repo/.test(markdown),
      evidence: "Searched report for the target title."
    },
    {
      text: "Markdown report contains location information",
      passed: /Location:/i.test(markdown),
      evidence: "Searched report for a rendered Location field."
    },
    {
      text: "Markdown report contains fix effort information",
      passed: /Fix effort:/i.test(markdown),
      evidence: "Searched report for a rendered Fix effort field."
    }
  ];
}

function gradeHtml(html) {
  return [
    {
      text: "HTML report contains the target title",
      passed: /Security Assessment Report - sample-risky-repo/.test(html),
      evidence: "Searched HTML report for the target title."
    },
    {
      text: "HTML report contains the fixed professional briefing template",
      passed: /Security Assessment Brief/.test(html) && /professional HTML report/i.test(html),
      evidence: "Checked HTML report for the shared template header."
    },
    {
      text: "HTML report contains finding content",
      passed: /Potential hardcoded credential detected/.test(html),
      evidence: "Searched HTML report for a rendered finding title."
    }
  ];
}

function gradeSarif(sarif) {
  return [
    {
      text: "SARIF output uses version 2.1.0",
      passed: sarif.version === "2.1.0",
      evidence: `Observed SARIF version: ${sarif.version}`
    },
    {
      text: "SARIF output contains at least one result",
      passed: Array.isArray(sarif.runs?.[0]?.results) && sarif.runs[0].results.length > 0,
      evidence: `Observed results count: ${sarif.runs?.[0]?.results?.length ?? 0}`
    },
    {
      text: "SARIF output includes file location data",
      passed: Boolean(sarif.runs?.[0]?.results?.[0]?.locations?.[0]?.physicalLocation?.artifactLocation?.uri),
      evidence: "Checked first SARIF result for artifact location URI."
    }
  ];
}

function gradeNormalizedExternal(outputJson) {
  const findings = outputJson.findings || [];
  return [
    {
      text: "Normalized output contains findings",
      passed: findings.length > 0,
      evidence: `Observed normalized findings count: ${findings.length}`
    },
    {
      text: "Normalized output records a source tool",
      passed: findings.some((finding) => typeof finding.source_tool === "string" && finding.source_tool.length > 0),
      evidence: "Checked normalized findings for source_tool values."
    },
    {
      text: "Normalized output preserves framework mapping",
      passed: findings.some((finding) => typeof finding.framework_mapping?.standard === "string" && finding.framework_mapping.standard.length > 0),
      evidence: "Checked normalized findings for framework_mapping.standard."
    }
  ];
}

function summarize(expectations) {
  const passed = expectations.filter((item) => item.passed).length;
  const total = expectations.length;
  const failed = total - passed;
  return {
    passed,
    failed,
    total,
    pass_rate: total ? Number((passed / total).toFixed(2)) : 0
  };
}

function benchmarkRun(evalId, evalName, configuration, summary, durationSeconds) {
  return {
    eval_id: evalId,
    eval_name: evalName,
    configuration,
    run_number: 1,
    result: {
      pass_rate: summary.pass_rate,
      passed: summary.passed,
      failed: summary.failed,
      total: summary.total,
      time_seconds: durationSeconds,
      tokens: 0,
      tool_calls: 1,
      errors: 0
    }
  };
}

function main() {
  const options = parseArgs(process.argv);
  const packageJson = readJson(PACKAGE_PATH);
  const evalsPath = path.resolve(ROOT, options.config || path.join("evals", "local-evals.json"));
  const evalSuite = readJson(evalsPath);
  const workspaceRoot = options.workspace
    ? path.resolve(ROOT, options.workspace)
    : path.resolve(ROOT, "..", `${evalSuite.skill_name}-workspace`);
  const iterationLabel = String(options.iteration || "local-iteration-1");
  const iterationDir = path.join(workspaceRoot, iterationLabel);
  ensureDir(iterationDir);

  const benchmarkRuns = [];
  const notes = [];

  for (const evalItem of evalSuite.evals) {
    const evalDir = path.join(iterationDir, evalItem.name);
    const outputsDir = path.join(evalDir, "outputs");
    ensureDir(outputsDir);

    const started = Date.now();
    let expectations = [];

    if (evalItem.type === "scan") {
      const outputPath = path.join(outputsDir, "findings.json");
      runNode([
        path.join("scripts", "audit-scan.js"),
        "--target",
        evalItem.target,
        "--type",
        evalItem.surface,
        "--standard",
        evalItem.standard,
        "--output",
        outputPath
      ]);
      const outputJson = readJson(outputPath);
      expectations = gradeScan(outputJson);
    } else if (evalItem.type === "report_md") {
      const outputPath = path.join(outputsDir, "report.md");
      runNode([
        path.join("scripts", "generate-report.js"),
        ...evalItem.inputs,
        "--output",
        outputPath
      ]);
      const markdown = fs.readFileSync(outputPath, "utf8");
      expectations = gradeMarkdown(markdown);
    } else if (evalItem.type === "report_sarif") {
      const outputPath = path.join(outputsDir, "report.sarif.json");
      runNode([
        path.join("scripts", "generate-report.js"),
        ...evalItem.inputs,
        "--format",
        "sarif",
        "--output",
        outputPath
      ]);
      const sarif = readJson(outputPath);
      expectations = gradeSarif(sarif);
    } else if (evalItem.type === "report_html") {
      const outputPath = path.join(outputsDir, "report.html");
      runNode([
        path.join("scripts", "generate-report.js"),
        ...evalItem.inputs,
        "--format",
        "html",
        "--output",
        outputPath
      ]);
      const html = fs.readFileSync(outputPath, "utf8");
      expectations = gradeHtml(html);
    } else if (evalItem.type === "normalize_external") {
      const outputPath = path.join(outputsDir, "normalized.json");
      runNode([
        path.join("scripts", "normalize-external-results.js"),
        "--tool",
        evalItem.tool,
        "--input",
        evalItem.input,
        "--target",
        evalItem.target,
        "--type",
        evalItem.surface,
        "--standard",
        evalItem.standard,
        "--output",
        outputPath
      ]);
      const outputJson = readJson(outputPath);
      expectations = gradeNormalizedExternal(outputJson);
    } else {
      throw new Error(`Unsupported eval type: ${evalItem.type}`);
    }

    const durationSeconds = Number(((Date.now() - started) / 1000).toFixed(2));
    const summary = summarize(expectations);

    writeJson(path.join(evalDir, "eval_metadata.json"), {
      eval_id: evalItem.id,
      eval_name: evalItem.name,
      prompt: `Local deterministic eval: ${evalItem.name}`,
      assertions: evalItem.expectations
    });

    writeJson(path.join(evalDir, "grading.json"), {
      expectations,
      summary,
      timing: {
        total_duration_seconds: durationSeconds
      }
    });

    writeJson(path.join(evalDir, "timing.json"), {
      total_tokens: 0,
      duration_ms: Math.round(durationSeconds * 1000),
      total_duration_seconds: durationSeconds
    });

    benchmarkRuns.push(benchmarkRun(evalItem.id, evalItem.name, "with_skill", summary, durationSeconds));
    notes.push(`${evalItem.name}: pass rate ${summary.pass_rate}`);
  }

  const benchmark = {
    metadata: {
      skill_name: evalSuite.skill_name,
      skill_path: ROOT,
      eval_config: path.relative(ROOT, evalsPath).split(path.sep).join("/"),
      workspace_root: workspaceRoot,
      iteration: iterationLabel,
      executor_model: "deterministic-local-harness",
      analyzer_model: "deterministic-local-harness",
      timestamp: new Date().toISOString(),
      evals_run: evalSuite.evals.map((item) => item.id),
      runs_per_configuration: 1,
      version: packageJson.version
    },
    runs: benchmarkRuns,
    run_summary: {
      with_skill: {
        pass_rate: {
          mean: Number((benchmarkRuns.reduce((sum, run) => sum + run.result.pass_rate, 0) / benchmarkRuns.length).toFixed(2)),
          stddev: 0
        },
        time_seconds: {
          mean: Number((benchmarkRuns.reduce((sum, run) => sum + run.result.time_seconds, 0) / benchmarkRuns.length).toFixed(2)),
          stddev: 0
        },
        tokens: {
          mean: 0,
          stddev: 0
        }
      }
    },
    notes
  };

  writeJson(path.join(iterationDir, "benchmark.json"), benchmark);
  fs.writeFileSync(path.join(iterationDir, "benchmark.md"), [
    `# Local Benchmark - ${evalSuite.skill_name}`,
    "",
    `Version: ${packageJson.version}`,
    `Iteration: ${iterationLabel}`,
    "",
    ...benchmarkRuns.map((run) => `- ${run.eval_name}: pass rate ${run.result.pass_rate}, time ${run.result.time_seconds}s`)
  ].join("\n"));

  console.log(`Local eval workspace written to ${iterationDir}`);
}

main();
