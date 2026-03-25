#!/usr/bin/env node

/**
 * Generate a markdown security report from one or more findings JSON files.
 *
 * Usage:
 *   node scripts/generate-report.js sandbox/raw-findings.json sandbox/manual-findings.json --output sandbox/report.md
 */

const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const inputFiles = [];
let output = "final-security-report.md";
let format = "md";

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === "--output") {
    output = args[i + 1];
    i += 1;
    continue;
  }

  if (arg === "--format") {
    format = args[i + 1];
    i += 1;
    continue;
  }

  if (!arg.startsWith("--")) {
    inputFiles.push(arg);
  }
}

if (inputFiles.length === 0) {
  console.error("[-] Provide at least one findings JSON input file.");
  process.exit(1);
}

function readJson(filePath) {
  const absolutePath = path.resolve(process.cwd(), filePath);
  if (!fs.existsSync(absolutePath)) {
    console.warn(`[!] Skipping missing input: ${absolutePath}`);
    return null;
  }

  try {
    return JSON.parse(fs.readFileSync(absolutePath, "utf8"));
  } catch {
    console.warn(`[!] Skipping unreadable JSON: ${absolutePath}`);
    return null;
  }
}

function parseSeverity(cvss) {
  const normalized = String(cvss || "").toLowerCase();
  if (normalized.includes("critical")) return "Critical";
  if (normalized.includes("high")) return "High";
  if (normalized.includes("medium")) return "Medium";
  if (normalized.includes("low")) return "Low";
  return "Informational";
}

function severityWeight(severity) {
  return {
    Critical: 5,
    High: 4,
    Medium: 3,
    Low: 2,
    Informational: 1
  }[severity] || 0;
}

function sarifLevel(severity) {
  return {
    Critical: "error",
    High: "error",
    Medium: "warning",
    Low: "note",
    Informational: "note"
  }[severity] || "note";
}

function renderFinding(finding, index) {
  const severity = parseSeverity(finding.cvss_v4);
  const mapping = finding.framework_mapping || {};

  return [
    `### ${index + 1}. [${severity}] ${finding.title}`,
    "",
    `- Asset: \`${finding.asset || "N/A"}\``,
    `- Location: ${finding.location || "N/A"}`,
    `- Category: ${finding.category || "N/A"}`,
    `- Weakness: ${finding.cwe || "N/A"}`,
    `- Severity: ${finding.cvss_v4 || "N/A"}`,
    `- Confidence: ${finding.confidence || "N/A"}`,
    `- Fix effort: ${finding.fix_effort || "N/A"}`,
    `- Framework mapping: ${mapping.standard ? `${mapping.standard}${mapping.control ? ` - ${mapping.control}` : ""}` : "N/A"}`,
    "",
    `**Evidence**`,
    "",
    "```text",
    finding.evidence || "No evidence provided.",
    "```",
    "",
    `**How to reproduce or verify**`,
    "",
    finding.reproduction_steps || "No reproduction steps provided.",
    "",
    `**Why it matters**`,
    "",
    finding.business_impact || "No impact statement provided.",
    "",
    `**Recommended remediation**`,
    "",
    finding.remediation || "No remediation provided.",
    "",
    "---",
    ""
  ].join("\n");
}

const envelopes = inputFiles
  .map(readJson)
  .filter(Boolean);

const findings = envelopes.flatMap((envelope) =>
  Array.isArray(envelope.findings) ? envelope.findings : Array.isArray(envelope) ? envelope : []
);

const sortedFindings = findings
  .slice()
  .sort((left, right) => severityWeight(parseSeverity(right.cvss_v4)) - severityWeight(parseSeverity(left.cvss_v4)));

const severityCounts = {
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
  Informational: 0
};

for (const finding of sortedFindings) {
  severityCounts[parseSeverity(finding.cvss_v4)] += 1;
}

const primaryMetadata = envelopes.find((envelope) => envelope.metadata)?.metadata || {};
const title = primaryMetadata.target ? `Security Assessment Report - ${primaryMetadata.target}` : "Security Assessment Report";
const standardsApplied = [...new Set(envelopes.map((envelope) => envelope.metadata?.standard).filter(Boolean))];
const surfaces = [...new Set(envelopes.map((envelope) => envelope.metadata?.target_surface).filter(Boolean))];

const resolvedOutput = path.resolve(process.cwd(), output);
fs.mkdirSync(path.dirname(resolvedOutput), { recursive: true });

if (format === "sarif") {
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "security-testing-skill",
            version: "3.1.0",
            informationUri: "https://github.com/jovd83/security-testing-skill",
            rules: sortedFindings.map((finding) => ({
              id: finding.cwe || finding.title,
              name: finding.title,
              shortDescription: {
                text: finding.title
              },
              fullDescription: {
                text: finding.remediation || "No remediation provided."
              },
              properties: {
                category: finding.category,
                severity: parseSeverity(finding.cvss_v4),
                confidence: finding.confidence,
                fix_effort: finding.fix_effort
              }
            }))
          }
        },
        properties: {
          target: primaryMetadata.target || "Not specified",
          target_surface: surfaces,
          standards_applied: standardsApplied
        },
        results: sortedFindings.map((finding) => {
          const severity = parseSeverity(finding.cvss_v4);
          const location = finding.location || finding.asset || "";
          const [uri, lineText] = location.split(":");
          const lineNumber = Number(lineText);
          return {
            ruleId: finding.cwe || finding.title,
            level: sarifLevel(severity),
            message: {
              text: `${finding.title}: ${finding.business_impact || "Security issue detected."}`
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: uri || finding.asset || "."
                  },
                  region: Number.isFinite(lineNumber) ? { startLine: lineNumber } : undefined
                }
              }
            ],
            properties: {
              asset: finding.asset,
              category: finding.category,
              cvss_v4: finding.cvss_v4,
              confidence: finding.confidence,
              remediation: finding.remediation,
              evidence: finding.evidence,
              fix_effort: finding.fix_effort
            }
          };
        })
      }
    ]
  };

  fs.writeFileSync(resolvedOutput, JSON.stringify(sarif, null, 2), "utf8");
} else {
  const reportSections = [
    `# ${title}`,
    "",
    "## Executive Summary",
    "",
    `This report summarizes an authorized, non-destructive security assessment with **${sortedFindings.length}** documented findings. The review emphasized evidence-backed observations and remediation-oriented guidance rather than speculative risk claims.`,
    "",
    "## Scope and Methodology",
    "",
    `- Target: ${primaryMetadata.target || "Not specified"}`,
    `- Surface type: ${surfaces.length ? surfaces.join(", ") : "Not specified"}`,
    `- Standards applied: ${standardsApplied.length ? standardsApplied.join(", ") : "Not specified"}`,
    "- Assessment mode: read-only review with deterministic helper tooling and analyst validation",
    "- Constraints: no destructive testing, no exploit chaining, no claims beyond observed evidence",
    "",
    "## Severity Snapshot",
    "",
    `- Critical: ${severityCounts.Critical}`,
    `- High: ${severityCounts.High}`,
    `- Medium: ${severityCounts.Medium}`,
    `- Low: ${severityCounts.Low}`,
    `- Informational: ${severityCounts.Informational}`,
    "",
    "## Findings",
    "",
    sortedFindings.length
      ? sortedFindings.map(renderFinding).join("\n")
      : "No verified findings were provided in the input files.",
    "",
    "## Recommended Next Steps",
    "",
    "- Validate high-confidence findings in the owning engineering context.",
    "- Prioritize remediation for credential exposure, authorization flaws, and overly broad CI or network permissions first.",
    "- Rerun targeted verification after fixes to confirm closure and identify regressions.",
    "",
    "## Residual Risk and Limitations",
    "",
    "This report reflects the supplied evidence and any deterministic scan results available at generation time. Areas outside the declared scope, runtime-only behavior, environment-specific controls, and exploitability assumptions may require separate manual validation.",
    ""
  ];

  fs.writeFileSync(resolvedOutput, reportSections.join("\n"), "utf8");
}

console.log(`[+] ${format.toUpperCase()} report written to ${resolvedOutput}`);
