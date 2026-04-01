#!/usr/bin/env node

/**
 * Generate security reports from one or more findings JSON files.
 *
 * Usage:
 *   node scripts/generate-report.js sandbox/raw-findings.json --output sandbox/report.md
 *   node scripts/generate-report.js sandbox/raw-findings.json --format html --output sandbox/report.html
 *   node scripts/generate-report.js sandbox/raw-findings.json --format sarif --output sandbox/report.sarif.json
 */

const fs = require("fs");
const path = require("path");

const PACKAGE_JSON_PATH = path.resolve(__dirname, "..", "package.json");
const HTML_TEMPLATE_PATH = path.resolve(__dirname, "..", "assets", "report-template.html");
const packageJson = JSON.parse(fs.readFileSync(PACKAGE_JSON_PATH, "utf8"));

const args = process.argv.slice(2);
const inputFiles = [];
let output = "final-security-report.md";
let format = "md";
let baselineInputFile = "";

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === "--output") {
    output = args[index + 1];
    index += 1;
    continue;
  }

  if (arg === "--format") {
    format = String(args[index + 1] || "").toLowerCase();
    index += 1;
    continue;
  }

  if (arg === "--baseline") {
    baselineInputFile = args[index + 1] || "";
    index += 1;
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

function severityTone(severity) {
  return severity.toLowerCase().replace(/\s+/g, "-");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "Not specified";
  }
  return parsed.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function pluralize(word, count) {
  return count === 1 ? word : `${word}s`;
}

function toAnchorSlug(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "section";
}

function getFrameworkAnchor(key) {
  return `framework-${toAnchorSlug(key)}`;
}

function getFindingAnchor(index) {
  return `finding-${index + 1}`;
}

function getCategoryAnchor(category) {
  return `category-${toAnchorSlug(category)}`;
}

function getFindingIdentityKey(finding) {
  const locationPath = String(finding.location || "").split(":")[0];
  const assetOrLocation = finding.asset || locationPath || ".";
  return [
    finding.title || "",
    assetOrLocation,
    finding.cwe || "",
    finding.category || ""
  ]
    .map((value) => String(value).trim().toLowerCase())
    .join("|");
}

function getFindingDisplayLocation(finding) {
  return finding.location || finding.asset || ".";
}

function parseFindingLocation(finding) {
  const explicitLineNumber = Number(finding.line_number);
  if (Number.isFinite(explicitLineNumber) && explicitLineNumber > 0) {
    return {
      asset: finding.asset || String(finding.location || "").replace(/:\d+$/, "") || ".",
      lineNumber: explicitLineNumber
    };
  }

  const location = String(finding.location || finding.asset || ".");
  const match = location.match(/^(.*):(\d+)$/);
  if (!match) {
    return {
      asset: finding.asset || location || ".",
      lineNumber: null
    };
  }

  return {
    asset: match[1] || finding.asset || ".",
    lineNumber: Number(match[2])
  };
}

function getFindingLineNumber(finding) {
  return parseFindingLocation(finding).lineNumber;
}

function getFindingClassOrFile(finding) {
  const parsed = parseFindingLocation(finding);
  if (finding.class_name) {
    return `${finding.class_name} (${parsed.asset || finding.asset || "."})`;
  }
  return parsed.asset || finding.asset || ".";
}

function getFindingFrameworkNavigation(finding) {
  const mapping = finding.framework_mapping || {};
  const targets = [
    { label: "Framework Coverage", anchor: "framework-coverage" }
  ];
  const owaspOnly = (mapping.owasp || []).filter((entry) => !/OWASP ASVS/i.test(entry));
  const asvsEntries = (mapping.asvs || []).length
    ? mapping.asvs
    : (mapping.owasp || []).filter((entry) => /OWASP ASVS/i.test(entry));

  if (mapping.standard) {
    targets.push({ label: "Primary control mapping", anchor: getFrameworkAnchor("primary") });
  }
  if (owaspOnly.length) {
    targets.push({ label: "OWASP", anchor: getFrameworkAnchor("owasp") });
  }
  if (asvsEntries.length) {
    targets.push({ label: "OWASP ASVS", anchor: getFrameworkAnchor("asvs") });
  }
  if ((mapping.nist || []).length) {
    targets.push({ label: "NIST SSDF", anchor: getFrameworkAnchor("nist") });
  }
  if ((mapping.cis || []).length) {
    targets.push({ label: "CIS Controls v8", anchor: getFrameworkAnchor("cis") });
  }
  if ((mapping.scvs || []).length) {
    targets.push({ label: "OWASP SCVS", anchor: getFrameworkAnchor("scvs") });
  }
  if ((mapping.slsa || []).length) {
    targets.push({ label: "SLSA", anchor: getFrameworkAnchor("slsa") });
  }

  return targets.filter((target, index, collection) =>
    collection.findIndex((candidate) => candidate.label === target.label && candidate.anchor === target.anchor) === index
  );
}

function getFindingCategoryNavigation(finding) {
  const category = finding.category && finding.category !== "Assessment Coverage"
    ? finding.category
    : "";
  const targets = [
    { label: "Category Browsing", anchor: "category-browsing" }
  ];

  if (category) {
    targets.push({ label: category, anchor: getCategoryAnchor(category) });
  }

  return targets;
}

function normalizeFindingStatus(status) {
  const normalized = String(status || "").trim().toLowerCase();
  const allowed = new Set(["new", "needs-review", "in-progress", "accepted-risk", "fixed", "deferred"]);
  return allowed.has(normalized) ? normalized : "";
}

function humanizeFindingStatus(status) {
  return {
    "new": "New",
    "needs-review": "Needs review",
    "in-progress": "In progress",
    "accepted-risk": "Accepted risk",
    "fixed": "Fixed",
    "deferred": "Deferred"
  }[normalizeFindingStatus(status)] || "Not set";
}

function listOrFallback(values, fallback) {
  return values.length ? values : [fallback];
}

function replaceTemplateTokens(template, replacements) {
  return Object.entries(replacements).reduce(
    (result, [token, value]) => result.replaceAll(token, value),
    template
  );
}

function getArrayMappingState(entries, emptyMarkdown, emptyHtml) {
  if (Array.isArray(entries) && entries.length) {
    return {
      markdown: entries.join("; "),
      html: entries.map((entry) => `<span class="chip chip-subtle">${escapeHtml(entry)}</span>`).join("")
    };
  }

  return {
    markdown: emptyMarkdown,
    html: emptyHtml
  };
}

function getOwaspMappingState(finding) {
  const mapping = finding.framework_mapping || {};
  const owaspOnly = (mapping.owasp || []).filter((entry) => !/OWASP ASVS/i.test(entry));
  if (owaspOnly.length) {
    return getArrayMappingState(
      owaspOnly,
      "No per-finding OWASP mapping supplied by scanner",
      `<span class="chip chip-subtle">No per-finding OWASP mapping supplied by scanner</span>`
    );
  }

  if (finding.category === "Assessment Coverage") {
    return {
      markdown: "Not applicable for coverage-only finding",
      html: `<span class="chip chip-subtle">Not applicable for coverage-only finding</span>`
    };
  }

  return {
    markdown: "No per-finding OWASP mapping supplied by scanner",
    html: `<span class="chip chip-subtle">No per-finding OWASP mapping supplied by scanner</span>`
  };
}

function getNistMappingState(finding) {
  const mapping = finding.framework_mapping || {};
  return getArrayMappingState(
    mapping.nist,
    "No per-finding NIST mapping supplied by scanner",
    `<span class="chip chip-subtle">No per-finding NIST mapping supplied by scanner</span>`
  );
}

function getAsvsMappingState(finding) {
  const mapping = finding.framework_mapping || {};
  const asvsEntries = (mapping.asvs || []).length
    ? mapping.asvs
    : (mapping.owasp || []).filter((entry) => /OWASP ASVS/i.test(entry));
  return getArrayMappingState(
    asvsEntries,
    "No per-finding ASVS mapping supplied by scanner",
    `<span class="chip chip-subtle">No per-finding ASVS mapping supplied by scanner</span>`
  );
}

function getCisMappingState(finding) {
  const mapping = finding.framework_mapping || {};
  return getArrayMappingState(
    mapping.cis,
    "No per-finding CIS mapping supplied by scanner",
    `<span class="chip chip-subtle">No per-finding CIS mapping supplied by scanner</span>`
  );
}

function getScvsMappingState(finding) {
  const mapping = finding.framework_mapping || {};
  return getArrayMappingState(
    mapping.scvs,
    "No per-finding SCVS mapping supplied by scanner",
    `<span class="chip chip-subtle">No per-finding SCVS mapping supplied by scanner</span>`
  );
}

function getSlsaMappingState(finding) {
  const mapping = finding.framework_mapping || {};
  return getArrayMappingState(
    mapping.slsa,
    "No per-finding SLSA mapping supplied by scanner",
    `<span class="chip chip-subtle">No per-finding SLSA mapping supplied by scanner</span>`
  );
}

function normalizeMappingProvenance(value) {
  return ["supplied", "inferred", "not-recorded"].includes(value) ? value : "not-recorded";
}

function humanizeMappingProvenance(value) {
  return {
    supplied: "supplied explicitly",
    inferred: "inferred by scanner",
    "not-recorded": "not recorded"
  }[normalizeMappingProvenance(value)];
}

function summarizeMappingProvenance(finding) {
  const provenance = finding.framework_mapping?.provenance || {};
  const entries = [
    ["Primary control mapping", provenance.primary],
    ["OWASP", provenance.owasp],
    ["OWASP ASVS", provenance.asvs],
    ["NIST SSDF", provenance.nist],
    ["CIS Controls v8", provenance.cis],
    ["OWASP SCVS", provenance.scvs],
    ["SLSA", provenance.slsa]
  ];

  return {
    markdown: entries.map(([label, value]) => `${label}: ${humanizeMappingProvenance(value)}`).join("; "),
    html: entries
      .map(([label, value]) => `<span class="chip chip-subtle">${escapeHtml(`${label}: ${humanizeMappingProvenance(value)}`)}</span>`)
      .join("")
  };
}

function deriveSammLenses(model) {
  const lenses = [];
  const surfaceSet = new Set(model.surfaces || []);
  const categorySet = new Set(model.findingCategories || []);
  const standardSet = new Set(model.standardsApplied || []);

  if (standardSet.has("owasp-samm") || surfaceSet.has("repo") || surfaceSet.has("pipeline") || surfaceSet.has("mixed")) {
    lenses.push("OWASP SAMM Governance and Verification maturity framing");
  }
  if ([...categorySet].some((category) => /Configuration|Container Security|Infrastructure Security|CI\/CD Security|Supply Chain Security/i.test(category))) {
    lenses.push("OWASP SAMM Implementation and Operations maturity framing");
  }
  if ([...categorySet].some((category) => /Authentication|Authorization|Input Validation|Code Injection Risk|Unsafe Deserialization/i.test(category))) {
    lenses.push("OWASP SAMM Design and Verification maturity framing");
  }

  return [...new Set(lenses)];
}

function deriveFrameworkCoverage(findings) {
  const total = findings.length;
  const severityOrder = ["Critical", "High", "Medium", "Low", "Informational"];
  const drilldownLimit = 8;
  const getOwaspEntries = (finding) =>
    ((finding.framework_mapping || {}).owasp || []).filter((entry) => !/OWASP ASVS/i.test(entry));
  const getAsvsEntries = (finding) => {
    const mapping = finding.framework_mapping || {};
    return (mapping.asvs || []).length
      ? mapping.asvs
      : (mapping.owasp || []).filter((entry) => /OWASP ASVS/i.test(entry));
  };
  const frameworkDefs = [
    {
      key: "primary",
      label: "Primary control mapping",
      extractor: (finding) => {
        const mapping = finding.framework_mapping || {};
        return mapping.standard ? [`${mapping.standard}${mapping.control ? ` - ${mapping.control}` : ""}`] : [];
      }
    },
    { key: "owasp", label: "OWASP", extractor: getOwaspEntries },
    { key: "asvs", label: "OWASP ASVS", extractor: getAsvsEntries },
    { key: "nist", label: "NIST SSDF", extractor: (finding) => (finding.framework_mapping || {}).nist || [] },
    { key: "cis", label: "CIS Controls v8", extractor: (finding) => (finding.framework_mapping || {}).cis || [] },
    { key: "scvs", label: "OWASP SCVS", extractor: (finding) => (finding.framework_mapping || {}).scvs || [] },
    { key: "slsa", label: "SLSA", extractor: (finding) => (finding.framework_mapping || {}).slsa || [] }
  ];

  const items = frameworkDefs.map(({ key, label, extractor }) => {
    const mappedFindings = findings.filter((finding) => extractor(finding).length > 0);
    const mapped = mappedFindings.length;
    const percent = total ? Math.round((mapped / total) * 100) : 0;
    const severityBreakdown = Object.fromEntries(
      severityOrder.map((severity) => [
        severity,
        mappedFindings.filter((finding) => parseSeverity(finding.cvss_v4) === severity).length
      ])
    );
    const provenanceBreakdown = findings.reduce((accumulator, finding) => {
      const provenance = normalizeMappingProvenance(finding.framework_mapping?.provenance?.[key]);
      accumulator[provenance] += 1;
      return accumulator;
    }, {
      supplied: 0,
      inferred: 0,
      "not-recorded": 0
    });
    return {
      key,
      label,
      extractor,
      mapped,
      total,
      percent,
      severityBreakdown,
      provenanceBreakdown,
      summary: `${label}: ${mapped}/${total} findings mapped (${percent}%)`
    };
  });
  const drilldownRows = frameworkDefs.map(({ key, label, extractor }) => {
    const mappedFindings = findings
      .map((finding, index) => ({ finding, index }))
      .filter(({ finding }) => extractor(finding).length > 0);
    const missingFindings = findings
      .map((finding, index) => ({ finding, index }))
      .filter(({ finding }) => extractor(finding).length === 0);
    const summarizeFindings = (entries, emptyText) => {
      const visible = entries.slice(0, drilldownLimit).map(({ finding, index }) => ({
        findingNumber: index + 1,
        title: finding.title || `Untitled finding ${index + 1}`,
        anchor: getFindingAnchor(index)
      }));
      return {
        total: entries.length,
        visible,
        remaining: Math.max(entries.length - visible.length, 0),
        emptyText
      };
    };

    return {
      key,
      label,
      anchor: getFrameworkAnchor(key),
      mapped: summarizeFindings(mappedFindings, "No findings currently use this framework mapping."),
      missing: summarizeFindings(missingFindings, "No findings are currently missing this framework mapping.")
    };
  });

  const findingsWithAnyFramework = findings.filter((finding) => frameworkDefs
    .slice(1)
    .some(({ extractor }) => extractor(finding).length > 0)).length;
  const findingsWithoutAnyFramework = total - findingsWithAnyFramework;
  const priorityGaps = items
    .map((item) => {
      const missingFindings = findings.filter((finding) => item.extractor(finding).length === 0);
      const missing = missingFindings.length;
      const highSeverityMissing = missingFindings.filter((finding) => {
        const severity = parseSeverity(finding.cvss_v4);
        return severity === "Critical" || severity === "High";
      }).length;
      const topCategories = topCountEntries(
        missingFindings.reduce((accumulator, finding) => {
          const category = finding.category || "Unclassified";
          accumulator[category] = (accumulator[category] || 0) + 1;
          return accumulator;
        }, {}),
        2
      ).map((entry) => entry.replace(/: \d+$/, ""));

      return {
        label: item.label,
        missing,
        total,
        highSeverityMissing,
        topCategories,
        summary: `${item.label}: missing on ${missing}/${total} findings, including ${highSeverityMissing} high-severity ${pluralize("finding", highSeverityMissing)}`
      };
    })
    .filter((item) => item.missing > 0)
    .sort((left, right) =>
      right.highSeverityMissing - left.highSeverityMissing ||
      right.missing - left.missing ||
      left.label.localeCompare(right.label))
    .slice(0, 4);
  const frameworkRecommendations = priorityGaps
    .filter((item) => item.label !== "Primary control mapping")
    .slice(0, 3)
    .map((item) => {
      const emphasis = item.highSeverityMissing > 0
        ? `${item.highSeverityMissing} high-severity ${pluralize("finding", item.highSeverityMissing)}`
        : `${item.missing} remaining ${pluralize("finding", item.missing)}`;
      const categoryText = item.topCategories.length
        ? ` Focus on ${item.topCategories.join(" and ")} first.`
        : "";
      return `Backfill ${item.label} mappings first for ${emphasis}.${categoryText}`;
    });

  return {
    items: items.map(({ extractor, ...item }) => item),
    posture: [
      `Findings with any framework lens: ${findingsWithAnyFramework}/${total}`,
      `Findings with a primary control mapping: ${items[0].mapped}/${total}`,
      `Findings without any framework lens: ${findingsWithoutAnyFramework}/${total}`
    ],
    provenanceItems: items.map((item) =>
      `${item.label}: ${item.provenanceBreakdown.supplied} supplied, ${item.provenanceBreakdown.inferred} inferred, ${item.provenanceBreakdown["not-recorded"]} not recorded`
    ),
    priorityGapRows: priorityGaps,
    priorityGaps: priorityGaps.length
      ? priorityGaps.map((item) => item.summary)
      : ["No framework mapping gaps were detected across the reported findings."],
    recommendations: frameworkRecommendations.length
      ? frameworkRecommendations
      : ["Maintain the current framework mapping coverage as new findings are added."],
    severityOrder,
    drilldownRows,
    matrixRows: items.map(({ label, mapped, severityBreakdown, provenanceBreakdown }) => ({
      key: frameworkDefs.find((definition) => definition.label === label)?.key || toAnchorSlug(label),
      anchor: getFrameworkAnchor(frameworkDefs.find((definition) => definition.label === label)?.key || label),
      label,
      mapped,
      severityBreakdown,
      provenanceBreakdown
    }))
  };
}

function deriveCategoryCoverage(findings) {
  const severityOrder = ["Critical", "High", "Medium", "Low", "Informational"];
  const categorizedFindings = findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => finding.category && finding.category !== "Assessment Coverage");
  const groups = [...categorizedFindings.reduce((accumulator, entry) => {
    const key = entry.finding.category;
    if (!accumulator.has(key)) {
      accumulator.set(key, []);
    }
    accumulator.get(key).push(entry);
    return accumulator;
  }, new Map()).entries()]
    .sort((left, right) => right[1].length - left[1].length || left[0].localeCompare(right[0]));

  const items = groups.map(([label, entries]) => {
    const severityBreakdown = Object.fromEntries(
      severityOrder.map((severity) => [
        severity,
        entries.filter(({ finding }) => parseSeverity(finding.cvss_v4) === severity).length
      ])
    );
    return {
      label,
      anchor: getCategoryAnchor(label),
      count: entries.length,
      severityBreakdown,
      summary: `${label}: ${entries.length} ${pluralize("finding", entries.length)}`
    };
  });

  const drilldownRows = groups.map(([label, entries]) => ({
    label,
    anchor: getCategoryAnchor(label),
    count: entries.length,
    findings: entries.map(({ finding, index }) => ({
      findingNumber: index + 1,
      title: finding.title || `Untitled finding ${index + 1}`,
      anchor: getFindingAnchor(index),
      severity: parseSeverity(finding.cvss_v4)
    }))
  }));

  const uncategorizedCount = findings.filter((finding) =>
    !finding.category || finding.category === "Assessment Coverage"
  ).length;

  return {
    items,
    posture: [
      `Distinct security categories: ${items.length}`,
      `Categorized findings: ${categorizedFindings.length}/${findings.length}`,
      `Unclassified or coverage-only findings: ${uncategorizedCount}/${findings.length}`
    ],
    drilldownRows
  };
}

function deriveTopRiskCategories(findings) {
  const severityScore = {
    Critical: 5,
    High: 4,
    Medium: 3,
    Low: 2,
    Informational: 1
  };
  const grouped = [...findings.reduce((accumulator, finding) => {
    const category = finding.category && finding.category !== "Assessment Coverage"
      ? finding.category
      : "";
    if (!category) {
      return accumulator;
    }

    if (!accumulator.has(category)) {
      accumulator.set(category, []);
    }
    accumulator.get(category).push(finding);
    return accumulator;
  }, new Map()).entries()]
    .map(([label, entries]) => {
      const counts = entries.reduce((accumulator, finding) => {
        const severity = parseSeverity(finding.cvss_v4);
        accumulator[severity] = (accumulator[severity] || 0) + 1;
        return accumulator;
      }, {});
      const highestSeverity = ["Critical", "High", "Medium", "Low", "Informational"]
        .find((severity) => counts[severity] > 0) || "Informational";
      const weightedScore = entries.reduce((total, finding) => total + severityScore[parseSeverity(finding.cvss_v4)], 0);
      const topDrivers = ["Critical", "High", "Medium", "Low", "Informational"]
        .filter((severity) => counts[severity] > 0)
        .map((severity) => `${counts[severity]} ${severity}`)
        .join(", ");

      return {
        label,
        anchor: getCategoryAnchor(label),
        count: entries.length,
        highestSeverity,
        weightedScore,
        topDrivers,
        summary: `${label}: ${entries.length} ${pluralize("finding", entries.length)}, highest severity ${highestSeverity}, mix ${topDrivers}`
      };
    })
    .sort((left, right) =>
      right.weightedScore - left.weightedScore ||
      severityWeight(right.highestSeverity) - severityWeight(left.highestSeverity) ||
      right.count - left.count ||
      left.label.localeCompare(right.label))
    .slice(0, 3);

  return grouped.length
    ? grouped
    : [{ label: "No dominant category recorded", anchor: "category-browsing", count: 0, highestSeverity: "Informational", weightedScore: 0, topDrivers: "No categorized findings", summary: "No categorized findings were recorded." }];
}

function deriveTopRiskFrameworks(frameworkCoverage) {
  const grouped = frameworkCoverage.items
    .filter((item) => item.label !== "Primary control mapping")
    .map((item) => {
      const criticalMapped = item.severityBreakdown.Critical || 0;
      const highMapped = item.severityBreakdown.High || 0;
      const weightedMapped =
        criticalMapped * 5 +
        highMapped * 4 +
        (item.severityBreakdown.Medium || 0) * 3 +
        (item.severityBreakdown.Low || 0) * 2 +
        (item.severityBreakdown.Informational || 0);
      const gap = (frameworkCoverage.priorityGapRows || []).find((entry) => entry.label === item.label) || {
        missing: 0,
        highSeverityMissing: 0
      };
      const riskScore = weightedMapped + gap.highSeverityMissing * 5 + gap.missing;
      const mappedDrivers = [];
      if (criticalMapped) {
        mappedDrivers.push(`${criticalMapped} Critical mapped`);
      }
      if (highMapped) {
        mappedDrivers.push(`${highMapped} High mapped`);
      }
      const gapDrivers = [];
      if (gap.highSeverityMissing) {
        gapDrivers.push(`${gap.highSeverityMissing} high-severity gaps`);
      }
      if (gap.missing) {
        gapDrivers.push(`${gap.missing} unmapped findings`);
      }

      return {
        label: item.label,
        anchor: getFrameworkAnchor(item.key || item.label),
        mapped: item.mapped,
        weightedMapped,
        highSeverityMapped: criticalMapped + highMapped,
        highSeverityMissing: gap.highSeverityMissing,
        missing: gap.missing,
        riskScore,
        summary: `${item.label}: ${item.mapped} mapped, ${criticalMapped + highMapped} high-severity mapped, ${gap.highSeverityMissing} high-severity gaps, ${gap.missing} unmapped findings`,
        mappedDrivers: mappedDrivers.length ? mappedDrivers.join(", ") : "no current high-severity mapped exposure",
        gapDrivers: gapDrivers.length ? gapDrivers.join(", ") : "no current mapping gap pressure"
      };
    })
    .sort((left, right) =>
      right.riskScore - left.riskScore ||
      right.highSeverityMissing - left.highSeverityMissing ||
      right.highSeverityMapped - left.highSeverityMapped ||
      left.label.localeCompare(right.label))
    .slice(0, 3);

  return grouped.length
    ? grouped
    : [{ label: "No dominant framework risk recorded", anchor: "framework-coverage", mapped: 0, weightedMapped: 0, highSeverityMapped: 0, highSeverityMissing: 0, missing: 0, riskScore: 0, summary: "No framework exposure or mapping gaps were recorded.", mappedDrivers: "No framework exposure recorded", gapDrivers: "No mapping gaps recorded" }];
}

function derivePriorityTrio(model) {
  const highSeverityTotal = model.severityCounts.Critical + model.severityCounts.High;
  const severityPriority = highSeverityTotal
    ? `Severity: ${highSeverityTotal} high-severity ${pluralize("finding", highSeverityTotal)} need first triage (${model.severityCounts.Critical} Critical, ${model.severityCounts.High} High).`
    : `Severity: no Critical or High findings were recorded in this report.`;
  const topCategory = model.topRiskCategories[0];
  const categoryPriority = topCategory && topCategory.count
    ? `Category: ${topCategory.label} leads with ${topCategory.count} ${pluralize("finding", topCategory.count)} and a ${topCategory.highestSeverity} ceiling.`
    : `Category: no dominant risk category was recorded.`;
  const topFramework = model.topRiskFrameworks[0];
  const frameworkPriority = topFramework && (topFramework.mapped || topFramework.missing)
    ? `Framework: ${topFramework.label} has the strongest pressure with ${topFramework.highSeverityMapped} high-severity mapped and ${topFramework.highSeverityMissing} high-severity gaps.`
    : `Framework: no dominant framework exposure or mapping gap was recorded.`;

  return [severityPriority, categoryPriority, frameworkPriority];
}

function deriveRecommendedFirstAction(model) {
  const highSeverityTotal = model.severityCounts.Critical + model.severityCounts.High;
  const topCategory = model.topRiskCategories[0];
  const topFramework = model.topRiskFrameworks[0];
  const categoryLabel = topCategory && topCategory.count ? topCategory.label : "the leading category";
  const frameworkLabel = topFramework && (topFramework.mapped || topFramework.missing) ? topFramework.label : "the leading framework lens";

  if (highSeverityTotal > 0) {
    return `Validate and triage the ${highSeverityTotal} high-severity ${pluralize("finding", highSeverityTotal)} in ${categoryLabel} first, then close the biggest mapping gap in ${frameworkLabel}.`;
  }

  if (topFramework && topFramework.highSeverityMissing > 0) {
    return `Backfill the highest-pressure framework gap in ${frameworkLabel} first, then review ${categoryLabel} for remediation planning.`;
  }

  if (topCategory && topCategory.count > 0) {
    return `Start with the ${categoryLabel} findings, confirm ownership, and sequence remediation from highest to lowest severity.`;
  }

  return "Start by reviewing the documented scope and telemetry, then confirm whether any manual follow-up is still required.";
}

function deriveWhyThisIsFirst(model) {
  const highSeverityTotal = model.severityCounts.Critical + model.severityCounts.High;
  const topCategory = model.topRiskCategories[0];
  const topFramework = model.topRiskFrameworks[0];
  const categoryLabel = topCategory && topCategory.count ? topCategory.label : "the leading category";
  const frameworkLabel = topFramework && (topFramework.mapped || topFramework.missing) ? topFramework.label : "the leading framework lens";

  if (highSeverityTotal > 0) {
    return `${categoryLabel} currently carries the most urgent business risk, and ${frameworkLabel} adds the strongest framework pressure through mapped exposure or missing high-severity coverage.`;
  }

  if (topFramework && topFramework.highSeverityMissing > 0) {
    return `${frameworkLabel} is the best first target because its mapping gaps are currently larger than the other framework lenses.`;
  }

  if (topCategory && topCategory.count > 0) {
    return `${categoryLabel} is the largest remaining cluster of findings, so working there first is the fastest way to reduce report risk.`;
  }

  return "The report does not show a dominant hotspot, so the best first move is to confirm scope, telemetry, and any remaining blind spots.";
}

function deriveStatusWorkflow(findings) {
  const statuses = ["new", "needs-review", "in-progress", "accepted-risk", "fixed", "deferred"];
  const counts = Object.fromEntries(statuses.map((status) => [status, 0]));
  const owners = {};
  const dueItems = [];

  for (const finding of findings) {
    const status = normalizeFindingStatus(finding.status) || "needs-review";
    counts[status] += 1;
    if (finding.owner) {
      owners[finding.owner] = (owners[finding.owner] || 0) + 1;
    }
    if (finding.due_date) {
      dueItems.push({
        title: finding.title || "Untitled finding",
        dueDate: finding.due_date,
        status,
        owner: finding.owner || "Unassigned"
      });
    }
  }

  dueItems.sort((left, right) => String(left.dueDate).localeCompare(String(right.dueDate)));

  return {
    summaryItems: [
      `New: ${counts.new}`,
      `Needs review: ${counts["needs-review"]}`,
      `In progress: ${counts["in-progress"]}`,
      `Accepted risk: ${counts["accepted-risk"]}`,
      `Fixed: ${counts.fixed}`,
      `Deferred: ${counts.deferred}`
    ],
    ownershipItems: Object.keys(owners).length
      ? topCountEntries(owners, 5).map((entry) => `Owner workload: ${entry}`)
      : ["Owner workload: no finding owners were recorded."],
    dueItems: dueItems.length
      ? dueItems.slice(0, 5).map((item) => `${item.title}: due ${item.dueDate} (${humanizeFindingStatus(item.status)}, owner ${item.owner})`)
      : ["No due dates were recorded for current findings."]
  };
}

function deriveChangeOverTime(currentFindings, baselineEnvelope) {
  if (!baselineEnvelope) {
    return {
      enabled: false,
      summaryItems: [],
      notableItems: [],
      counts: {
        new: 0,
        fixed: 0,
        regressed: 0,
        improved: 0,
        unchanged: 0
      }
    };
  }

  const baselineFindings = Array.isArray(baselineEnvelope.findings)
    ? baselineEnvelope.findings
    : Array.isArray(baselineEnvelope)
      ? baselineEnvelope
      : [];
  const currentGrouped = currentFindings.reduce((accumulator, finding, index) => {
    const key = getFindingIdentityKey(finding);
    if (!accumulator.has(key)) {
      accumulator.set(key, []);
    }
    accumulator.get(key).push({ finding, index });
    return accumulator;
  }, new Map());
  const baselineGrouped = baselineFindings.reduce((accumulator, finding) => {
    const key = getFindingIdentityKey(finding);
    if (!accumulator.has(key)) {
      accumulator.set(key, []);
    }
    accumulator.get(key).push({ finding });
    return accumulator;
  }, new Map());
  const changes = {
    new: [],
    fixed: [],
    regressed: [],
    improved: [],
    unchanged: []
  };

  for (const key of new Set([...currentGrouped.keys(), ...baselineGrouped.keys()])) {
    const currentEntries = (currentGrouped.get(key) || [])
      .slice()
      .sort((left, right) => severityWeight(parseSeverity(right.finding.cvss_v4)) - severityWeight(parseSeverity(left.finding.cvss_v4)));
    const baselineEntries = (baselineGrouped.get(key) || [])
      .slice()
      .sort((left, right) => severityWeight(parseSeverity(right.finding.cvss_v4)) - severityWeight(parseSeverity(left.finding.cvss_v4)));
    const overlap = Math.min(currentEntries.length, baselineEntries.length);

    for (let index = 0; index < overlap; index += 1) {
      const current = currentEntries[index];
      const baseline = baselineEntries[index];
      const currentSeverity = parseSeverity(current.finding.cvss_v4);
      const baselineSeverity = parseSeverity(baseline.finding.cvss_v4);
      const shared = {
        title: current.finding.title || baseline.finding.title || "Untitled finding",
        location: getFindingDisplayLocation(current.finding),
        anchor: getFindingAnchor(current.index),
        currentSeverity,
        baselineSeverity
      };

      if (severityWeight(currentSeverity) > severityWeight(baselineSeverity)) {
        changes.regressed.push(shared);
      } else if (severityWeight(currentSeverity) < severityWeight(baselineSeverity)) {
        changes.improved.push(shared);
      } else {
        changes.unchanged.push(shared);
      }
    }

    for (const entry of currentEntries.slice(overlap)) {
      changes.new.push({
        title: entry.finding.title || "Untitled finding",
        location: getFindingDisplayLocation(entry.finding),
        anchor: getFindingAnchor(entry.index),
        currentSeverity: parseSeverity(entry.finding.cvss_v4)
      });
    }

    for (const entry of baselineEntries.slice(overlap)) {
      changes.fixed.push({
        title: entry.finding.title || "Untitled finding",
        location: getFindingDisplayLocation(entry.finding),
        baselineSeverity: parseSeverity(entry.finding.cvss_v4)
      });
    }
  }

  const counts = {
    new: changes.new.length,
    fixed: changes.fixed.length,
    regressed: changes.regressed.length,
    improved: changes.improved.length,
    unchanged: changes.unchanged.length
  };
  const baselineTarget = baselineEnvelope.metadata?.target || "Not specified";
  const baselineTimestamp = formatDate(baselineEnvelope.metadata?.timestamp);
  const summaryItems = [
    `Baseline target: ${baselineTarget}`,
    `Baseline generated: ${baselineTimestamp}`,
    `New findings: ${counts.new}`,
    `Fixed findings: ${counts.fixed}`,
    `Regressed findings: ${counts.regressed}`,
    `Improved findings: ${counts.improved}`,
    `Unchanged findings: ${counts.unchanged}`
  ];
  const notableItems = [
    ...changes.new.slice(0, 3).map((item) => ({ text: `New: ${item.title} (${item.currentSeverity}) at ${item.location}`, anchor: item.anchor })),
    ...changes.fixed.slice(0, 3).map((item) => ({ text: `Fixed: ${item.title} previously at ${item.location} (${item.baselineSeverity})` })),
    ...changes.regressed.slice(0, 3).map((item) => ({ text: `Regressed: ${item.title} moved from ${item.baselineSeverity} to ${item.currentSeverity} at ${item.location}`, anchor: item.anchor })),
    ...changes.improved.slice(0, 3).map((item) => ({ text: `Improved: ${item.title} moved from ${item.baselineSeverity} to ${item.currentSeverity} at ${item.location}`, anchor: item.anchor }))
  ];

  return {
    enabled: true,
    baselineTarget,
    baselineTimestamp,
    counts,
    summaryItems,
    notableItems
  };
}

function renderMarkdownChangeOverTime(changeOverTime) {
  if (!changeOverTime.enabled) {
    return "";
  }

  const notableLines = changeOverTime.notableItems.length
    ? changeOverTime.notableItems.map((item) =>
      `- ${item.anchor ? `[${item.text}](#${item.anchor})` : item.text}`
    ).join("\n")
    : "- No notable changes were detected between the current report and the baseline.";

  return [
    "## Change Over Time",
    "",
    changeOverTime.summaryItems.map((item) => `- ${item}`).join("\n"),
    "",
    "### Notable Changes",
    "",
    notableLines,
    ""
  ].join("\n");
}

function renderHtmlChangeOverTime(changeOverTime) {
  if (!changeOverTime.enabled) {
    return "";
  }

  const notableItems = changeOverTime.notableItems.length
    ? changeOverTime.notableItems.map((item) => `
          <li class="coverage-item">${item.anchor ? `<a class="anchor-link" href="#${escapeHtml(item.anchor)}">${escapeHtml(item.text)}</a>` : escapeHtml(item.text)}</li>
        `).join("")
    : `<li class="coverage-item">No notable changes were detected between the current report and the baseline.</li>`;

  return `
    <section class="section">
      <div class="section-heading">
        <div>
          <h2>Change Over Time</h2>
          <p>This section compares the current findings against a supplied baseline so new, fixed, regressed, and improved findings are obvious.</p>
        </div>
      </div>
      <div class="two-column">
        <div class="panel">
          <h3>Delta Summary</h3>
          <ul class="coverage-list">${renderHtmlList(changeOverTime.summaryItems, "coverage-item")}</ul>
        </div>
        <div class="panel">
          <h3>Notable Changes</h3>
          <ul class="coverage-list">${notableItems}</ul>
        </div>
      </div>
    </section>
  `;
}

function renderMarkdownFrameworkMatrix(frameworkCoverage) {
  const headers = [
    "Framework",
    ...frameworkCoverage.severityOrder,
    "Mapped total",
    "Supplied",
    "Inferred",
    "Not recorded"
  ];
  const divider = headers.map(() => "---");
  const rows = frameworkCoverage.matrixRows.map((row) => [
    `[${row.label}](#${row.anchor})`,
    ...frameworkCoverage.severityOrder.map((severity) => String(row.severityBreakdown[severity] || 0)),
    String(row.mapped),
    String(row.provenanceBreakdown.supplied || 0),
    String(row.provenanceBreakdown.inferred || 0),
    String(row.provenanceBreakdown["not-recorded"] || 0)
  ]);

  return [
    `| ${headers.join(" | ")} |`,
    `| ${divider.join(" | ")} |`,
    ...rows.map((row) => `| ${row.join(" | ")} |`)
  ].join("\n");
}

function renderMarkdownFrameworkDrilldown(frameworkCoverage) {
  return frameworkCoverage.drilldownRows.map((row) => {
    const renderLinkedFindings = (group) => {
      if (!group.total) {
        return group.emptyText;
      }

      const items = group.visible.map((item) => `[Finding ${item.findingNumber}](#${item.anchor}) ${item.title}`);
      if (group.remaining > 0) {
        items.push(`and ${group.remaining} more ${pluralize("finding", group.remaining)}`);
      }
      return items.join("; ");
    };

    return [
      `### <a id="${row.anchor}"></a>${row.label}`,
      "",
      `- Mapped findings (${row.mapped.total}): ${renderLinkedFindings(row.mapped)}`,
      `- Missing mappings (${row.missing.total}): ${renderLinkedFindings(row.missing)}`,
      ""
    ].join("\n");
  }).join("\n");
}

function renderMarkdownCategoryDrilldown(categoryCoverage) {
  return categoryCoverage.drilldownRows.map((row) => [
    `### <a id="${row.anchor}"></a>${row.label}`,
    "",
    `- Findings in this category (${row.count}): ${row.findings.map((item) => `[Finding ${item.findingNumber}](#${item.anchor}) [${item.severity}] ${item.title}`).join("; ")}`,
    ""
  ].join("\n")).join("\n");
}

function renderHtmlFrameworkMatrix(frameworkCoverage) {
  const headerCells = [
    "Framework",
    ...frameworkCoverage.severityOrder,
    "Mapped total",
    "Supplied",
    "Inferred",
    "Not recorded"
  ]
    .map((label) => `<th>${escapeHtml(label)}</th>`)
    .join("");
  const bodyRows = frameworkCoverage.matrixRows.map((row) => `
      <tr>
        <td><a class="anchor-link" href="#${escapeHtml(row.anchor)}">${escapeHtml(row.label)}</a></td>
        ${frameworkCoverage.severityOrder.map((severity) => `<td>${escapeHtml(row.severityBreakdown[severity] || 0)}</td>`).join("")}
        <td>${escapeHtml(row.mapped)}</td>
        <td>${escapeHtml(row.provenanceBreakdown.supplied || 0)}</td>
        <td>${escapeHtml(row.provenanceBreakdown.inferred || 0)}</td>
        <td>${escapeHtml(row.provenanceBreakdown["not-recorded"] || 0)}</td>
      </tr>
    `).join("");

  return `
    <table class="matrix-table">
      <thead>
        <tr>${headerCells}</tr>
      </thead>
      <tbody>${bodyRows}</tbody>
    </table>
  `;
}

function renderHtmlFrameworkDrilldown(frameworkCoverage) {
  const renderLinkedFindings = (group) => {
    if (!group.total) {
      return `<p class="drilldown-empty">${escapeHtml(group.emptyText)}</p>`;
    }

    const items = group.visible.map((item) => `
      <li class="coverage-item">
        <a class="anchor-link" href="#${escapeHtml(item.anchor)}">Finding ${escapeHtml(item.findingNumber)}</a>
        <span>${escapeHtml(item.title)}</span>
      </li>
    `).join("");
    const more = group.remaining > 0
      ? `<li class="coverage-item">and ${escapeHtml(group.remaining)} more ${escapeHtml(pluralize("finding", group.remaining))}</li>`
      : "";

    return `<ul class="coverage-list">${items}${more}</ul>`;
  };

  return frameworkCoverage.drilldownRows.map((row) => `
    <article class="panel framework-drilldown-card" id="${escapeHtml(row.anchor)}">
      <h3>${escapeHtml(row.label)}</h3>
      <div class="two-column drilldown-columns">
        <div>
          <h4>Mapped findings (${escapeHtml(row.mapped.total)})</h4>
          ${renderLinkedFindings(row.mapped)}
        </div>
        <div>
          <h4>Missing mappings (${escapeHtml(row.missing.total)})</h4>
          ${renderLinkedFindings(row.missing)}
        </div>
      </div>
    </article>
  `).join("");
}

function renderHtmlCategoryDrilldown(categoryCoverage) {
  return categoryCoverage.drilldownRows.map((row) => `
    <article class="panel framework-drilldown-card" id="${escapeHtml(row.anchor)}">
      <h3>${escapeHtml(row.label)}</h3>
      <p class="drilldown-empty">Findings in this category: ${escapeHtml(row.count)}</p>
      <ul class="coverage-list">
        ${row.findings.map((item) => `
          <li class="coverage-item">
            <a class="anchor-link" href="#${escapeHtml(item.anchor)}">Finding ${escapeHtml(item.findingNumber)}</a>
            <span>[${escapeHtml(item.severity)}] ${escapeHtml(item.title)}</span>
          </li>
        `).join("")}
      </ul>
    </article>
  `).join("");
}

function escapeMarkdownTableCell(value) {
  return String(value ?? "")
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, "<br>");
}

function formatComponentObservedVia(item) {
  return [
    item.ecosystem,
    item.manifest_path,
    item.origin
  ].filter(Boolean).join(" / ") || "Not specified";
}

function formatComponentEvidence(item) {
  return `${humanizeEvidenceMode(item.evidence_mode)}; checked ${formatDate(item.checked_at)}`;
}

function renderMarkdownComponentPostureTable(componentPosture) {
  const headers = [
    "Component",
    "Kind",
    "Observed via",
    "Security",
    "Maintenance",
    "Provenance",
    "Overall",
    "Confidence",
    "Evidence",
    "Notes"
  ];
  const divider = headers.map(() => "---");
  const rows = componentPosture.items.map((item) => [
    escapeMarkdownTableCell(item.version ? `${item.name}@${item.version}` : item.name),
    escapeMarkdownTableCell(item.kind),
    escapeMarkdownTableCell(formatComponentObservedVia(item)),
    escapeMarkdownTableCell(humanizeComponentPosture(item.security_posture)),
    escapeMarkdownTableCell(humanizeComponentPosture(item.maintenance_posture)),
    escapeMarkdownTableCell(humanizeComponentPosture(item.provenance_posture)),
    escapeMarkdownTableCell(humanizeComponentPosture(item.review_status)),
    escapeMarkdownTableCell(item.confidence),
    escapeMarkdownTableCell(formatComponentEvidence(item)),
    escapeMarkdownTableCell(item.notes || "No additional notes")
  ]);

  return [
    `| ${headers.join(" | ")} |`,
    `| ${divider.join(" | ")} |`,
    ...rows.map((row) => `| ${row.join(" | ")} |`)
  ].join("\n");
}

function renderHtmlComponentPostureTable(componentPosture) {
  const headerCells = [
    "Component",
    "Kind",
    "Observed via",
    "Security",
    "Maintenance",
    "Provenance",
    "Overall",
    "Confidence",
    "Evidence",
    "Notes"
  ].map((label) => `<th>${escapeHtml(label)}</th>`).join("");

  const bodyRows = componentPosture.items.map((item) => `
      <tr>
        <td>${escapeHtml(item.version ? `${item.name}@${item.version}` : item.name)}</td>
        <td>${escapeHtml(item.kind)}</td>
        <td>${escapeHtml(formatComponentObservedVia(item))}</td>
        <td>${escapeHtml(humanizeComponentPosture(item.security_posture))}</td>
        <td>${escapeHtml(humanizeComponentPosture(item.maintenance_posture))}</td>
        <td>${escapeHtml(humanizeComponentPosture(item.provenance_posture))}</td>
        <td>${escapeHtml(humanizeComponentPosture(item.review_status))}</td>
        <td>${escapeHtml(item.confidence)}</td>
        <td>${escapeHtml(formatComponentEvidence(item))}</td>
        <td>${escapeHtml(item.notes || "No additional notes")}</td>
      </tr>
    `).join("");

  return `
    <table class="matrix-table">
      <thead>
        <tr>${headerCells}</tr>
      </thead>
      <tbody>${bodyRows}</tbody>
    </table>
  `;
}

function renderMarkdownFinding(finding, index) {
  const severity = parseSeverity(finding.cvss_v4);
  const mapping = finding.framework_mapping || {};
  const status = humanizeFindingStatus(finding.status);
  const categoryNavigation = getFindingCategoryNavigation(finding)
    .map((item) => `[${item.label}](#${item.anchor})`)
    .join("; ");
  const frameworkNavigation = getFindingFrameworkNavigation(finding)
    .map((item) => `[${item.label}](#${item.anchor})`)
    .join("; ");
  const asvsMapping = getAsvsMappingState(finding).markdown;
  const nistMapping = getNistMappingState(finding).markdown;
  const cisMapping = getCisMappingState(finding).markdown;
  const scvsMapping = getScvsMappingState(finding).markdown;
  const slsaMapping = getSlsaMappingState(finding).markdown;
  const owaspMapping = getOwaspMappingState(finding).markdown;
  const mappingProvenance = summarizeMappingProvenance(finding).markdown;
  const primaryFrameworkMapping = mapping.standard
    ? `${mapping.standard}${mapping.control ? ` - ${mapping.control}` : ""}`
    : "";
  const lineNumber = getFindingLineNumber(finding);
  const codeSnippet = finding.code_snippet || "Code snippet not provided.";

  return [
    `<a id="${getFindingAnchor(index)}"></a>`,
    `### ${index + 1}. [${severity}] ${finding.title}`,
    "",
    `- Asset: \`${getFindingMetaValue("Asset", finding.asset)}\``,
    `- Class/file: ${getFindingMetaValue("Asset", getFindingClassOrFile(finding))}`,
    `- Location: ${getFindingMetaValue("Location", finding.location)}`,
    `- Line number: ${lineNumber || "Not specified"}`,
    `- Category: ${getFindingMetaValue("Category", finding.category)}`,
    `- Weakness: ${getFindingMetaValue("Weakness", finding.cwe)}`,
    `- Severity: ${getFindingMetaValue("Severity", finding.cvss_v4)}`,
    `- Confidence: ${getFindingMetaValue("Confidence", finding.confidence)}`,
    `- Status: ${status}`,
    `- Owner: ${getFindingMetaValue("Owner", finding.owner)}`,
    `- Due date: ${getFindingMetaValue("Due date", finding.due_date)}`,
    `- Fix effort: ${getFindingMetaValue("Fix effort", finding.fix_effort)}`,
    `- Source tool: ${finding.source_tool || "native-heuristic-scan"}`,
    `- Framework mapping: ${getFindingMetaValue("Framework mapping", primaryFrameworkMapping)}`,
    `- Category navigation: ${categoryNavigation}`,
    `- Framework navigation: ${frameworkNavigation}`,
    `- Mapping provenance: ${mappingProvenance}`,
    `- ASVS mapping: ${asvsMapping}`,
    `- NIST mapping: ${nistMapping}`,
    `- CIS mapping: ${cisMapping}`,
    `- SCVS mapping: ${scvsMapping}`,
    `- SLSA mapping: ${slsaMapping}`,
    `- OWASP mapping: ${owaspMapping}`,
    `- Verification tier: ${getFindingMetaValue("Verification tier", finding.verification_tier)}`,
    "",
    "**Evidence**",
    "",
    "```text",
    finding.evidence || "No evidence provided.",
    "```",
    "",
    "**Problematic code**",
    "",
    "```text",
    codeSnippet,
    "```",
    "",
    "**How to reproduce or verify**",
    "",
    finding.reproduction_steps || "No reproduction steps provided.",
    "",
    "**Why it matters**",
    "",
    finding.business_impact || "No impact statement provided.",
    "",
    "**Recommended remediation**",
    "",
    finding.remediation || "No remediation provided.",
    "",
    "---",
    ""
  ].join("\n");
}

function renderHtmlList(items, className) {
  return items.map((item) => `<li class="${className}">${escapeHtml(item)}</li>`).join("");
}

function formatListInline(values, fallback = "Not specified") {
  return values.length ? values.join(", ") : fallback;
}

function getFindingMetaFallback(label) {
  const fallbackByLabel = {
    Asset: "Not specified",
    Location: "Not specified",
    Category: "Not classified",
    Weakness: "Not mapped",
    Severity: "Not scored",
    Confidence: "Not specified",
    Status: "Not set",
    Owner: "Unassigned",
    "Due date": "Not scheduled",
    "Fix effort": "Not estimated",
    "Framework mapping": "No primary framework mapping supplied by scanner",
    "Verification tier": "Not specified"
  };

  return fallbackByLabel[label] || "Not specified";
}

function getFindingMetaValue(label, value) {
  if (value === undefined || value === null || value === "") {
    return getFindingMetaFallback(label);
  }

  return value;
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "Not specified";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function topCountEntries(countMap, limit = 5) {
  return Object.entries(countMap || {})
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([label, count]) => `${label}: ${count}`);
}

function normalizeComponentPosture(value) {
  return ["favorable", "caution", "concern", "unknown"].includes(value) ? value : "unknown";
}

function humanizeComponentPosture(value) {
  return {
    favorable: "Favorable",
    caution: "Caution",
    concern: "Concern",
    unknown: "Unknown"
  }[normalizeComponentPosture(value)];
}

function componentKnowledgeWeight(value) {
  return {
    concern: 4,
    caution: 3,
    favorable: 2,
    unknown: 1
  }[normalizeComponentPosture(value)] || 0;
}

function componentDisplayWeight(value) {
  return {
    concern: 4,
    caution: 3,
    unknown: 2,
    favorable: 1
  }[normalizeComponentPosture(value)] || 0;
}

function componentKindWeight(value) {
  return {
    library: 4,
    tool: 3,
    source: 2,
    "analysis-source": 1
  }[String(value || "").trim()] || 0;
}

function normalizeEvidenceMode(value) {
  return ["offline-only", "live", "mixed"].includes(value) ? value : "offline-only";
}

function humanizeEvidenceMode(value) {
  return {
    "offline-only": "Offline-only",
    "live": "Live",
    "mixed": "Mixed"
  }[normalizeEvidenceMode(value)];
}

function confidenceWeight(value) {
  return {
    High: 3,
    Medium: 2,
    Low: 1
  }[value] || 0;
}

function normalizeComponentItem(item, fallbackCheckedAt) {
  const security = normalizeComponentPosture(item.security_posture);
  const maintenance = normalizeComponentPosture(item.maintenance_posture);
  const provenance = normalizeComponentPosture(item.provenance_posture);
  const explicitOverall = normalizeComponentPosture(item.review_status);
  const derivedOverall = [security, maintenance, provenance]
    .sort((left, right) => componentKnowledgeWeight(right) - componentKnowledgeWeight(left))[0] || "unknown";

  return {
    name: String(item.name || "").trim(),
    version: String(item.version || "").trim(),
    kind: String(item.kind || "library").trim() || "library",
    ecosystem: String(item.ecosystem || "").trim(),
    manifest_path: String(item.manifest_path || "").trim(),
    origin: String(item.origin || "").trim(),
    review_status: explicitOverall !== "unknown" ? explicitOverall : derivedOverall,
    security_posture: security,
    maintenance_posture: maintenance,
    provenance_posture: provenance,
    confidence: ["High", "Medium", "Low"].includes(item.confidence) ? item.confidence : "Low",
    evidence_mode: normalizeEvidenceMode(item.evidence_mode),
    checked_at: item.checked_at || fallbackCheckedAt,
    evidence_sources: [...new Set((item.evidence_sources || []).filter(Boolean))],
    notes: String(item.notes || "").trim()
  };
}

function mergeComponentItem(current, incoming) {
  const combinedEvidenceMode = current.evidence_mode === incoming.evidence_mode
    ? current.evidence_mode
    : "mixed";
  const currentCheckedAt = new Date(current.checked_at || 0).getTime();
  const incomingCheckedAt = new Date(incoming.checked_at || 0).getTime();

  return {
    ...current,
    version: current.version || incoming.version,
    ecosystem: current.ecosystem || incoming.ecosystem,
    manifest_path: current.manifest_path || incoming.manifest_path,
    origin: [current.origin, incoming.origin].filter(Boolean).join("; "),
    review_status: componentKnowledgeWeight(incoming.review_status) > componentKnowledgeWeight(current.review_status)
      ? incoming.review_status
      : current.review_status,
    security_posture: componentKnowledgeWeight(incoming.security_posture) > componentKnowledgeWeight(current.security_posture)
      ? incoming.security_posture
      : current.security_posture,
    maintenance_posture: componentKnowledgeWeight(incoming.maintenance_posture) > componentKnowledgeWeight(current.maintenance_posture)
      ? incoming.maintenance_posture
      : current.maintenance_posture,
    provenance_posture: componentKnowledgeWeight(incoming.provenance_posture) > componentKnowledgeWeight(current.provenance_posture)
      ? incoming.provenance_posture
      : current.provenance_posture,
    confidence: confidenceWeight(incoming.confidence) > confidenceWeight(current.confidence)
      ? incoming.confidence
      : current.confidence,
    evidence_mode: combinedEvidenceMode,
    checked_at: incomingCheckedAt > currentCheckedAt ? incoming.checked_at : current.checked_at,
    evidence_sources: [...new Set([...(current.evidence_sources || []), ...(incoming.evidence_sources || [])])],
    notes: [...new Set([current.notes, incoming.notes].filter(Boolean))].join(" ")
  };
}

function componentKey(item) {
  return [
    String(item.kind || "").toLowerCase(),
    String(item.ecosystem || "").toLowerCase(),
    String(item.name || "").toLowerCase(),
    String(item.version || "").toLowerCase(),
    String(item.manifest_path || "").toLowerCase()
  ].join("|");
}

function findingSignalsDependencyRisk(finding) {
  const sourceTool = String(finding.source_tool || "").toLowerCase();
  return /Dependency Security|Supply Chain Security/i.test(String(finding.category || "")) ||
    /vulnerable and outdated components|dependency|advisory/i.test(String(finding.title || "")) ||
    ["trivy", "osv-scanner", "dependency-check"].includes(sourceTool);
}

function findingMentionsComponent(finding, item) {
  if (!item.name || item.kind === "analysis-source") {
    return false;
  }

  const name = item.name.toLowerCase();
  const title = String(finding.title || "").toLowerCase();
  const asset = String(finding.asset || "").toLowerCase();
  return asset === name ||
    asset.endsWith(`/${name}`) ||
    asset.includes(`${name}@`) ||
    title.includes(` in ${name}`) ||
    title.includes(`${name} `) ||
    title.endsWith(name);
}

function hasMeaningfulComponentSignal(item) {
  return [
    item.review_status,
    item.security_posture,
    item.maintenance_posture,
    item.provenance_posture
  ].some((value) => normalizeComponentPosture(value) !== "unknown");
}

function deriveComponentPosture(envelopes, findings, sourceTools, fallbackCheckedAt) {
  const inventory = new Map();
  const explicitItems = envelopes.flatMap((envelope) => envelope.metadata?.component_posture || []);

  for (const rawItem of explicitItems) {
    const item = normalizeComponentItem(rawItem, fallbackCheckedAt);
    if (!item.name) {
      continue;
    }
    const key = componentKey(item);
    inventory.set(key, inventory.has(key) ? mergeComponentItem(inventory.get(key), item) : item);
  }

  for (const sourceTool of sourceTools) {
    const fallbackItem = normalizeComponentItem({
      name: sourceTool,
      kind: "analysis-source",
      ecosystem: "report-source",
      origin: "findings metadata",
      review_status: "unknown",
      security_posture: "unknown",
      maintenance_posture: "unknown",
      provenance_posture: "unknown",
      confidence: "Low",
      evidence_mode: "offline-only",
      checked_at: fallbackCheckedAt,
      evidence_sources: [sourceTool],
      notes: "Observed as an analysis source for this report. Unknown means the report did not verify whether the tool itself is favorable or unfavorable."
    }, fallbackCheckedAt);
    const key = componentKey(fallbackItem);
    if (!inventory.has(key)) {
      inventory.set(key, fallbackItem);
    }
  }

  const annotatedItems = [...inventory.values()].map((item) => {
    const relatedFindings = findings.filter((finding) =>
      findingSignalsDependencyRisk(finding) && findingMentionsComponent(finding, item));

    if (!relatedFindings.length) {
      return item;
    }

    const highestSeverity = relatedFindings
      .map((finding) => parseSeverity(finding.cvss_v4))
      .sort((left, right) => severityWeight(right) - severityWeight(left))[0];
    const derivedStatus = severityWeight(highestSeverity) >= severityWeight("High") ? "concern" : "caution";
    return {
      ...item,
      review_status: componentKnowledgeWeight(derivedStatus) > componentKnowledgeWeight(item.review_status)
        ? derivedStatus
        : item.review_status,
      security_posture: componentKnowledgeWeight(derivedStatus) > componentKnowledgeWeight(item.security_posture)
        ? derivedStatus
        : item.security_posture,
      confidence: confidenceWeight("Medium") > confidenceWeight(item.confidence)
        ? "Medium"
        : item.confidence,
      evidence_sources: [...new Set([
        ...(item.evidence_sources || []),
        ...relatedFindings.map((finding) => finding.source_tool || "native-heuristic-scan")
      ])],
      notes: [
        item.notes,
        `${relatedFindings.length} dependency-related ${pluralize("finding", relatedFindings.length)} referenced this component in the current evidence.`
      ].filter(Boolean).join(" ")
    };
  });
  const inventoryOnlyCount = annotatedItems.filter((item) =>
    !hasMeaningfulComponentSignal(item) &&
    !/dependency-related finding referenced this component/i.test(String(item.notes || ""))
  ).length;
  const items = annotatedItems.filter((item) =>
    item.kind !== "analysis-source" &&
    (hasMeaningfulComponentSignal(item) ||
      /dependency-related finding referenced this component/i.test(String(item.notes || "")))
  );

  const statusCounts = items.reduce((accumulator, item) => {
    const key = normalizeComponentPosture(item.review_status);
    accumulator[key] += 1;
    return accumulator;
  }, {
    favorable: 0,
    caution: 0,
    concern: 0,
    unknown: 0
  });
  const evidenceModeCounts = items.reduce((accumulator, item) => {
    const key = normalizeEvidenceMode(item.evidence_mode);
    accumulator[key] += 1;
    return accumulator;
  }, {
    "offline-only": 0,
    live: 0,
    mixed: 0
  });

  return {
    note: items.length
      ? "Unknown means insufficient evidence. The report does not treat unknown as favorable or unfavorable by default."
      : "Component inventory was observed, but no security, maintenance, or provenance posture signals were available. Inventory-only rows are omitted to reduce noise.",
    items: items.sort((left, right) =>
      componentDisplayWeight(right.review_status) - componentDisplayWeight(left.review_status) ||
      componentKindWeight(right.kind) - componentKindWeight(left.kind) ||
      left.name.localeCompare(right.name)),
    emptyStateText: items.length
      ? "No component posture rows were available."
      : "Only inventory-level component evidence was found for this report, so the posture table is omitted until stronger signals are available.",
    summaryItems: [
      `Rows reviewed: ${items.length}`,
      `Inventory-only rows omitted: ${inventoryOnlyCount}`,
      `Concern: ${statusCounts.concern}`,
      `Caution: ${statusCounts.caution}`,
      `Unknown: ${statusCounts.unknown}`,
      `Favorable: ${statusCounts.favorable}`,
      `Evidence modes: Offline-only ${evidenceModeCounts["offline-only"]}, Live ${evidenceModeCounts.live}, Mixed ${evidenceModeCounts.mixed}`
    ],
    followUpItems: [
      statusCounts.concern
        ? `Review ${statusCounts.concern} component ${pluralize("row", statusCounts.concern)} marked Concern first, especially any runtime libraries tied to dependency findings.`
        : "No component rows were marked Concern in this run.",
      statusCounts.unknown
        ? `Treat ${statusCounts.unknown} Unknown component ${pluralize("row", statusCounts.unknown)} as insufficiently verified rather than approved.`
        : "No component rows remained Unknown after the supplied evidence was merged.",
      inventoryOnlyCount
        ? `${inventoryOnlyCount} inventory-only component ${pluralize("row", inventoryOnlyCount)} were omitted because the evidence did not justify a posture verdict.`
        : "No inventory-only component rows were omitted."
    ]
  };
}

function mergeTelemetry(envelopes) {
  const telemetryItems = envelopes
    .map((envelope) => envelope.metadata?.scan_telemetry)
    .filter(Boolean);

  if (!telemetryItems.length) {
    return null;
  }

  const merged = {
    scan_depth: "quick",
    files_discovered: 0,
    files_scanned: 0,
    bytes_scanned: 0,
    heuristic_checks_run: 0,
    manifests_detected: 0,
    directories_skipped: 0,
    elapsed_ms: 0,
    skipped_files: {
      support_material: 0,
      oversized: 0,
      unreadable: 0
    },
    skipped_directories: [],
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

  for (const telemetry of telemetryItems) {
    if (telemetry.scan_depth === "deep") {
      merged.scan_depth = "deep";
    }
    merged.files_discovered += Number(telemetry.files_discovered || 0);
    merged.files_scanned += Number(telemetry.files_scanned || 0);
    merged.bytes_scanned += Number(telemetry.bytes_scanned || 0);
    merged.heuristic_checks_run += Number(telemetry.heuristic_checks_run || 0);
    merged.manifests_detected += Number(telemetry.manifests_detected || 0);
    merged.directories_skipped += Number(telemetry.directories_skipped || 0);
    merged.elapsed_ms += Number(telemetry.elapsed_ms || 0);
    merged.external_findings_imported += Number(telemetry.external_findings_imported || 0);

    for (const key of ["external_inputs_provided", "autodiscovered_external_inputs"]) {
      for (const item of telemetry[key] || []) {
        if (!merged[key].includes(item) && merged[key].length < 10) {
          merged[key].push(item);
        }
      }
    }

    for (const key of ["external_sources_loaded", "external_sources_failed"]) {
      for (const item of telemetry[key] || []) {
        const serialized = JSON.stringify(item);
        if (!merged[key].some((entry) => JSON.stringify(entry) === serialized) && merged[key].length < 10) {
          merged[key].push(item);
        }
      }
    }

    for (const key of Object.keys(merged.skipped_files)) {
      merged.skipped_files[key] += Number(telemetry.skipped_files?.[key] || 0);
      for (const example of telemetry.skipped_file_examples?.[key] || []) {
        if (!merged.skipped_file_examples[key].includes(example) && merged.skipped_file_examples[key].length < 5) {
          merged.skipped_file_examples[key].push(example);
        }
      }
    }

    for (const directory of telemetry.skipped_directories || []) {
      if (!merged.skipped_directories.includes(directory) && merged.skipped_directories.length < 5) {
        merged.skipped_directories.push(directory);
      }
    }

    for (const [label, count] of Object.entries(telemetry.findings_by_rule || {})) {
      merged.findings_by_rule[label] = (merged.findings_by_rule[label] || 0) + count;
    }

    for (const [label, count] of Object.entries(telemetry.findings_by_category || {})) {
      merged.findings_by_category[label] = (merged.findings_by_category[label] || 0) + count;
    }
  }

  return merged;
}

function renderFindingHtml(finding, index) {
  const severity = parseSeverity(finding.cvss_v4);
  const tone = severityTone(severity);
  const mapping = finding.framework_mapping || {};
  const status = humanizeFindingStatus(finding.status);
  const categoryNavigation = getFindingCategoryNavigation(finding)
    .map((item) => `<a class="chip chip-subtle anchor-chip" href="#${escapeHtml(item.anchor)}">${escapeHtml(item.label)}</a>`)
    .join("");
  const frameworkNavigation = getFindingFrameworkNavigation(finding)
    .map((item) => `<a class="chip chip-subtle anchor-chip" href="#${escapeHtml(item.anchor)}">${escapeHtml(item.label)}</a>`)
    .join("");
  const asvsMapping = getAsvsMappingState(finding).html;
  const nistMapping = getNistMappingState(finding).html;
  const cisMapping = getCisMappingState(finding).html;
  const scvsMapping = getScvsMappingState(finding).html;
  const slsaMapping = getSlsaMappingState(finding).html;
  const owaspMapping = getOwaspMappingState(finding).html;
  const mappingProvenance = summarizeMappingProvenance(finding).html;
  const primaryFrameworkMapping = mapping.standard
    ? `${mapping.standard}${mapping.control ? ` - ${mapping.control}` : ""}`
    : "";
  const lineNumber = getFindingLineNumber(finding);
  const codeSnippet = finding.code_snippet || "Code snippet not provided.";

  const metaItems = [
    ["Asset", getFindingMetaValue("Asset", finding.asset)],
    ["Class/file", getFindingClassOrFile(finding)],
    ["Location", getFindingMetaValue("Location", finding.location)],
    ["Line number", lineNumber || "Not specified"],
    ["Category", getFindingMetaValue("Category", finding.category)],
    ["Weakness", getFindingMetaValue("Weakness", finding.cwe)],
    ["Severity", getFindingMetaValue("Severity", finding.cvss_v4)],
    ["Confidence", getFindingMetaValue("Confidence", finding.confidence)],
    ["Status", status],
    ["Owner", getFindingMetaValue("Owner", finding.owner)],
    ["Due date", getFindingMetaValue("Due date", finding.due_date)],
    ["Fix effort", getFindingMetaValue("Fix effort", finding.fix_effort)],
    ["Source tool", finding.source_tool || "native-heuristic-scan"],
    ["Framework mapping", getFindingMetaValue("Framework mapping", primaryFrameworkMapping)],
    ["Verification tier", getFindingMetaValue("Verification tier", finding.verification_tier)]
  ].map(([label, value]) => `
    <div class="definition">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(value)}</dd>
    </div>
  `).join("");

  const references = (finding.references || []).length
    ? `<div class="finding-block">
        <h4>References</h4>
        <ul class="reference-list">${renderHtmlList(finding.references || [], "reference-item")}</ul>
      </div>`
    : "";

  return `
    <article class="finding-card severity-${tone}" id="${escapeHtml(getFindingAnchor(index))}">
      <div class="finding-header">
        <div class="finding-kicker">Finding ${index + 1}</div>
        <div class="finding-title-row">
          <h3>${escapeHtml(finding.title)}</h3>
          <span class="severity-pill severity-pill-${tone}">${escapeHtml(severity)}</span>
        </div>
      </div>
      <dl class="definition-grid">
        ${metaItems}
      </dl>
      <div class="finding-block">
        <h4>Category navigation</h4>
        <div class="chip-row">${categoryNavigation}</div>
      </div>
      <div class="finding-block">
        <h4>Framework navigation</h4>
        <div class="chip-row">${frameworkNavigation}</div>
      </div>
      <div class="finding-block">
        <h4>ASVS mapping</h4>
        <div class="chip-row">${asvsMapping}</div>
      </div>
      <div class="finding-block">
        <h4>Mapping provenance</h4>
        <div class="chip-row">${mappingProvenance}</div>
      </div>
      <div class="finding-block">
        <h4>NIST mapping</h4>
        <div class="chip-row">${nistMapping}</div>
      </div>
      <div class="finding-block">
        <h4>CIS mapping</h4>
        <div class="chip-row">${cisMapping}</div>
      </div>
      <div class="finding-block">
        <h4>SCVS mapping</h4>
        <div class="chip-row">${scvsMapping}</div>
      </div>
      <div class="finding-block">
        <h4>SLSA mapping</h4>
        <div class="chip-row">${slsaMapping}</div>
      </div>
      <div class="finding-block">
        <h4>OWASP mapping</h4>
        <div class="chip-row">${owaspMapping}</div>
      </div>
      <div class="finding-block">
        <h4>Evidence</h4>
        <pre class="evidence-block"><code>${escapeHtml(finding.evidence || "No evidence provided.")}</code></pre>
      </div>
      <div class="finding-block">
        <h4>Problematic code</h4>
        <pre class="evidence-block"><code>${escapeHtml(codeSnippet)}</code></pre>
      </div>
      <div class="finding-two-up">
        <div class="finding-block">
          <h4>How to reproduce or verify</h4>
          <p>${escapeHtml(finding.reproduction_steps || "No reproduction steps provided.").replace(/\n/g, "<br>")}</p>
        </div>
        <div class="finding-block">
          <h4>Why it matters</h4>
          <p>${escapeHtml(finding.business_impact || "No impact statement provided.")}</p>
        </div>
      </div>
      <div class="finding-block">
        <h4>Recommended remediation</h4>
        <p>${escapeHtml(finding.remediation || "No remediation provided.")}</p>
      </div>
      ${references}
    </article>
  `;
}

function buildReportModel(envelopes, baselineEnvelope) {
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
  const standardsApplied = [...new Set(envelopes.map((envelope) => envelope.metadata?.standard).filter(Boolean))];
  const surfaces = [...new Set(envelopes.map((envelope) => envelope.metadata?.target_surface).filter(Boolean))];
  const coverageAreas = [...new Set(envelopes.flatMap((envelope) => envelope.metadata?.coverage_areas || []).filter(Boolean))];
  const blindSpots = [...new Set(envelopes.flatMap((envelope) => envelope.metadata?.blind_spots || []).filter(Boolean))];
  const sourceTools = [...new Set([
    ...envelopes.flatMap((envelope) => envelope.metadata?.source_tools || []),
    ...sortedFindings.map((finding) => finding.source_tool).filter(Boolean)
  ])];
  const verificationTiers = [...new Set(sortedFindings.map((finding) => finding.verification_tier).filter(Boolean))];
  const findingCategories = [...new Set(
    sortedFindings
      .map((finding) => finding.category)
      .filter((category) => Boolean(category) && category !== "Assessment Coverage")
  )];
  const reviewedAssets = [...new Set(
    sortedFindings
      .map((finding) => finding.asset)
      .filter((asset) => Boolean(asset) && asset !== ".")
  )];
  const scanTelemetry = mergeTelemetry(envelopes);

  const title = primaryMetadata.target
    ? `Security Assessment Report - ${primaryMetadata.target}`
    : "Security Assessment Report";
  const findingsText = sortedFindings.length
    ? `with ${sortedFindings.length} documented ${pluralize("finding", sortedFindings.length)}`
    : "with no verified findings";
  const summary = `This report summarizes an authorized, non-destructive security assessment ${findingsText}. The review emphasized evidence-backed observations, clear remediation, and explicit limits on what static review can prove on its own.`;

  const model = {
    title,
    summary,
    primaryMetadata,
    standardsApplied,
    surfaces,
    coverageAreas,
    blindSpots,
    sourceTools,
    verificationTiers,
    findingCategories,
    reviewedAssets,
    topRiskCategories: [],
    topRiskFrameworks: [],
    priorityTrio: [],
    recommendedFirstAction: "",
    whyThisIsFirst: "",
    changeOverTime: { enabled: false, summaryItems: [], notableItems: [], counts: { new: 0, fixed: 0, regressed: 0, improved: 0, unchanged: 0 } },
    statusWorkflow: { summaryItems: [], ownershipItems: [], dueItems: [] },
    categoryCoverage: { items: [], posture: [], drilldownRows: [] },
    frameworkCoverage: { items: [], posture: [], provenanceItems: [], priorityGapRows: [], priorityGaps: [], recommendations: [], severityOrder: [], drilldownRows: [], matrixRows: [] },
    componentPosture: { note: "", items: [], summaryItems: [], followUpItems: [], emptyStateText: "" },
    sammLenses: [],
    scanTelemetry,
    sortedFindings,
    severityCounts,
    generatedAt: new Date().toISOString()
  };

  model.sammLenses = deriveSammLenses(model);
  model.topRiskCategories = deriveTopRiskCategories(sortedFindings);
  model.categoryCoverage = deriveCategoryCoverage(sortedFindings);
  model.frameworkCoverage = deriveFrameworkCoverage(sortedFindings);
  model.topRiskFrameworks = deriveTopRiskFrameworks(model.frameworkCoverage);
  model.componentPosture = deriveComponentPosture(envelopes, sortedFindings, sourceTools, model.generatedAt);
  model.priorityTrio = derivePriorityTrio(model);
  model.recommendedFirstAction = deriveRecommendedFirstAction(model);
  model.whyThisIsFirst = deriveWhyThisIsFirst(model);
  model.changeOverTime = deriveChangeOverTime(sortedFindings, baselineEnvelope);
  model.statusWorkflow = deriveStatusWorkflow(sortedFindings);
  return model;
}

function renderMarkdownReport(model) {
  const telemetrySummary = model.scanTelemetry ? [
    `- Scan depth: ${model.scanTelemetry.scan_depth}`,
    `- Files discovered: ${model.scanTelemetry.files_discovered}`,
    `- Files scanned: ${model.scanTelemetry.files_scanned}`,
    `- Data scanned: ${formatBytes(model.scanTelemetry.bytes_scanned)}`,
    `- Heuristic checks run: ${model.scanTelemetry.heuristic_checks_run}`,
    `- Scan duration: ${model.scanTelemetry.elapsed_ms} ms`,
    `- Dependency manifests detected: ${model.scanTelemetry.manifests_detected}`,
    `- External findings imported: ${model.scanTelemetry.external_findings_imported}`,
    `- External sources loaded: ${formatListInline((model.scanTelemetry.external_sources_loaded || []).map((item) => `${item.tool} (${item.findings})`), "None recorded")}`,
    `- External source failures: ${formatListInline((model.scanTelemetry.external_sources_failed || []).map((item) => `${item.tool} (${item.error})`), "None recorded")}`,
    `- Excluded directories skipped: ${model.scanTelemetry.directories_skipped}`,
    `- Support-material files skipped: ${model.scanTelemetry.skipped_files.support_material}`,
    `- Oversized files skipped: ${model.scanTelemetry.skipped_files.oversized}`,
    `- Unreadable files skipped: ${model.scanTelemetry.skipped_files.unreadable}`,
    `- Sample skipped directories: ${formatListInline(model.scanTelemetry.skipped_directories, "None recorded")}`,
    `- Sample skipped files: ${formatListInline([
      ...model.scanTelemetry.skipped_file_examples.support_material,
      ...model.scanTelemetry.skipped_file_examples.oversized,
      ...model.scanTelemetry.skipped_file_examples.unreadable
    ], "None recorded")}`,
    `- Top finding rules: ${formatListInline(topCountEntries(model.scanTelemetry.findings_by_rule), "None recorded")}`,
    `- Finding categories observed: ${formatListInline(topCountEntries(model.scanTelemetry.findings_by_category), "None recorded")}`
  ] : [
    "- Scan telemetry was not supplied in the findings metadata."
  ];

  const reportSections = [
    `# ${model.title}`,
    "",
    "## Executive Summary",
    "",
    model.summary,
    "",
    "### Priority Trio",
    "",
    model.priorityTrio
      .map((item) => `- ${item}`)
      .join("\n"),
    "",
    "### Recommended First Action",
    "",
    `- ${model.recommendedFirstAction}`,
    "",
    "### Why This Is First",
    "",
    `- ${model.whyThisIsFirst}`,
    "",
    "### Top Risk Categories",
    "",
    model.topRiskCategories
      .map((item) => item.count
        ? `- [${item.label}](#${item.anchor}): ${item.count} ${pluralize("finding", item.count)} with highest severity ${item.highestSeverity}; severity mix ${item.topDrivers}`
        : `- ${item.summary}`)
      .join("\n"),
    "",
    "### Top Risk Frameworks",
    "",
    model.topRiskFrameworks
      .map((item) => item.mapped || item.missing
        ? `- [${item.label}](#${item.anchor}): ${item.mapped} mapped findings, ${item.highSeverityMapped} high-severity mapped; mapping pressure ${item.gapDrivers}`
        : `- ${item.summary}`)
      .join("\n"),
    "",
    model.changeOverTime.enabled
      ? renderMarkdownChangeOverTime(model.changeOverTime)
      : "",
    "## Workflow Status",
    "",
    model.statusWorkflow.summaryItems
      .map((item) => `- ${item}`)
      .join("\n"),
    "",
    "### Ownership and Due Dates",
    "",
    [
      ...model.statusWorkflow.ownershipItems,
      ...model.statusWorkflow.dueItems
    ].map((item) => `- ${item}`).join("\n"),
    "",
    "## Scope and Methodology",
    "",
    `- Target: ${model.primaryMetadata.target || "Not specified"}`,
    `- Surface type: ${model.surfaces.length ? model.surfaces.join(", ") : "Not specified"}`,
    `- Standards applied: ${model.standardsApplied.length ? model.standardsApplied.join(", ") : "Not specified"}`,
    `- Source tools: ${model.sourceTools.length ? model.sourceTools.join(", ") : "native-heuristic-scan"}`,
    `- OWASP SAMM maturity lens: ${formatListInline(model.sammLenses, "Not emphasized for this report")}`,
    "- Assessment mode: read-only review with deterministic helper tooling and analyst validation",
    "- Constraints: no destructive testing, no exploit chaining, no claims beyond observed evidence",
    "",
    "## Severity Snapshot",
    "",
    `- Critical: ${model.severityCounts.Critical}`,
    `- High: ${model.severityCounts.High}`,
    `- Medium: ${model.severityCounts.Medium}`,
    `- Low: ${model.severityCounts.Low}`,
    `- Informational: ${model.severityCounts.Informational}`,
    "",
    "## Coverage Profile",
    "",
    listOrFallback(model.coverageAreas, "Coverage profile not provided in the findings metadata.")
      .map((area) => `- Assessed theme: ${area}`)
      .join("\n"),
    "",
    listOrFallback(model.blindSpots, "Runtime blind spots were not declared in the findings metadata.")
      .map((gap) => `- Manual follow-up needed: ${gap}`)
      .join("\n"),
    "",
    "## What Was Tested",
    "",
    `- Tested themes: ${formatListInline(model.coverageAreas, "Coverage profile not provided in the findings metadata.")}`,
    `- Security categories reviewed: ${formatListInline(model.findingCategories, "No finding categories were recorded.")}`,
    `- Verification methods observed: ${formatListInline(model.verificationTiers, "No verification tiers were recorded.")}`,
    `- Source tools used: ${formatListInline(model.sourceTools, "native-heuristic-scan")}`,
    `- Assets with evidence: ${model.reviewedAssets.length || 0}`,
    `- Distinct asset examples: ${formatListInline(model.reviewedAssets.slice(0, 6), model.reviewedAssets.length ? "Not specified" : "No evidence-bearing assets were recorded.")}${model.reviewedAssets.length > 6 ? ", ..." : ""}`,
    "",
    "## Dependency and Source Posture",
    "",
    `- ${model.componentPosture.note}`,
    ...model.componentPosture.summaryItems.map((item) => `- ${item}`),
    "",
    model.componentPosture.items.length
      ? renderMarkdownComponentPostureTable(model.componentPosture)
      : model.componentPosture.emptyStateText || "No component posture rows were available.",
    "",
    "### Component Follow-up",
    "",
    model.componentPosture.followUpItems
      .map((item) => `- ${item}`)
      .join("\n"),
    "",
    `<a id="category-browsing"></a>`,
    "## Category Browsing",
    "",
    model.categoryCoverage.items.length
      ? model.categoryCoverage.items.map((item) => `- [${item.label}](#${item.anchor}): ${item.count} ${pluralize("finding", item.count)}`).join("\n")
      : "- No categorized findings were recorded.",
    "",
    model.categoryCoverage.posture
      .map((item) => `- ${item}`)
      .join("\n"),
    "",
    "### Category Drill-Down",
    "",
    model.categoryCoverage.drilldownRows.length
      ? renderMarkdownCategoryDrilldown(model.categoryCoverage)
      : "No categorized findings were recorded.",
    "",
    `<a id="framework-coverage"></a>`,
    "## Framework Coverage",
    "",
    model.frameworkCoverage.items
      .map((item) => `- ${item.summary}`)
      .join("\n"),
    "",
    model.frameworkCoverage.posture
      .map((item) => `- ${item}`)
      .join("\n"),
    "",
    "### Mapping Provenance",
    "",
    model.frameworkCoverage.provenanceItems
      .map((item) => `- ${item}`)
      .join("\n"),
    "",
    "### Priority Mapping Gaps",
    "",
    model.frameworkCoverage.priorityGaps
      .map((item) => `- ${item}`)
      .join("\n"),
    "",
    "### Severity by Framework",
    "",
    renderMarkdownFrameworkMatrix(model.frameworkCoverage),
    "",
    "### Framework Drill-Down",
    "",
    renderMarkdownFrameworkDrilldown(model.frameworkCoverage),
    "",
    "## Scan Telemetry",
    "",
    telemetrySummary.join("\n"),
    "",
    "## Findings",
    "",
    model.sortedFindings.length
      ? model.sortedFindings.map(renderMarkdownFinding).join("\n")
      : "No verified findings were provided in the input files.",
    "",
    "## Recommended Next Steps",
    "",
    model.frameworkCoverage.recommendations
      .map((item) => `- ${item}`)
      .join("\n"),
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

  return reportSections.join("\n");
}

function renderHtmlReport(model) {
  const template = fs.readFileSync(HTML_TEMPLATE_PATH, "utf8");
  const metadataChips = [
    `Target: ${model.primaryMetadata.target || "Not specified"}`,
    `Surface: ${model.surfaces.length ? model.surfaces.join(", ") : "Not specified"}`,
    `Standards: ${model.standardsApplied.length ? model.standardsApplied.join(", ") : "Not specified"}`,
    `Source tools: ${model.sourceTools.length ? model.sourceTools.join(", ") : "native-heuristic-scan"}`
  ].map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("");

  const severityCards = [
    ["Critical", model.severityCounts.Critical],
    ["High", model.severityCounts.High],
    ["Medium", model.severityCounts.Medium],
    ["Low", model.severityCounts.Low],
    ["Informational", model.severityCounts.Informational]
  ].map(([label, count]) => `
    <div class="severity-card severity-card-${severityTone(label)}">
      <span class="severity-card-label">${escapeHtml(label)}</span>
      <strong>${escapeHtml(count)}</strong>
    </div>
  `).join("");

  const overviewItems = [
    ["Assessment mode", "Authorized, non-destructive, evidence-based review"],
    ["Generated", formatDate(model.generatedAt)],
    ["Assessment scope", model.primaryMetadata.target || "Not specified"],
    ["OWASP SAMM lens", formatListInline(model.sammLenses, "Not emphasized for this report")],
    ["Version", packageJson.version]
  ].map(([label, value]) => `
    <div class="overview-row">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(value)}</dd>
    </div>
  `).join("");

  const coverageItems = renderHtmlList(
    listOrFallback(model.coverageAreas, "Coverage profile not provided in the findings metadata."),
    "coverage-item"
  );
  const topRiskCategoryItems = renderHtmlList(
    model.topRiskCategories.map((item) => item.count
      ? `${item.label}: ${item.count} ${pluralize("finding", item.count)}, highest severity ${item.highestSeverity}, mix ${item.topDrivers}`
      : item.summary),
    "coverage-item"
  );
  const topRiskFrameworkItems = renderHtmlList(
    model.topRiskFrameworks.map((item) => item.mapped || item.missing
      ? `${item.label}: ${item.mapped} mapped findings, ${item.highSeverityMapped} high-severity mapped, ${item.gapDrivers}`
      : item.summary),
    "coverage-item"
  );
  const priorityTrioItems = renderHtmlList(
    model.priorityTrio,
    "coverage-item"
  );
  const recommendedFirstActionItems = renderHtmlList(
    [model.recommendedFirstAction],
    "coverage-item"
  );
  const whyThisIsFirstItems = renderHtmlList(
    [model.whyThisIsFirst],
    "coverage-item"
  );
  const workflowSummaryItems = renderHtmlList(
    model.statusWorkflow.summaryItems,
    "coverage-item"
  );
  const workflowOwnershipItems = renderHtmlList(
    [
      ...model.statusWorkflow.ownershipItems,
      ...model.statusWorkflow.dueItems
    ],
    "coverage-item"
  );
  const blindSpotItems = renderHtmlList(
    listOrFallback(model.blindSpots, "Runtime blind spots were not declared in the findings metadata."),
    "coverage-item"
  );
  const testedScopeItems = renderHtmlList([
    `Tested themes: ${formatListInline(model.coverageAreas, "Coverage profile not provided in the findings metadata.")}`,
    `Security categories reviewed: ${formatListInline(model.findingCategories, "No finding categories were recorded.")}`,
    `Assets with evidence: ${model.reviewedAssets.length || 0}`
  ], "coverage-item");
  const testMethodItems = renderHtmlList([
    `Verification methods observed: ${formatListInline(model.verificationTiers, "No verification tiers were recorded.")}`,
    `Source tools used: ${formatListInline(model.sourceTools, "native-heuristic-scan")}`,
    `Distinct asset examples: ${formatListInline(model.reviewedAssets.slice(0, 6), model.reviewedAssets.length ? "Not specified" : "No evidence-bearing assets were recorded.")}${model.reviewedAssets.length > 6 ? ", ..." : ""}`
  ], "coverage-item");
  const componentPostureSummaryItems = renderHtmlList([
    model.componentPosture.note,
    ...model.componentPosture.summaryItems
  ], "coverage-item");
  const componentPostureFollowUpItems = renderHtmlList(
    model.componentPosture.followUpItems,
    "coverage-item"
  );
  const componentPostureTable = model.componentPosture.items.length
    ? renderHtmlComponentPostureTable(model.componentPosture)
    : `<p class="drilldown-empty">${escapeHtml(model.componentPosture.emptyStateText || "No component posture rows were available.")}</p>`;
  const frameworkCoverageItems = renderHtmlList(
    model.frameworkCoverage.items.map((item) => item.summary),
    "coverage-item"
  );
  const categoryCoverageItems = renderHtmlList(
    model.categoryCoverage.items.length
      ? model.categoryCoverage.items.map((item) => `${item.label}: ${item.count} ${pluralize("finding", item.count)}`)
      : ["No categorized findings were recorded."],
    "coverage-item"
  );
  const categoryPostureItems = renderHtmlList(
    model.categoryCoverage.posture,
    "coverage-item"
  );
  const categoryDrilldown = renderHtmlCategoryDrilldown(model.categoryCoverage);
  const frameworkPostureItems = renderHtmlList(
    model.frameworkCoverage.posture,
    "coverage-item"
  );
  const frameworkProvenanceItems = renderHtmlList(
    model.frameworkCoverage.provenanceItems,
    "coverage-item"
  );
  const frameworkGapItems = renderHtmlList(
    model.frameworkCoverage.priorityGaps,
    "coverage-item"
  );
  const frameworkMatrix = renderHtmlFrameworkMatrix(model.frameworkCoverage);
  const frameworkDrilldown = renderHtmlFrameworkDrilldown(model.frameworkCoverage);
  const telemetrySummaryItems = renderHtmlList(model.scanTelemetry ? [
    `Scan depth: ${model.scanTelemetry.scan_depth}`,
    `Files discovered: ${model.scanTelemetry.files_discovered}`,
    `Files scanned: ${model.scanTelemetry.files_scanned}`,
    `Data scanned: ${formatBytes(model.scanTelemetry.bytes_scanned)}`,
    `Heuristic checks run: ${model.scanTelemetry.heuristic_checks_run}`,
    `Scan duration: ${model.scanTelemetry.elapsed_ms} ms`,
    `Dependency manifests detected: ${model.scanTelemetry.manifests_detected}`,
    `External findings imported: ${model.scanTelemetry.external_findings_imported}`
  ] : [
    "Scan telemetry was not supplied in the findings metadata."
  ], "coverage-item");
  const telemetryDetailItems = renderHtmlList(model.scanTelemetry ? [
    `Excluded directories skipped: ${model.scanTelemetry.directories_skipped}`,
    `Support-material files skipped: ${model.scanTelemetry.skipped_files.support_material}`,
    `Oversized files skipped: ${model.scanTelemetry.skipped_files.oversized}`,
    `Unreadable files skipped: ${model.scanTelemetry.skipped_files.unreadable}`,
    `External sources loaded: ${formatListInline((model.scanTelemetry.external_sources_loaded || []).map((item) => `${item.tool} (${item.findings})`), "None recorded")}`,
    `External source failures: ${formatListInline((model.scanTelemetry.external_sources_failed || []).map((item) => `${item.tool} (${item.error})`), "None recorded")}`,
    `Top finding rules: ${formatListInline(topCountEntries(model.scanTelemetry.findings_by_rule), "None recorded")}`,
    `Finding categories observed: ${formatListInline(topCountEntries(model.scanTelemetry.findings_by_category), "None recorded")}`
  ] : [
    "No skip or rule-level telemetry was supplied."
  ], "coverage-item");

  const findingsHtml = model.sortedFindings.length
    ? model.sortedFindings.map(renderFindingHtml).join("")
    : `
      <section class="empty-state">
        <div class="empty-state-kicker">Review result</div>
        <h3>No verified findings were reported</h3>
        <p>The supplied evidence did not produce verified findings in this run. Keep the stated blind spots in mind before treating the target as fully hardened.</p>
      </section>
    `;

  const nextSteps = [
    ...model.frameworkCoverage.recommendations,
    "Validate high-confidence findings in the owning engineering context.",
    "Prioritize remediation for credential exposure, authorization flaws, and overly broad CI or network permissions first.",
    "Rerun targeted verification after fixes to confirm closure and identify regressions."
  ];

  return replaceTemplateTokens(template, {
    "__PAGE_TITLE__": escapeHtml(model.title),
    "__REPORT_TITLE__": escapeHtml(model.title),
    "__REPORT_SUMMARY__": escapeHtml(model.summary),
    "__PRIORITY_TRIO_ITEMS__": priorityTrioItems,
    "__RECOMMENDED_FIRST_ACTION_ITEMS__": recommendedFirstActionItems,
    "__WHY_THIS_IS_FIRST_ITEMS__": whyThisIsFirstItems,
    "__WORKFLOW_SUMMARY_ITEMS__": workflowSummaryItems,
    "__WORKFLOW_OWNERSHIP_ITEMS__": workflowOwnershipItems,
    "__CHANGE_OVER_TIME_SECTION__": renderHtmlChangeOverTime(model.changeOverTime),
    "__GENERATED_AT__": escapeHtml(formatDate(model.generatedAt)),
    "__META_CHIPS__": metadataChips,
    "__SEVERITY_CARDS__": severityCards,
    "__OVERVIEW_ROWS__": overviewItems,
    "__TOP_RISK_CATEGORY_ITEMS__": topRiskCategoryItems,
    "__TOP_RISK_FRAMEWORK_ITEMS__": topRiskFrameworkItems,
    "__COVERAGE_ITEMS__": coverageItems,
    "__BLIND_SPOT_ITEMS__": blindSpotItems,
    "__TESTED_SCOPE_ITEMS__": testedScopeItems,
    "__TEST_METHOD_ITEMS__": testMethodItems,
    "__COMPONENT_POSTURE_SUMMARY_ITEMS__": componentPostureSummaryItems,
    "__COMPONENT_POSTURE_TABLE__": componentPostureTable,
    "__COMPONENT_POSTURE_FOLLOWUP_ITEMS__": componentPostureFollowUpItems,
    "__CATEGORY_COVERAGE_ITEMS__": categoryCoverageItems,
    "__CATEGORY_POSTURE_ITEMS__": categoryPostureItems,
    "__CATEGORY_DRILLDOWN__": categoryDrilldown,
    "__FRAMEWORK_COVERAGE_ITEMS__": frameworkCoverageItems,
    "__FRAMEWORK_POSTURE_ITEMS__": frameworkPostureItems,
    "__FRAMEWORK_PROVENANCE_ITEMS__": frameworkProvenanceItems,
    "__FRAMEWORK_GAP_ITEMS__": frameworkGapItems,
    "__FRAMEWORK_MATRIX__": frameworkMatrix,
    "__FRAMEWORK_DRILLDOWN__": frameworkDrilldown,
    "__TELEMETRY_SUMMARY_ITEMS__": telemetrySummaryItems,
    "__TELEMETRY_DETAIL_ITEMS__": telemetryDetailItems,
    "__FINDINGS_HTML__": findingsHtml,
    "__NEXT_STEPS__": renderHtmlList(nextSteps, "coverage-item"),
    "__LIMITATIONS__": escapeHtml("This report reflects the supplied evidence and any deterministic scan results available at generation time. Areas outside the declared scope, runtime-only behavior, environment-specific controls, and exploitability assumptions may require separate manual validation.")
  });
}

const envelopes = inputFiles
  .map(readJson)
  .filter(Boolean);

const baselineEnvelope = baselineInputFile ? readJson(baselineInputFile) : null;
const model = buildReportModel(envelopes, baselineEnvelope);
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
            name: "defensive-appsec-review-skill",
            version: packageJson.version,
            informationUri: "https://github.com/jovd83/defensive-appsec-review-skill",
            rules: model.sortedFindings.map((finding) => ({
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
                fix_effort: finding.fix_effort,
                status: normalizeFindingStatus(finding.status) || null,
                owner: finding.owner || null,
                due_date: finding.due_date || null,
                mapping_provenance: finding.framework_mapping?.provenance || {},
                asvs: finding.framework_mapping?.asvs || [],
                nist: finding.framework_mapping?.nist || [],
                cis: finding.framework_mapping?.cis || [],
                scvs: finding.framework_mapping?.scvs || [],
                slsa: finding.framework_mapping?.slsa || [],
                owasp: finding.framework_mapping?.owasp || [],
                verification_tier: finding.verification_tier || null
              }
            }))
          }
        },
        properties: {
          target: model.primaryMetadata.target || "Not specified",
          target_surface: model.surfaces,
          standards_applied: model.standardsApplied
        },
        results: model.sortedFindings.map((finding) => {
          const severity = parseSeverity(finding.cvss_v4);
          const parsedLocation = parseFindingLocation(finding);
          const uri = parsedLocation.asset || finding.asset || ".";
          const lineNumber = parsedLocation.lineNumber;
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
                  region: Number.isFinite(lineNumber)
                    ? {
                      startLine: lineNumber,
                      snippet: finding.code_snippet ? { text: finding.code_snippet } : undefined
                    }
                    : undefined
                }
              }
            ],
            properties: {
              asset: finding.asset,
              class_name: finding.class_name || null,
              line_number: lineNumber || null,
              code_snippet: finding.code_snippet || null,
              category: finding.category,
              cvss_v4: finding.cvss_v4,
              confidence: finding.confidence,
              remediation: finding.remediation,
              evidence: finding.evidence,
              fix_effort: finding.fix_effort,
              status: normalizeFindingStatus(finding.status) || null,
              owner: finding.owner || null,
              due_date: finding.due_date || null,
              mapping_provenance: finding.framework_mapping?.provenance || {},
              asvs: finding.framework_mapping?.asvs || [],
              nist: finding.framework_mapping?.nist || [],
              cis: finding.framework_mapping?.cis || [],
              scvs: finding.framework_mapping?.scvs || [],
              slsa: finding.framework_mapping?.slsa || [],
              owasp: finding.framework_mapping?.owasp || [],
              verification_tier: finding.verification_tier || null
            }
          };
        })
      }
    ]
  };

  fs.writeFileSync(resolvedOutput, JSON.stringify(sarif, null, 2), "utf8");
} else if (format === "html") {
  fs.writeFileSync(resolvedOutput, renderHtmlReport(model), "utf8");
} else if (format === "md") {
  fs.writeFileSync(resolvedOutput, renderMarkdownReport(model), "utf8");
} else {
  console.error(`[-] Unsupported format: ${format}`);
  process.exit(1);
}

console.log(`[+] ${format.toUpperCase()} report written to ${resolvedOutput}`);
