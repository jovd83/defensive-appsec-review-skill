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
      standard_family: "nist-ssdf",
      coverage_areas: ["injection and configuration review"],
      blind_spots: ["runtime authorization verification"],
      scan_telemetry: {
        scan_depth: "quick",
        files_discovered: 3,
        files_scanned: 2,
        bytes_scanned: 1536,
        heuristic_checks_run: 42,
        manifests_detected: 1,
        directories_skipped: 1,
        skipped_directories: ["node_modules"],
        skipped_files: {
          support_material: 1,
          oversized: 0,
          unreadable: 0
        },
        skipped_file_examples: {
          support_material: ["README.md"],
          oversized: [],
          unreadable: []
        },
        findings_by_rule: {
          "Potential hardcoded credential detected": 1
        },
        findings_by_category: {
          "Credential Management": 1
        },
        elapsed_ms: 180
      },
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "Potential hardcoded credential detected",
        asset: "src/config.js",
        location: "src/config.js:12",
        line_number: 12,
        class_name: "ConfigManager",
        code_snippet: "11 | const region = process.env.AWS_REGION;\n12 | const password = \"super-secret-demo-value\";\n13 | export default { password, region };",
        category: "Credential Management",
        cwe: "CWE-798: Use of Hard-coded Credentials",
        cvss_v4: "8.6 (High)",
        confidence: "Medium",
        status: "new",
        owner: "Security Guild",
        due_date: "2026-04-15",
        fix_effort: "M",
        framework_mapping: {
          standard: "nist-ssdf",
          control: "Secret exposure prevention",
          provenance: {
            primary: "supplied",
            asvs: "supplied",
            nist: "supplied",
            cis: "supplied",
            scvs: "not-recorded",
            slsa: "not-recorded",
            owasp: "supplied"
          },
          asvs: ["OWASP ASVS V8 Data Protection"],
          nist: ["NIST SP 800-218 SSDF PS.1 Protect code, secrets, and related artifacts"],
          cis: ["CIS Controls v8 Control 3 Data Protection"],
          scvs: [],
          slsa: [],
          owasp: ["OWASP Top 10 2021 A02 Cryptographic Failures"]
        },
        verification_tier: "deterministic-static",
        source_tool: "gitleaks",
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
  assert.match(markdown, /Priority Trio/);
  assert.match(markdown, /Recommended First Action/);
  assert.match(markdown, /Why This Is First/);
  assert.match(markdown, /Severity Snapshot/);
  assert.match(markdown, /Top Risk Categories/);
  assert.match(markdown, /Top Risk Frameworks/);
  assert.match(markdown, /Coverage Profile/);
  assert.match(markdown, /What Was Tested/);
  assert.match(markdown, /Category Browsing/);
  assert.match(markdown, /<a id="category-browsing"><\/a>/);
  assert.match(markdown, /Framework Coverage/);
  assert.match(markdown, /<a id="framework-coverage"><\/a>/);
  assert.match(markdown, /Mapping Provenance/);
  assert.match(markdown, /Priority Mapping Gaps/);
  assert.match(markdown, /Severity by Framework/);
  assert.match(markdown, /Framework Drill-Down/);
  assert.match(markdown, /Workflow Status/);
  assert.match(markdown, /Scan Telemetry/);
  assert.match(markdown, /OWASP SAMM maturity lens:/);
  assert.match(markdown, /Security categories reviewed: Credential Management/);
  assert.match(markdown, /\[Credential Management\]\(#category-credential-management\): 1 finding with highest severity High; severity mix 1 High/);
  assert.match(markdown, /\[OWASP SCVS\]\(#framework-scvs\): 0 mapped findings, 0 high-severity mapped; mapping pressure 1 high-severity gaps, 1 unmapped findings/);
  assert.match(markdown, /Severity: 1 high-severity finding need first triage \(0 Critical, 1 High\)\./);
  assert.match(markdown, /Category: Credential Management leads with 1 finding and a High ceiling\./);
  assert.match(markdown, /Framework: (OWASP SCVS|OWASP|SLSA) has the strongest pressure with 0 high-severity mapped and 1 high-severity gaps\./);
  assert.match(markdown, /Validate and triage the 1 high-severity finding in Credential Management first, then close the biggest mapping gap in (OWASP SCVS|OWASP|SLSA)\./);
  assert.match(markdown, /Credential Management currently carries the most urgent business risk, and (OWASP SCVS|OWASP|SLSA) adds the strongest framework pressure through mapped exposure or missing high-severity coverage\./);
  assert.match(markdown, /Verification methods observed: deterministic-static/);
  assert.match(markdown, /Assets with evidence: 1/);
  assert.match(markdown, /Files discovered: 3/);
  assert.match(markdown, /Scan depth: quick/);
  assert.match(markdown, /Heuristic checks run: 42/);
  assert.match(markdown, /Top finding rules: Potential hardcoded credential detected: 1/);
  assert.match(markdown, /Location: src\/config\.js:12/);
  assert.match(markdown, /Class\/file: ConfigManager \(src\/config\.js\)/);
  assert.match(markdown, /Line number: 12/);
  assert.match(markdown, /const password = "super-secret-demo-value"/);
  assert.match(markdown, /Status: New/);
  assert.match(markdown, /Owner: Security Guild/);
  assert.match(markdown, /Due date: 2026-04-15/);
  assert.match(markdown, /Fix effort: M/);
  assert.match(markdown, /Source tool: gitleaks/);
  assert.match(markdown, /New: 1/);
  assert.match(markdown, /Needs review: 0/);
  assert.match(markdown, /Owner workload: Security Guild: 1/);
  assert.match(markdown, /Potential hardcoded credential detected: due 2026-04-15 \(New, owner Security Guild\)/);
  assert.match(markdown, /Category navigation: \[Category Browsing\]\(#category-browsing\); \[Credential Management\]\(#category-credential-management\)/);
  assert.match(markdown, /Framework navigation: \[Framework Coverage\]\(#framework-coverage\); \[Primary control mapping\]\(#framework-primary\); \[OWASP\]\(#framework-owasp\); \[OWASP ASVS\]\(#framework-asvs\); \[NIST SSDF\]\(#framework-nist\); \[CIS Controls v8\]\(#framework-cis\)/);
  assert.match(markdown, /ASVS mapping: OWASP ASVS V8 Data Protection/);
  assert.match(markdown, /NIST mapping: NIST SP 800-218 SSDF PS\.1 Protect code, secrets, and related artifacts/);
  assert.match(markdown, /CIS mapping: CIS Controls v8 Control 3 Data Protection/);
  assert.match(markdown, /OWASP mapping: OWASP Top 10 2021 A02 Cryptographic Failures/);
  assert.match(markdown, /Primary control mapping: 1\/1 findings mapped \(100%\)/);
  assert.match(markdown, /OWASP: 1 supplied, 0 inferred, 0 not recorded/);
  assert.match(markdown, /OWASP SCVS: 0\/1 findings mapped \(0%\)/);
  assert.match(markdown, /Findings with any framework lens: 1\/1/);
  assert.match(markdown, /Mapping provenance: Primary control mapping: supplied explicitly; OWASP: supplied explicitly; OWASP ASVS: supplied explicitly; NIST SSDF: supplied explicitly; CIS Controls v8: supplied explicitly; OWASP SCVS: not recorded; SLSA: not recorded/);
  assert.match(markdown, /OWASP SCVS: missing on 1\/1 findings, including 1 high-severity finding/);
  assert.match(markdown, /SLSA: missing on 1\/1 findings, including 1 high-severity finding/);
  assert.match(markdown, /\| Framework \| Critical \| High \| Medium \| Low \| Informational \| Mapped total \| Supplied \| Inferred \| Not recorded \|/);
  assert.match(markdown, /\| \[OWASP ASVS\]\(#framework-asvs\) \| 0 \| 1 \| 0 \| 0 \| 0 \| 1 \| 1 \| 0 \| 0 \|/);
  assert.match(markdown, /\[Credential Management\]\(#category-credential-management\): 1 finding/);
  assert.match(markdown, /Distinct security categories: 1/);
  assert.match(markdown, /### <a id="category-credential-management"><\/a>Credential Management/);
  assert.match(markdown, /- Findings in this category \(1\): \[Finding 1\]\(#finding-1\) \[High\] Potential hardcoded credential detected/);
  assert.match(markdown, /### <a id="framework-scvs"><\/a>OWASP SCVS/);
  assert.match(markdown, /- Mapped findings \(0\): No findings currently use this framework mapping\./);
  assert.match(markdown, /- Missing mappings \(1\): \[Finding 1\]\(#finding-1\) Potential hardcoded credential detected/);
  assert.match(markdown, /<a id="finding-1"><\/a>/);
  assert.match(markdown, /Backfill OWASP SCVS mappings first for 1 high-severity finding\./);
  assert.match(markdown, /Manual follow-up needed: runtime authorization verification/);
});

test("generate-report renders component posture with explicit unknowns and evidence-based concerns", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-report-components-"));
  const inputFile = path.join(tempDir, "input.json");
  const markdownOutput = path.join(tempDir, "report.md");
  const htmlOutput = path.join(tempDir, "report.html");

  fs.writeFileSync(inputFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      target_surface: "repo",
      standard: "owasp-scvs",
      standard_family: "owasp-scvs",
      coverage_areas: ["dependency review"],
      blind_spots: ["live registry validation was not performed"],
      source_tools: ["native-heuristic-scan", "osv-scanner"],
      component_posture: [
        {
          name: "express",
          version: "^4.21.0",
          kind: "library",
          ecosystem: "npm",
          manifest_path: "package.json",
          origin: "dependencies",
          review_status: "unknown",
          security_posture: "unknown",
          maintenance_posture: "unknown",
          provenance_posture: "unknown",
          confidence: "Low",
          evidence_mode: "offline-only",
          checked_at: "2026-04-01T09:00:00.000Z",
          evidence_sources: ["package.json"],
          notes: "Observed in package.json. No live package-intel or advisory verdict was supplied in this run."
        },
        {
          name: "lodash",
          version: "^4.17.21",
          kind: "library",
          ecosystem: "npm",
          manifest_path: "package.json",
          origin: "dependencies",
          review_status: "unknown",
          security_posture: "unknown",
          maintenance_posture: "unknown",
          provenance_posture: "unknown",
          confidence: "Low",
          evidence_mode: "offline-only",
          checked_at: "2026-04-01T09:00:00.000Z",
          evidence_sources: ["package.json"],
          notes: "Observed in package.json. No live package-intel or advisory verdict was supplied in this run."
        }
      ],
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "Known advisory in lodash",
        asset: "lodash",
        location: "lodash",
        category: "Dependency Security",
        cwe: "CWE-1104: Use of Unmaintained Third Party Components",
        cvss_v4: "7.8 (High)",
        confidence: "High",
        framework_mapping: {
          standard: "owasp-scvs",
          control: "Dependency vulnerability management",
          provenance: {
            primary: "supplied",
            asvs: "not-recorded",
            nist: "supplied",
            cis: "supplied",
            scvs: "supplied",
            slsa: "supplied",
            owasp: "supplied"
          },
          asvs: [],
          nist: ["NIST SP 800-218 SSDF RV.1 Ongoing vulnerability identification"],
          cis: ["CIS Controls v8 Control 2 Inventory and Control of Software Assets"],
          scvs: ["OWASP SCVS V5 Component Analysis"],
          slsa: ["SLSA dependency and provenance verification support"],
          owasp: ["OWASP Top 10 2021 A06 Vulnerable and Outdated Components"]
        },
        verification_tier: "deterministic-static",
        source_tool: "osv-scanner",
        evidence: "OSV advisory reported against lodash.",
        reproduction_steps: "1. Inspect lodash version\n2. Compare against the advisory.",
        business_impact: "A known vulnerable dependency can expose inherited product risk.",
        remediation: "Upgrade lodash to a fixed version.",
        fix_effort: "M"
      }
    ]
  }, null, 2));

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--output",
    markdownOutput
  ], { cwd: process.cwd() });

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--format",
    "html",
    "--output",
    htmlOutput
  ], { cwd: process.cwd() });

  const markdown = fs.readFileSync(markdownOutput, "utf8");
  const html = fs.readFileSync(htmlOutput, "utf8");

  assert.match(markdown, /## Dependency and Source Posture/);
  assert.match(markdown, /Unknown means insufficient evidence\./);
  assert.match(markdown, /- Rows reviewed: 1/);
  assert.match(markdown, /- Inventory-only rows omitted: 3/);
  assert.match(markdown, /- Concern: 1/);
  assert.match(markdown, /- Unknown: 0/);
  assert.match(markdown, /\| Component \| Kind \| Observed via \| Security \| Maintenance \| Provenance \| Overall \| Confidence \| Evidence \| Notes \|/);
  assert.match(markdown, /lodash@\^4\.17\.21/);
  assert.match(markdown, /Concern/);
  assert.match(markdown, /1 dependency-related finding referenced this component in the current evidence\./);
  assert.match(markdown, /3 inventory-only component rows were omitted because the evidence did not justify a posture verdict\./);

  assert.match(html, /Dependency and Source Posture/);
  assert.match(html, /Unknown means insufficient evidence, not implicit approval or rejection\./);
  assert.match(html, /Rows reviewed: 1/);
  assert.match(html, /Inventory-only rows omitted: 3/);
  assert.match(html, /Concern: 1/);
  assert.match(html, /Unknown: 0/);
  assert.match(html, /lodash@\^4\.17\.21/);
  assert.match(html, /3 inventory-only component rows were omitted because the evidence did not justify a posture verdict\./);
});

test("generate-report builds a professional HTML report from findings input", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-report-html-"));
  const inputFile = path.join(tempDir, "input.json");
  const outputFile = path.join(tempDir, "report.html");

  fs.writeFileSync(inputFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      target_surface: "repo",
      standard: "owasp-scvs",
      standard_family: "owasp-scvs",
      coverage_areas: ["dependency and secrets review", "CI/CD trust review"],
      blind_spots: ["runtime authorization verification"],
      source_tools: ["native-heuristic-scan"],
      scan_telemetry: {
        scan_depth: "quick",
        files_discovered: 3,
        files_scanned: 2,
        bytes_scanned: 1536,
        heuristic_checks_run: 42,
        manifests_detected: 1,
        directories_skipped: 1,
        skipped_directories: ["node_modules"],
        skipped_files: {
          support_material: 1,
          oversized: 0,
          unreadable: 0
        },
        skipped_file_examples: {
          support_material: ["README.md"],
          oversized: [],
          unreadable: []
        },
        findings_by_rule: {
          "Potential hardcoded credential detected": 1
        },
        findings_by_category: {
          "Credential Management": 1
        },
        elapsed_ms: 180
      },
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "Potential hardcoded credential detected",
        asset: "src/config.js",
        location: "src/config.js:12",
        line_number: 12,
        class_name: "ConfigManager",
        code_snippet: "11 | const region = process.env.AWS_REGION;\n12 | const password = \"super-secret-demo-value\";\n13 | export default { password, region };",
        category: "Credential Management",
        cwe: "CWE-798: Use of Hard-coded Credentials",
        cvss_v4: "8.6 (High)",
        confidence: "Medium",
        status: "in-progress",
        owner: "AppSec Team",
        due_date: "2026-04-10",
        fix_effort: "M",
        framework_mapping: {
          standard: "owasp-scvs",
          control: "Secret exposure prevention",
          provenance: {
            primary: "supplied",
            asvs: "supplied",
            nist: "supplied",
            cis: "supplied",
            scvs: "supplied",
            slsa: "not-recorded",
            owasp: "supplied"
          },
          asvs: ["OWASP ASVS V8 Data Protection"],
          nist: ["NIST SP 800-218 SSDF PS.1 Protect code, secrets, and related artifacts"],
          cis: ["CIS Controls v8 Control 3 Data Protection"],
          scvs: ["OWASP SCVS V1 Inventory"],
          slsa: [],
          owasp: ["OWASP Top 10 2021 A02 Cryptographic Failures"]
        },
        verification_tier: "deterministic-static",
        source_tool: "gitleaks",
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
    "--format",
    "html",
    "--output",
    outputFile
  ], { cwd: process.cwd() });

  const html = fs.readFileSync(outputFile, "utf8");
  assert.match(html, /<!DOCTYPE html>/);
  assert.match(html, /Security Assessment Brief/);
  assert.match(html, /Security Assessment Report - demo-repo/);
  assert.match(html, /Class\/file/);
  assert.match(html, /ConfigManager \(src\/config\.js\)/);
  assert.match(html, /Line number/);
  assert.match(html, /const password = &quot;super-secret-demo-value&quot;/);
  assert.match(html, /Priority Trio/);
  assert.match(html, /Recommended First Action/);
  assert.match(html, /Why This Is First/);
  assert.match(html, /Severity Snapshot/);
  assert.match(html, /Top Risk Categories/);
  assert.match(html, /Top Risk Frameworks/);
  assert.match(html, /What Was Tested/);
  assert.match(html, /Category Browsing/);
  assert.match(html, /<section class="section" id="category-browsing">/);
  assert.match(html, /Framework Coverage/);
  assert.match(html, /<section class="section" id="framework-coverage">/);
  assert.match(html, /Workflow Status/);
  assert.match(html, /Mapping Provenance/);
  assert.match(html, /Priority Mapping Gaps/);
  assert.match(html, /Severity by Framework/);
  assert.match(html, /href="#framework-scvs">OWASP SCVS<\/a>/);
  assert.match(html, /id="framework-scvs"/);
  assert.match(html, /Mapped findings \(1\)/);
  assert.match(html, /Missing mappings \(0\)/);
  assert.match(html, /<a class="anchor-link" href="#finding-1">Finding 1<\/a>/);
  assert.match(html, /id="finding-1"/);
  assert.match(html, /Scan Telemetry/);
  assert.match(html, /Processing Summary/);
  assert.match(html, /Tested Scope/);
  assert.match(html, /OWASP SAMM lens/);
  assert.match(html, /Credential Management: 1 finding, highest severity High, mix 1 High/);
  assert.match(html, /SLSA: 0 mapped findings, 0 high-severity mapped, 1 high-severity gaps, 1 unmapped findings/);
  assert.match(html, /Severity: 1 high-severity finding need first triage \(0 Critical, 1 High\)\./);
  assert.match(html, /Category: Credential Management leads with 1 finding and a High ceiling\./);
  assert.match(html, /Framework: SLSA has the strongest pressure with 0 high-severity mapped and 1 high-severity gaps\.|Framework: OWASP has the strongest pressure with 0 high-severity mapped and 1 high-severity gaps\./);
  assert.match(html, /Validate and triage the 1 high-severity finding in Credential Management first, then close the biggest mapping gap in (OWASP SCVS|OWASP|SLSA)\./);
  assert.match(html, /Credential Management currently carries the most urgent business risk, and (OWASP SCVS|OWASP|SLSA) adds the strongest framework pressure through mapped exposure or missing high-severity coverage\./);
  assert.match(html, /Security categories reviewed: Credential Management/);
  assert.match(html, /Verification methods observed: deterministic-static/);
  assert.match(html, /Assets with evidence: 1/);
  assert.match(html, /Scan depth: quick/);
  assert.match(html, /Files discovered: 3/);
  assert.match(html, /Heuristic checks run: 42/);
  assert.match(html, /Potential hardcoded credential detected/);
  assert.match(html, /Source tool/);
  assert.match(html, /gitleaks/);
  assert.match(html, /<dt>Status<\/dt>\s*<dd>In progress<\/dd>/);
  assert.match(html, /<dt>Owner<\/dt>\s*<dd>AppSec Team<\/dd>/);
  assert.match(html, /<dt>Due date<\/dt>\s*<dd>2026-04-10<\/dd>/);
  assert.match(html, /New: 0/);
  assert.match(html, /In progress: 1/);
  assert.match(html, /Owner workload: AppSec Team: 1/);
  assert.match(html, /Potential hardcoded credential detected: due 2026-04-10 \(In progress, owner AppSec Team\)/);
  assert.match(html, /Category navigation<\/h4>/);
  assert.match(html, /href="#category-browsing">Category Browsing<\/a>/);
  assert.match(html, /href="#category-credential-management">Credential Management<\/a>/);
  assert.match(html, /Framework navigation<\/h4>/);
  assert.match(html, /href="#framework-coverage">Framework Coverage<\/a>/);
  assert.match(html, /href="#framework-scvs">OWASP SCVS<\/a>/);
  assert.match(html, /OWASP ASVS V8 Data Protection/);
  assert.match(html, /NIST SP 800-218 SSDF PS\.1 Protect code, secrets, and related artifacts/);
  assert.match(html, /CIS Controls v8 Control 3 Data Protection/);
  assert.match(html, /OWASP SCVS V1 Inventory/);
  assert.match(html, /OWASP Top 10 2021 A02 Cryptographic Failures/);
  assert.match(html, /Category Coverage/);
  assert.match(html, /Distinct security categories: 1/);
  assert.match(html, /id="category-credential-management"/);
  assert.match(html, /Primary control mapping: 1\/1 findings mapped \(100%\)/);
  assert.match(html, /OWASP SCVS: 1 supplied, 0 inferred, 0 not recorded/);
  assert.match(html, /SLSA: 0\/1 findings mapped \(0%\)/);
  assert.match(html, /Findings with any framework lens: 1\/1/);
  assert.match(html, /Primary control mapping: supplied explicitly/);
  assert.match(html, /SLSA: missing on 1\/1 findings, including 1 high-severity finding/);
  assert.match(html, /<th>Critical<\/th>/);
  assert.match(html, /<th>Supplied<\/th>/);
  assert.match(html, /href="#framework-scvs">OWASP SCVS<\/a><\/td>\s*<td>0<\/td>\s*<td>1<\/td>\s*<td>0<\/td>\s*<td>0<\/td>\s*<td>0<\/td>\s*<td>1<\/td>\s*<td>1<\/td>\s*<td>0<\/td>\s*<td>0<\/td>/);
  assert.match(html, /Backfill SLSA mappings first for 1 high-severity finding\./);
  assert.match(html, /professional HTML report/i);
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
      standard_family: "nist-ssdf",
      coverage_areas: ["injection review"],
      blind_spots: ["runtime verification"],
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "Dynamic code execution via eval detected",
        asset: "src/index.js",
        location: "src/index.js:3",
        line_number: 3,
        class_name: "DangerousRunner",
        code_snippet: "2 | const userCode = req.body.code;\n3 | eval(userCode);\n4 | return true;",
        category: "Code Injection Risk",
        cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        cvss_v4: "7.8 (High)",
        confidence: "Medium",
        status: "needs-review",
        owner: "Platform Security",
        due_date: "2026-04-20",
        fix_effort: "M",
        framework_mapping: {
          standard: "nist-ssdf",
          control: "Avoid dynamic evaluation",
          provenance: {
            primary: "supplied",
            asvs: "supplied",
            nist: "supplied",
            cis: "supplied",
            scvs: "not-recorded",
            slsa: "not-recorded",
            owasp: "supplied"
          },
          asvs: ["OWASP ASVS V5 Validation, Sanitization and Encoding"],
          nist: ["NIST SP 800-218 SSDF PW.4 Code review and static analysis"],
          cis: ["CIS Controls v8 Control 4 Secure Configuration of Enterprise Assets and Software"],
          scvs: [],
          slsa: [],
          owasp: ["OWASP Top 10 2021 A03 Injection"]
        },
        verification_tier: "heuristic-static",
        source_tool: "semgrep",
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
  assert.equal(sarif.runs[0].tool.driver.name, "defensive-appsec-review-skill");
  assert.equal(sarif.runs[0].results[0].ruleId, "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/index.js");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet.text, "2 | const userCode = req.body.code;\n3 | eval(userCode);\n4 | return true;");
  assert.equal(sarif.runs[0].results[0].properties.class_name, "DangerousRunner");
  assert.deepEqual(sarif.runs[0].results[0].properties.asvs, ["OWASP ASVS V5 Validation, Sanitization and Encoding"]);
  assert.deepEqual(sarif.runs[0].results[0].properties.nist, ["NIST SP 800-218 SSDF PW.4 Code review and static analysis"]);
  assert.deepEqual(sarif.runs[0].results[0].properties.cis, ["CIS Controls v8 Control 4 Secure Configuration of Enterprise Assets and Software"]);
  assert.deepEqual(sarif.runs[0].results[0].properties.owasp, ["OWASP Top 10 2021 A03 Injection"]);
  assert.deepEqual(sarif.runs[0].results[0].properties.mapping_provenance, {
    primary: "supplied",
    asvs: "supplied",
    nist: "supplied",
    cis: "supplied",
    scvs: "not-recorded",
    slsa: "not-recorded",
    owasp: "supplied"
  });
  assert.equal(sarif.runs[0].results[0].properties.verification_tier, "heuristic-static");
  assert.equal(sarif.runs[0].results[0].properties.status, "needs-review");
  assert.equal(sarif.runs[0].results[0].properties.owner, "Platform Security");
  assert.equal(sarif.runs[0].results[0].properties.due_date, "2026-04-20");
});

test("generate-report compares a current report against a baseline", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-report-compare-"));
  const baselineFile = path.join(tempDir, "baseline.json");
  const currentFile = path.join(tempDir, "current.json");
  const markdownOutput = path.join(tempDir, "report.md");
  const htmlOutput = path.join(tempDir, "report.html");

  fs.writeFileSync(baselineFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      timestamp: "2026-03-01T10:00:00.000Z"
    },
    findings: [
      {
        title: "Dynamic code execution via eval detected",
        asset: "src/index.js",
        location: "src/index.js:3",
        category: "Code Injection Risk",
        cwe: "CWE-95",
        cvss_v4: "5.9 (Medium)"
      },
      {
        title: "Potential hardcoded credential detected",
        asset: "src/config.js",
        location: "src/config.js:12",
        category: "Credential Management",
        cwe: "CWE-798",
        cvss_v4: "8.2 (High)"
      },
      {
        title: "Non-local plaintext HTTP endpoint referenced",
        asset: "src/http.js",
        location: "src/http.js:9",
        category: "Transport Security",
        cwe: "CWE-319",
        cvss_v4: "5.5 (Medium)"
      }
    ]
  }, null, 2));

  fs.writeFileSync(currentFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      target_surface: "repo",
      standard: "owasp-top10",
      timestamp: "2026-03-28T10:00:00.000Z"
    },
    findings: [
      {
        title: "Dynamic code execution via eval detected",
        asset: "src/index.js",
        location: "src/index.js:3",
        category: "Code Injection Risk",
        cwe: "CWE-95",
        cvss_v4: "7.8 (High)"
      },
      {
        title: "Potential hardcoded credential detected",
        asset: "src/config.js",
        location: "src/config.js:12",
        category: "Credential Management",
        cwe: "CWE-798",
        cvss_v4: "5.4 (Medium)"
      },
      {
        title: "Sensitive token stored in browser localStorage",
        asset: "src/storage.js",
        location: "src/storage.js:20",
        category: "Credential Management",
        cwe: "CWE-922",
        cvss_v4: "7.1 (High)"
      }
    ]
  }, null, 2));

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    currentFile,
    "--baseline",
    baselineFile,
    "--output",
    markdownOutput
  ], { cwd: process.cwd() });

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    currentFile,
    "--baseline",
    baselineFile,
    "--format",
    "html",
    "--output",
    htmlOutput
  ], { cwd: process.cwd() });

  const markdown = fs.readFileSync(markdownOutput, "utf8");
  const html = fs.readFileSync(htmlOutput, "utf8");

  assert.match(markdown, /Change Over Time/);
  assert.match(markdown, /Baseline target: demo-repo/);
  assert.match(markdown, /New findings: 1/);
  assert.match(markdown, /Fixed findings: 1/);
  assert.match(markdown, /Regressed findings: 1/);
  assert.match(markdown, /Improved findings: 1/);
  assert.match(markdown, /New: Sensitive token stored in browser localStorage \(High\) at src\/storage\.js:20/);
  assert.match(markdown, /Fixed: Non-local plaintext HTTP endpoint referenced previously at src\/http\.js:9 \(Medium\)/);
  assert.match(markdown, /Regressed: Dynamic code execution via eval detected moved from Medium to High at src\/index\.js:3/);
  assert.match(markdown, /Improved: Potential hardcoded credential detected moved from High to Medium at src\/config\.js:12/);

  assert.match(html, /Change Over Time/);
  assert.match(html, /Baseline target: demo-repo/);
  assert.match(html, /New findings: 1/);
  assert.match(html, /Fixed findings: 1/);
  assert.match(html, /Regressed findings: 1/);
  assert.match(html, /Improved findings: 1/);
  assert.match(html, /Sensitive token stored in browser localStorage \(High\) at src\/storage\.js:20/);
  assert.match(html, /Non-local plaintext HTTP endpoint referenced previously at src\/http\.js:9 \(Medium\)/);
  assert.match(html, /Dynamic code execution via eval detected moved from Medium to High at src\/index\.js:3/);
  assert.match(html, /Potential hardcoded credential detected moved from High to Medium at src\/config\.js:12/);
});

test("generate-report explains intentionally unmapped findings instead of rendering N/A", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-report-empty-owasp-"));
  const inputFile = path.join(tempDir, "input.json");
  const markdownOutput = path.join(tempDir, "report.md");
  const htmlOutput = path.join(tempDir, "report.html");

  fs.writeFileSync(inputFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      target_surface: "repo",
      standard: "owasp-scvs",
      standard_family: "owasp-scvs",
      coverage_areas: ["dependency inventory review"],
      blind_spots: ["runtime validation"],
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "No common dependency manifest discovered",
        asset: ".",
        location: ".",
        category: "Assessment Coverage",
        cwe: "CWE-1104: Use of Unmaintained Third Party Components",
        cvss_v4: "0.0 (Info)",
        confidence: "Low",
        fix_effort: "S",
        framework_mapping: {
          standard: "owasp-scvs",
          control: "Dependency inventory coverage",
          asvs: [],
          nist: ["NIST SP 800-218 SSDF PW.4 Code and dependency review"],
          cis: ["CIS Controls v8 Control 2 Inventory and Control of Software Assets"],
          scvs: ["OWASP SCVS V1 Inventory", "OWASP SCVS V5 Component Analysis"],
          slsa: ["SLSA dependency and provenance verification support"],
          owasp: []
        },
        verification_tier: "heuristic-static",
        source_tool: "native-heuristic-scan",
        evidence: "No common package manifest or lockfile was found during repository traversal.",
        reproduction_steps: "1. Confirm the scan root.",
        business_impact: "Coverage is incomplete.",
        remediation: "Scan the actual project root."
      }
    ]
  }, null, 2));

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--output",
    markdownOutput
  ], { cwd: process.cwd() });

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--format",
    "html",
    "--output",
    htmlOutput
  ], { cwd: process.cwd() });

  const markdown = fs.readFileSync(markdownOutput, "utf8");
  const html = fs.readFileSync(htmlOutput, "utf8");

  assert.match(markdown, /ASVS mapping: No per-finding ASVS mapping supplied by scanner/);
  assert.match(markdown, /NIST mapping: NIST SP 800-218 SSDF PW\.4 Code and dependency review/);
  assert.match(markdown, /Status: Not set/);
  assert.match(markdown, /Owner: Unassigned/);
  assert.match(markdown, /Due date: Not scheduled/);
  assert.match(markdown, /CIS mapping: CIS Controls v8 Control 2 Inventory and Control of Software Assets/);
  assert.match(markdown, /SCVS mapping: OWASP SCVS V1 Inventory; OWASP SCVS V5 Component Analysis/);
  assert.match(markdown, /SLSA mapping: SLSA dependency and provenance verification support/);
  assert.match(markdown, /OWASP mapping: Not applicable for coverage-only finding/);
  assert.match(html, /Not applicable for coverage-only finding/);
  assert.match(html, /<dt>Status<\/dt>\s*<dd>Not set<\/dd>/);
  assert.match(html, /<dt>Owner<\/dt>\s*<dd>Unassigned<\/dd>/);
  assert.match(html, /<dt>Due date<\/dt>\s*<dd>Not scheduled<\/dd>/);
});

test("generate-report uses readable fallback labels instead of raw N\\/A for missing finding metadata", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-report-fallbacks-"));
  const inputFile = path.join(tempDir, "input.json");
  const markdownOutput = path.join(tempDir, "report.md");
  const htmlOutput = path.join(tempDir, "report.html");

  fs.writeFileSync(inputFile, JSON.stringify({
    metadata: {
      target: "demo-repo",
      target_surface: "repo",
      standard: "owasp-top10",
      standard_family: "owasp-top10",
      coverage_areas: ["manual triage"],
      blind_spots: [],
      timestamp: new Date().toISOString(),
      generated_by: "test"
    },
    findings: [
      {
        title: "Sparse metadata finding",
        framework_mapping: {
          standard: "",
          control: "",
          asvs: [],
          nist: [],
          cis: [],
          scvs: [],
          slsa: [],
          owasp: []
        },
        evidence: "Observed during triage.",
        business_impact: "Needs manual review.",
        remediation: "Add missing metadata before sharing widely."
      }
    ]
  }, null, 2));

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--output",
    markdownOutput
  ], { cwd: process.cwd() });

  execFileSync("node", [
    path.join(process.cwd(), "scripts", "generate-report.js"),
    inputFile,
    "--format",
    "html",
    "--output",
    htmlOutput
  ], { cwd: process.cwd() });

  const markdown = fs.readFileSync(markdownOutput, "utf8");
  const html = fs.readFileSync(htmlOutput, "utf8");

  assert.doesNotMatch(markdown, /- Asset: `N\/A`/);
  assert.match(markdown, /- Asset: `Not specified`/);
  assert.match(markdown, /- Category: Not classified/);
  assert.match(markdown, /- Weakness: Not mapped/);
  assert.match(markdown, /- Severity: Not scored/);
  assert.match(markdown, /- Fix effort: Not estimated/);
  assert.match(markdown, /- Framework mapping: No primary framework mapping supplied by scanner/);
  assert.match(markdown, /- Verification tier: Not specified/);
  assert.match(html, /<dt>Asset<\/dt>\s*<dd>Not specified<\/dd>/);
  assert.match(html, /<dt>Framework mapping<\/dt>\s*<dd>No primary framework mapping supplied by scanner<\/dd>/);
});
