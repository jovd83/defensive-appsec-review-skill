#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SKILL_PATH = path.join(ROOT, "SKILL.md");
const PACKAGE_PATH = path.join(ROOT, "package.json");
const OPENAI_PATH = path.join(ROOT, "agents", "openai.yaml");

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function stripQuotes(value) {
  const trimmed = String(value || "").trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function getFrontmatter(markdown) {
  const match = markdown.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) {
    throw new Error("SKILL.md is missing YAML frontmatter.");
  }
  return match[1];
}

function parseSimpleYaml(yamlText) {
  const root = {};
  const stack = [{ indent: -1, value: root }];

  for (const rawLine of yamlText.split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trimStart().startsWith("#")) {
      continue;
    }

    const indent = rawLine.match(/^ */)[0].length;
    const trimmed = rawLine.trim();
    const separatorIndex = trimmed.indexOf(":");

    if (separatorIndex === -1) {
      throw new Error(`Unsupported frontmatter line: ${rawLine}`);
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const rawValue = trimmed.slice(separatorIndex + 1).trim();

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
      stack.pop();
    }

    const container = stack[stack.length - 1].value;
    if (rawValue === "") {
      container[key] = {};
      stack.push({ indent, value: container[key] });
      continue;
    }

    container[key] = stripQuotes(rawValue);
  }

  return root;
}

function parseOpenAiYaml(yamlText) {
  const parsed = parseSimpleYaml(yamlText);
  return {
    displayName: parsed.interface?.display_name || "",
    shortDescription: parsed.interface?.short_description || "",
    defaultPrompt: parsed.interface?.default_prompt || "",
    author: parsed.interface?.author || "",
    version: parsed.interface?.version || ""
  };
}

function validate() {
  const skillText = readText(SKILL_PATH);
  const skillFrontmatter = parseSimpleYaml(getFrontmatter(skillText));
  const packageJson = JSON.parse(readText(PACKAGE_PATH));
  const openAiMetadata = parseOpenAiYaml(readText(OPENAI_PATH));

  const issues = [];
  const metadata = skillFrontmatter.metadata || {};

  const requiredFrontmatter = ["name", "description", "license", "compatibility"];
  for (const key of requiredFrontmatter) {
    if (!skillFrontmatter[key]) {
      issues.push(`Missing required SKILL frontmatter field: ${key}`);
    }
  }

  if (!metadata["display-name"]) {
    issues.push("Missing SKILL frontmatter metadata.display-name");
  }
  if (!metadata.version) {
    issues.push("Missing SKILL frontmatter metadata.version");
  }
  if (!metadata.author) {
    issues.push("Missing SKILL frontmatter metadata.author");
  }

  if (!String(skillFrontmatter.description || "").startsWith("Use when")) {
    issues.push("SKILL description should begin with 'Use when' for stronger Agent Skills triggering.");
  }

  if (String(skillFrontmatter.description || "").length > 1024) {
    issues.push("SKILL description exceeds the 1024 character Agent Skills limit.");
  }

  if (skillFrontmatter.name !== packageJson.name) {
    issues.push(`Skill name mismatch: SKILL.md=${skillFrontmatter.name} package.json=${packageJson.name}`);
  }

  if (metadata.version !== packageJson.version) {
    issues.push(`Version mismatch: SKILL.md=${metadata.version} package.json=${packageJson.version}`);
  }

  if (metadata.author !== packageJson.author) {
    issues.push(`Author mismatch: SKILL.md=${metadata.author} package.json=${packageJson.author}`);
  }

  if (metadata["display-name"] !== openAiMetadata.displayName) {
    issues.push(`Display name mismatch: SKILL.md=${metadata["display-name"]} agents/openai.yaml=${openAiMetadata.displayName}`);
  }

  if (metadata.version !== openAiMetadata.version) {
    issues.push(`Version mismatch: SKILL.md=${metadata.version} agents/openai.yaml=${openAiMetadata.version}`);
  }

  if (metadata.author !== openAiMetadata.author) {
    issues.push(`Author mismatch: SKILL.md=${metadata.author} agents/openai.yaml=${openAiMetadata.author}`);
  }

  const result = {
    ok: issues.length === 0,
    skill: {
      name: skillFrontmatter.name,
      display_name: metadata["display-name"],
      version: metadata.version,
      author: metadata.author
    },
    issues
  };

  return result;
}

function main() {
  const result = validate();
  if (!result.ok) {
    console.error(JSON.stringify(result, null, 2));
    process.exit(1);
  }

  console.log(JSON.stringify(result, null, 2));
}

module.exports = {
  validate,
  parseSimpleYaml,
  parseOpenAiYaml,
  getFrontmatter
};

if (require.main === module) {
  main();
}
