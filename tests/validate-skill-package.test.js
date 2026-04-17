const test = require("node:test");
const assert = require("node:assert/strict");

const { validate } = require("../scripts/validate-skill-package.js");

test("validate-skill-package keeps repository metadata aligned", () => {
  const result = validate();

  assert.equal(result.ok, true);
  assert.equal(result.skill.name, "defensive-appsec-review-skill");
  assert.equal(result.skill.display_name, "Defensive AppSec Review Skill");
  assert.equal(result.skill.version, require("../package.json").version);
  assert.equal(result.skill.author, "jovd83");
  assert.deepEqual(result.issues, []);
});
