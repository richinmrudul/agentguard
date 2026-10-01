import fs from "node:fs";

const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const packages = lock.packages || {};
const codex = packages["node_modules/@openai/codex"];
const linux = packages["node_modules/@openai/codex-linux-x64"];

const expected = {
  codexVersion: "0.159.2",
  codexIntegrity: "sha512-SE13C3nZCYoVL569BdegoOl6vwjb7o2sXOo7ivwVzaVoY0cswwi0/6pIE0TyO/C0vIkQh3jslExitET7PBTfIg==",
  linuxVersion: "0.159.2-linux-x64",
  linuxIntegrity: "sha512-RrCZ1X52wpa1lOsXtCtSyhjOFdQPh7LH5Ccv8HsKmd/2UXbUwxXFqWXFK3JzatquUNGtW/TLox5Y7qVOGkV0/Q=="
};

function requireEqual(actual, wanted, label) {
  if (actual !== wanted) {
    throw new Error(`${label} mismatch: ${actual} !== ${wanted}`);
  }
}

requireEqual(codex?.version, expected.codexVersion, "codex version");
requireEqual(codex?.integrity, expected.codexIntegrity, "codex integrity");
requireEqual(linux?.version, expected.linuxVersion, "linux x64 version");
requireEqual(linux?.integrity, expected.linuxIntegrity, "linux x64 integrity");

console.log(JSON.stringify({
  schema: "agentguard.codex-package-integrity",
  schema_version: 1,
  package: "@openai/codex",
  version: codex.version,
  integrity: codex.integrity,
  linux_x64_package: "@openai/codex@0.159.2-linux-x64",
  linux_x64_integrity: linux.integrity
}));
