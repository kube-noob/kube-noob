// Validate a JSON document against a pinned schema, with ajv, choosing the dialect the schema declares.
//
// Python's `jsonschema` is not usable for either schema this repository pins. OSCAL's TokenDatatype pattern is
// `^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$`, and Python's `re` cannot compile a Unicode property escape, so it raises on
// every document rather than validating one. ajv compiles it.
//
// Two dialects, because the two schemas are not the same vintage:
//
//   * SARIF 2.1.0 (OASIS) declares draft-04 and uses the draft-04 `id` keyword. Ajv 8 refuses `id` outright
//     ('NOT SUPPORTED: keyword "id", use "$id"'), so a draft-04 schema is compiled by ajv-draft-04. Rewriting the
//     schema to draft-07 instead would mean validating against a document the committee did not publish, and
//     `exclusiveMinimum` means something different in the two drafts.
//   * NIST's OSCAL declares 2020-12 while using `definitions`. Its `$schema` is dropped so ajv uses its own
//     configured dialect rather than trying to fetch the meta-schema over the network.
//
//   npm install --no-save ajv@8.17.1 ajv-formats@3.0.1 ajv-draft-04@1.0.0
//   node scripts/json_schema_validate.mjs tests/fixtures/sarif/sarif-schema-2.1.0.json out.sarif.json
//
// Exits 0 and prints VALID, or exits 1 and prints up to 25 errors with their instance paths.
import Ajv from "ajv";
import Ajv04 from "ajv-draft-04";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";

const [schemaPath, docPath] = process.argv.slice(2);
if (!schemaPath || !docPath) {
  console.error("usage: node scripts/json_schema_validate.mjs <schema.json> <document.json>");
  process.exit(2);
}
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const draft04 = typeof schema.$schema === "string" && schema.$schema.includes("draft-04");
let ajv;
if (draft04) {
  ajv = new Ajv04({ strict: false, allErrors: true, allowUnionTypes: true });
} else {
  delete schema.$schema;
  ajv = new Ajv({ strict: false, allErrors: true, allowUnionTypes: true });
}
addFormats(ajv);
const validate = ajv.compile(schema);
if (validate(JSON.parse(readFileSync(docPath, "utf8")))) {
  console.log(`VALID (${draft04 ? "draft-04" : "draft-07"})`);
  process.exit(0);
}
console.log(`INVALID: ${validate.errors.length} error(s)`);
for (const e of validate.errors.slice(0, 25)) {
  console.log(" ", e.instancePath || "/", e.message, JSON.stringify(e.params));
}
process.exit(1);
