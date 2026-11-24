import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

// Official SARIF 2.1.0 JSON schema (https://json.schemastore.org/sarif-2.1.0.json,
// $id = OASIS sarif-spec Schemata/sarif-schema-2.1.0.json), vendored so tests run offline.
const schema = JSON.parse(readFileSync(new URL('./sarif-schema-2.1.0.json', import.meta.url), 'utf8'));

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

/** Returns the schema violations of a SARIF document (empty array = valid). */
export function validateSarif(doc: string | object): string[] {
	const data = typeof doc === 'string' ? JSON.parse(doc) : doc;
	if (validate(data)) return [];
	return (validate.errors || []).map((e) => `${e.instancePath || '/'} ${e.message}`);
}
