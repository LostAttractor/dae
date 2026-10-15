import { readFile, writeFile } from "node:fs/promises";
import openapiTS, { astToString } from "openapi-typescript";

const destination = new URL("../src/api.generated.ts", import.meta.url);
const schema = new URL("../../docs/api/openapi.json", import.meta.url);
const output = "// Generated from docs/api/openapi.json. Run pnpm run types:api to update.\n"
  + astToString(await openapiTS(schema, { alphabetize: true }));

if (process.argv.includes("--check")) {
  if (await readFile(destination, "utf8") !== output) {
    throw new Error("API types are out of date. Run pnpm run types:api.");
  }
} else {
  await writeFile(destination, output);
}
