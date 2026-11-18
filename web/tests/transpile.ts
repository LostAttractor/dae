import { readFile } from "node:fs/promises";
import { transform } from "esbuild";

export async function transpile(name: "api" | "certificate", format: "esm" | "cjs", apiTarget?: string): Promise<string> {
  const source = await readFile(new URL(`../src/${name}.ts`, import.meta.url), "utf8");
  const { code } = await transform(source, {
    sourcefile: `${name}.ts`, loader: "ts", format, target: "es2022",
    define: apiTarget === undefined ? undefined : { __DAE_API_URL__: JSON.stringify(apiTarget) },
  });
  return code;
}
