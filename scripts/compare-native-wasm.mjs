// Runs the WebAssembly build and the native CLI on the same files and checks
// that the two reports are identical.
//   node scripts/compare-native-wasm.mjs <program.so>...
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const wasm = require("../pkg/sbpf_inspect.js");
const cli = fileURLToPath(new URL("../target/release/sbpf-inspect" + (process.platform === "win32" ? ".exe" : ""), import.meta.url));

let failed = 0;
for (const file of process.argv.slice(2)) {
  const bytes = readFileSync(file);
  const t0 = performance.now();
  const fromWasm = wasm.inspect(bytes);
  const ms = (performance.now() - t0).toFixed(1);
  const fromNative = execFileSync(cli, [file, "--compact"], { encoding: "utf8" }).trim();
  const same = fromWasm === fromNative;
  if (!same) failed++;
  const r = JSON.parse(fromWasm);
  console.log(`${same ? "SAME" : "DIFFERENT"}  ${file}  wasm ${ms} ms  ${r.anchor.instructions.length} instructions, ${r.anchor.accounts.length} accounts, ${r.syscalls.length} named calls`);
}
console.log(wasm.engineVersion());
process.exit(failed ? 1 : 0);
