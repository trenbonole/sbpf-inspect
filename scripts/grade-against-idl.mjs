// Grade an sbpf-inspect report against a published Anchor IDL.
//   node grade.mjs <report.json> <idl.json>
import { readFileSync } from "node:fs";
const [reportPath, idlPath] = process.argv.slice(2);
const r = JSON.parse(readFileSync(reportPath, "utf8"));
const idl = JSON.parse(readFileSync(idlPath, "utf8"));
const hex = (a) => Buffer.from(a).toString("hex");

const truth = new Map(idl.instructions.map((i) => [i.name, hex(i.discriminator)]));
const got = r.anchor.instructions.filter((i) => i.status === "implemented");
const referenced = r.anchor.instructions.filter((i) => i.status === "referenced");
const right = got.filter((i) => truth.get(i.name) === i.discriminator);
const wrong = got.filter((i) => truth.get(i.name) !== i.discriminator);
const missed = [...truth.keys()].filter((n) => !got.some((i) => i.name === n));
console.log(`instructions: ${right.length}/${truth.size} recovered with matching discriminator, ${wrong.length} not in IDL or mismatched`);
if (wrong.length) console.log("  not in IDL:", wrong.map((i) => i.name).join(", "));
if (missed.length) console.log("  missed:", missed.join(", "));

for (const [kind, list, recovered] of [["accounts", idl.accounts || [], r.anchor.accounts], ["events", idl.events || [], r.anchor.events]]) {
  const t = new Map(list.map((a) => [a.name, hex(a.discriminator)]));
  const ok = recovered.filter((a) => t.get(a.name) === a.discriminator);
  const extra = recovered.filter((a) => t.get(a.name) !== a.discriminator);
  console.log(`${kind}: ${ok.length}/${t.size} recovered, ${extra.length} not in IDL`);
  if (extra.length) console.log("  not in IDL:", extra.map((a) => a.name).join(", "));
}
console.log(`referenced (called, not implemented): ${referenced.map((i) => i.name).join(", ") || "none"}`);
console.log(`framework IDL instructions: ${r.anchor.instructions.filter((i) => i.status === "framework").length}, uncorroborated log strings: ${r.anchor.uncorroborated_instruction_logs.length}`);
console.log(`sbpf ${r.elf.sbpf_version}, ${r.syscalls.length} named calls, ${r.constants.lddw + r.constants.mov32_hor64} 64-bit immediates, diagnostics ${r.diagnostics.length}`);
