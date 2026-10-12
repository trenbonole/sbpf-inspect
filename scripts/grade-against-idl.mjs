// Grade an sbpf-inspect report against an Anchor IDL, in the current format or the legacy one.
//   node scripts/grade-against-idl.mjs <report.json> <idl.json> [program.so] [--verbose]
// Instructions match by discriminator, computed from the name when a legacy IDL omits it. With the
// program file, account lists are also graded leaving out IDL accounts whose names never occur in the
// binary: the program cannot check those by name, so they are usually IDL-only additions.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const args = process.argv.slice(2);
const verbose = args.includes("--verbose");
const [reportPath, idlPath, programPath] = args.filter((a) => !a.startsWith("--"));
const r = JSON.parse(readFileSync(reportPath, "utf8"));
const idl = JSON.parse(readFileSync(idlPath, "utf8"));
const binary = programPath ? readFileSync(programPath).toString("latin1") : null;
const hex = (a) => Buffer.from(a).toString("hex");
const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
const norm = (s) => s.replace(/_/g, "").toLowerCase();
const sha8 = (s) => createHash("sha256").update(s).digest().subarray(0, 8).toString("hex");
const flat = (accounts) =>
  accounts.flatMap((a) => (a.accounts ? flat(a.accounts) : [{ name: a.name, writable: !!(a.writable ?? a.isMut), signer: !!(a.signer ?? a.isSigner) }]));

// Instructions.
const truth = new Map(idl.instructions.map((i) => [i.discriminator ? hex(i.discriminator) : sha8("global:" + snake(i.name)), i]));
const got = r.anchor.instructions.filter((i) => i.status === "implemented");
const right = got.filter((i) => truth.has(i.discriminator));
const extra = got.filter((i) => !truth.has(i.discriminator));
const missed = [...truth.entries()].filter(([d]) => !got.some((i) => i.discriminator === d)).map(([, i]) => i.name);
console.log(`instructions: ${right.length}/${truth.size} recovered with matching discriminator, ${extra.length} not in IDL`);
if (extra.length) console.log("  not in IDL:", extra.map((i) => i.name).join(", "));
if (missed.length) console.log("  missed:", missed.join(", "));

// Account and event types.
for (const [kind, ns, list, recovered] of [["accounts", "account", idl.accounts || [], r.anchor.accounts], ["events", "event", idl.events || [], r.anchor.events]]) {
  const t = new Map(list.map((a) => [a.name, a.discriminator ? hex(a.discriminator) : sha8(`${ns}:${a.name}`)]));
  const ok = recovered.filter((a) => t.get(a.name) === a.discriminator);
  const notIn = recovered.filter((a) => t.get(a.name) !== a.discriminator);
  console.log(`${kind}: ${ok.length}/${t.size} recovered, ${notIn.length} not in IDL`);
  if (notIn.length) console.log("  not in IDL:", notIn.map((a) => a.name).join(", "));
}

// Per-instruction account lists.
let lists = 0, exact = 0, backedExact = 0, n = 0, w = 0, s = 0, wExtra = 0, sExtra = 0;
for (const i of right) {
  if (!i.accounts) continue;
  lists++;
  const want = flat(truth.get(i.discriminator).accounts);
  const gotNames = i.accounts.map((a) => norm(a.name));
  let flags = true;
  for (const a of want) {
    const m = i.accounts.find((x) => norm(x.name) === norm(a.name));
    if (!m) continue;
    n++;
    if (m.writable === a.writable) w++; else { flags = false; if (m.writable) wExtra++; }
    if (m.signer === a.signer) s++; else { flags = false; if (m.signer) sExtra++; }
  }
  const same = (names) => flags && JSON.stringify(names) === JSON.stringify(gotNames);
  if (same(want.map((a) => norm(a.name)))) exact++;
  const backed = want.filter((a) => !binary || binary.includes(snake(a.name)) || gotNames.includes(norm(a.name))).map((a) => norm(a.name));
  const ok = same(backed);
  if (ok) backedExact++;
  if (verbose && !ok) {
    const show = (list) => list.map((a) => a.name + (a.writable ? "[w]" : "") + (a.signer ? "[s]" : "")).join(", ");
    console.log(`  ${truth.get(i.discriminator).name}\n    idl  : ${show(want)}\n    found: ${show(i.accounts)}`);
  }
}
console.log(`account lists: ${lists} of ${right.length} instructions, ${exact} exact${binary ? `, ${backedExact} exact counting only accounts named in the binary` : ""}`);
console.log(`  flags on ${n} accounts: writable ${w} agree (${wExtra} writable where the IDL says not), signer ${s} agree (${sExtra} signer where the IDL says not)`);
console.log(`referenced (called, not implemented): ${r.anchor.instructions.filter((i) => i.status === "referenced").map((i) => i.name).join(", ") || "none"}`);
console.log(`sbpf ${r.elf.sbpf_version}, ${r.syscalls.length} named calls, ${r.constants.lddw + r.constants.mov32_hor64} 64-bit immediates, diagnostics ${r.diagnostics.length}`);
