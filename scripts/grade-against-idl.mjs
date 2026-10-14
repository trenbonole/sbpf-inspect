// Grade an sbpf-inspect report against an Anchor IDL, in the current format or the legacy one.
//   node scripts/grade-against-idl.mjs <report.json> <idl.json> [program.so] [--verbose]
// Instructions match by discriminator, computed from the name when a legacy IDL omits it. With the
// program file, account lists are also graded leaving out IDL accounts whose names never occur in the
// binary: the program cannot check those by name, so they are usually IDL-only additions.
// Argument layouts are graded on each instruction's fixed-size prefix, with defined structs expanded
// into their fields; the prefix ends at the first vector, string or option.
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
// Argument layouts.
const PRIM = { bool: 1, u8: 1, i8: 1, u16: 2, i16: 2, u32: 4, i32: 4, f32: 4, u64: 8, i64: 8, f64: 8, u128: 16, i128: 16, pubkey: 32, publicKey: 32 };
const types = new Map((idl.types || []).map((t) => [t.name, t]));
/** The fixed-size fields an argument list starts with, defined structs expanded, and whether that is all of it. */
function expected(args) {
  const fields = [];
  let off = 0, complete = true;
  const walk = (t, depth) => {
    if (!complete || depth > 16) return void (complete = false);
    if (typeof t === "string") {
      if (PRIM[t] === undefined) return void (complete = false);
      fields.push({ offset: off, size: PRIM[t], elem: PRIM[t] });
      off += PRIM[t];
      return;
    }
    if (t.array && typeof t.array[1] === "number") {
      const [inner, n] = t.array;
      if (typeof inner === "string" && PRIM[inner] !== undefined) {
        fields.push({ offset: off, size: PRIM[inner] * n, elem: PRIM[inner] });
        off += PRIM[inner] * n;
        return;
      }
      for (let k = 0; k < n && complete; k++) walk(inner, depth + 1);
      return;
    }
    const def = t.defined !== undefined ? types.get(typeof t.defined === "string" ? t.defined : t.defined.name) : null;
    if (def?.type?.kind === "struct") {
      for (const f of def.type.fields || []) if (complete) walk(f.type !== undefined ? f.type : f, depth + 1);
      return;
    }
    if (def?.type?.kind === "enum" && (def.type.variants || []).every((v) => !v.fields || v.fields.length === 0)) {
      fields.push({ offset: off, size: 1, elem: 1 });
      off += 1;
      return;
    }
    complete = false;
  };
  for (const a of args) if (complete) walk(a.type, 0);
  return { fields, fixed: off, complete };
}
/** Points where a field may end or begin: field edges, and splits inside arrays (by element) and 16- or 32-byte values (by 8 bytes). */
function points(exp, fixed) {
  const pts = new Set([0, fixed]);
  for (const e of exp) {
    pts.add(e.offset);
    pts.add(e.offset + e.size);
    const step = e.elem < e.size ? e.elem : e.size === 16 || e.size === 32 ? 8 : e.size;
    for (let p = e.offset + step; p < e.offset + e.size; p += step) pts.add(p);
  }
  return pts;
}
/** Grade the layouts of `found` instructions (each with its discriminator and `arguments`). */
function gradeArgs(found) {
  const A = { exact: 0, consistent: 0, read: 0, gradable: 0, none: 0, missing: 0, noArgs: 0, noArgsRight: 0, ungradable: 0 };
  for (const i of found) {
    const want = truth.get(i.discriminator);
    const e = expected(want.args || []);
    const a = i.arguments;
    if (e.fixed === 0 && !e.complete) { A.ungradable++; continue; }
    if (e.fixed === 0) { A.noArgs++; if (a && a.fields.length === 0) A.noArgsRight++; continue; }
    A.gradable++;
    if (!a) { A.missing++; continue; }
    if (a.fields.length === 0) { A.none++; continue; }
    A.read++;
    const pts = points(e.fields, e.fixed);
    const inPrefix = a.fields.filter((f) => f.offset < e.fixed);
    const consistent = inPrefix.every((f) => pts.has(f.offset) && (f.offset + f.size > e.fixed || pts.has(f.offset + f.size)));
    const boundaries = new Set(inPrefix.map((f) => f.offset));
    const exact = consistent && e.fields.every((f) => boundaries.has(f.offset)) && (e.complete ? a.fixed_size === e.fixed : a.fixed_size >= e.fixed);
    if (consistent) A.consistent++;
    if (exact) A.exact++;
    if (verbose && !exact) {
      const show = (fs) => fs.map((f) => `${f.offset}+${f.size}${f.copied ? "c" : ""}`).join(" ");
      console.log(`  ${want.name} arguments
    idl  : ${show(e.fields)}${e.complete ? "" : " ..."}
    found: ${show(a.fields)}`);
    }
  }
  return A;
}
const A = gradeArgs(right);
console.log(`argument layouts: ${A.gradable} instructions with a fixed-size prefix: ${A.exact} exact, ${A.read - A.exact} not, ${A.none} with no reads found, ${A.missing} without a layout`);
console.log(`  precision: ${A.consistent} of ${A.read} layouts put every field edge on a real field boundary`);
console.log(`  no arguments: ${A.noArgsRight} of ${A.noArgs} have an empty layout; ${A.ungradable} start with a variable-size argument and are not graded`);

// Instructions found by their discriminator alone. The IDL names those it lists; the others are
// either missing from the IDL or wrong.
const unnamed = r.unnamed_instructions || [];
const unnamedInIdl = unnamed.filter((u) => truth.has(u.discriminator));
const unnamedNotInIdl = unnamed.filter((u) => !truth.has(u.discriminator));
console.log(`unnamed instructions: ${unnamed.length} found, ${unnamedInIdl.length} are IDL instructions, ${unnamedNotInIdl.length} not in IDL`);
if (unnamedInIdl.length) console.log("  IDL names:", unnamedInIdl.map((u) => truth.get(u.discriminator).name).join(", "));
if (unnamedNotInIdl.length) console.log("  not in IDL:", unnamedNotInIdl.map((u) => u.text ?? u.discriminator).join(", "));
if (unnamedInIdl.length) {
  const U = gradeArgs(unnamedInIdl);
  console.log(`  their argument layouts: ${U.gradable} with a fixed-size prefix: ${U.exact} exact, ${U.read - U.exact} not, ${U.none} with no reads found, ${U.missing} without a layout; precision ${U.consistent} of ${U.read}; no arguments: ${U.noArgsRight} of ${U.noArgs} empty`);
}
console.log(`referenced (called, not implemented): ${r.anchor.instructions.filter((i) => i.status === "referenced").map((i) => i.name).join(", ") || "none"}`);
console.log(`sbpf ${r.elf.sbpf_version}, ${r.syscalls.length} named calls, ${r.constants.lddw + r.constants.mov32_hor64} 64-bit immediates, diagnostics ${r.diagnostics.length}`);
