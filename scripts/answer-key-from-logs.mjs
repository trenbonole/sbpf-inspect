// Independent answer key for an Anchor program: pair the first 8 bytes of every
// call to it with the `Instruction: <Name>` line the program logged for that call.
//   RPC_URL=<endpoint> node scripts/answer-key-from-logs.mjs <PROGRAM_ID> <out.json>
import { writeFileSync } from "node:fs";

const RPC = process.env.RPC_URL || "https://api.mainnet-beta.solana.com";
const rpc = async (m, p) => {
  for (let t = 0; t < 8; t++) {
    const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) });
    if (r.status === 429) { await new Promise((x) => setTimeout(x, 800 * (t + 1))); continue; }
    const j = await r.json();
    if (j.error) { await new Promise((x) => setTimeout(x, 600 * (t + 1))); continue; }
    return j.result;
  }
  return null;
};
const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = (s) => { let b = [0]; for (const c of s) { let x = ALPHA.indexOf(c); for (let i = 0; i < b.length; i++) { x += b[i] * 58; b[i] = x & 255; x >>= 8; } while (x) { b.push(x & 255); x >>= 8; } } for (const c of s) { if (c === "1") b.push(0); else break; } return Buffer.from(b.reverse()); };

const [program, out] = process.argv.slice(2);
const sigs = [];
let before;
for (;;) { const page = await rpc("getSignaturesForAddress", [program, { limit: 1000, ...(before ? { before } : {}) }]); if (!page?.length) break; sigs.push(...page); if (page.length < 1000) break; before = page.at(-1).signature; }
console.log(`transactions: ${sigs.length}`);

const pairs = new Map(); // disc hex -> { names: Map<name,count>, calls, firstSlot, lastSlot }
let calls = 0, matched = 0, txs = 0, missingTx = 0;
for (let i = 0; i < sigs.length; i += 8) {
  const batch = sigs.slice(i, i + 8);
  const got = await Promise.all(batch.map((s) => rpc("getTransaction", [s.signature, { encoding: "json", maxSupportedTransactionVersion: 0 }])));
  for (const [k, tx] of got.entries()) {
    if (!tx) { missingTx++; continue; }
    txs++;
    const keys = [...tx.transaction.message.accountKeys, ...(tx.meta?.loadedAddresses?.writable || []), ...(tx.meta?.loadedAddresses?.readonly || [])];
    // Calls to the program in execution order: each outer instruction, then its inner ones.
    const order = [];
    tx.transaction.message.instructions.forEach((ix, idx) => {
      if (keys[ix.programIdIndex] === program) order.push(ix.data);
      const inner = (tx.meta?.innerInstructions || []).find((g) => g.index === idx);
      for (const iix of inner?.instructions || []) if (keys[iix.programIdIndex] === program) order.push(iix.data);
    });
    // The log lines: each `Program <id> invoke` of ours, then the handler's `Instruction:` line.
    let callIdx = -1, waiting = false;
    for (const line of tx.meta?.logMessages || []) {
      if (line.startsWith(`Program ${program} invoke`)) { callIdx++; waiting = true; continue; }
      if (line.startsWith("Program ") && line.includes(" invoke [")) { waiting = false; continue; }
      if (waiting && line.startsWith("Program log: Instruction: ")) {
        waiting = false;
        const data = order[callIdx];
        if (!data) continue;
        const disc = b58(data).subarray(0, 8).toString("hex");
        const name = line.slice("Program log: Instruction: ".length).trim();
        const e = pairs.get(disc) || { names: new Map(), calls: 0, firstSlot: batch[k].slot, lastSlot: batch[k].slot };
        e.names.set(name, (e.names.get(name) || 0) + 1);
        e.calls++; e.firstSlot = Math.min(e.firstSlot, batch[k].slot); e.lastSlot = Math.max(e.lastSlot, batch[k].slot);
        pairs.set(disc, e);
        matched++;
      }
    }
    calls += order.length;
  }
  if (i % 400 === 0) process.stderr.write(`  ${i}/${sigs.length}\n`);
}
console.log(`decoded ${txs} transactions (${missingTx} unavailable), ${calls} calls to the program, ${matched} paired with an Instruction log line`);
const key = [...pairs].map(([disc, e]) => ({ discriminator: disc, names: Object.fromEntries(e.names), calls: e.calls, firstSlot: e.firstSlot, lastSlot: e.lastSlot }));
key.sort((a, b) => b.calls - a.calls);
for (const k of key) console.log(`  ${k.discriminator}  ${String(k.calls).padStart(5)} calls  ${Object.keys(k.names).join(" / ")}  slots ${k.firstSlot}..${k.lastSlot}`);
writeFileSync(out, JSON.stringify({ program, transactions: txs, calls, paired: matched, key }, null, 1));
