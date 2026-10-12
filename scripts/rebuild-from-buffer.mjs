// Rebuild a deployed program binary from the Write transactions that filled its deploy buffer.
// Works after the program has been closed, as long as the RPC endpoint serves the history.
//   RPC_URL=<endpoint> node scripts/rebuild-from-buffer.mjs <BUFFER_ADDRESS> <out.so>
import { writeFileSync } from "node:fs";
const RPC = process.env.RPC_URL || "https://api.mainnet-beta.solana.com";
const LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const rpc = async (m, p) => { for (let t = 0; t < 8; t++) { const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) }); if (r.status === 429) { await new Promise((x) => setTimeout(x, 1200 * (t + 1))); continue; } const j = await r.json(); if (j.error) { await new Promise((x) => setTimeout(x, 800 * (t + 1))); continue; } return j.result; } throw new Error(`${m}: gave up`); };
const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = (s) => { let b = [0]; for (const c of s) { let x = ALPHA.indexOf(c); for (let i = 0; i < b.length; i++) { x += b[i] * 58; b[i] = x & 255; x >>= 8; } while (x) { b.push(x & 255); x >>= 8; } } for (const c of s) { if (c === "1") b.push(0); else break; } return Buffer.from(b.reverse()); };
const [buffer, out] = process.argv.slice(2);
const sigs = [];
let before;
for (;;) { const page = await rpc("getSignaturesForAddress", [buffer, { limit: 1000, ...(before ? { before } : {}) }]); sigs.push(...page); if (page.length < 1000) break; before = page.at(-1).signature; }
const ok = sigs.filter((s) => !s.err);
console.log(`buffer transactions: ${sigs.length} (${sigs.length - ok.length} failed, skipped)`);
const chunks = [];
let done = 0;
for (let i = 0; i < ok.length; i += 6) {
  const txs = await Promise.all(ok.slice(i, i + 6).map((s) => rpc("getTransaction", [s.signature, { encoding: "json", maxSupportedTransactionVersion: 0 }])));
  for (const tx of txs) {
    if (!tx) continue;
    const keys = [...tx.transaction.message.accountKeys, ...(tx.meta?.loadedAddresses?.writable || []), ...(tx.meta?.loadedAddresses?.readonly || [])];
    for (const ix of tx.transaction.message.instructions) {
      if (keys[ix.programIdIndex] !== LOADER) continue;
      const d = b58(ix.data);
      // UpgradeableLoaderInstruction::Write { offset: u32, bytes: Vec<u8> } = tag 1, offset, u64 length, bytes.
      if (d.readUInt32LE(0) !== 1) continue;
      const offset = d.readUInt32LE(4);
      const len = Number(d.readBigUInt64LE(8));
      chunks.push({ offset, bytes: d.subarray(16, 16 + len) });
    }
  }
  done += 6;
  if (done % 120 === 0) process.stderr.write(`  ${Math.min(done, ok.length)}/${ok.length}\n`);
  await new Promise((r) => setTimeout(r, 150));
}
chunks.sort((a, b) => a.offset - b.offset);
const size = Math.max(...chunks.map((c) => c.offset + c.bytes.length));
const bin = Buffer.alloc(size);
const covered = new Uint8Array(size);
for (const c of chunks) { c.bytes.copy(bin, c.offset); covered.fill(1, c.offset, c.offset + c.bytes.length); }
const gaps = covered.reduce((n, v) => n + (v ? 0 : 1), 0);
writeFileSync(out, bin);
console.log(`write chunks: ${chunks.length}, rebuilt size ${size} bytes, bytes never written: ${gaps}, ELF magic: ${bin.subarray(0, 4).toString("hex") === "7f454c46"}`);
