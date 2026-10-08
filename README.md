# sbpf-inspect

Offline interface recovery for Solana sBPF programs. Give it a compiled program
(a `.so` file, or a dump of a deployed program) and it reports what the binary
contains and which Anchor instructions, accounts and events it implements. Every
name comes with the byte offsets of the evidence behind it.

It runs as a Rust library, a command-line tool, or a 178 KB WebAssembly module
for Node. It never executes the program and never touches the network.

## Results on real programs

Graded against the IDLs pump.fun publishes in
[pump-fun/pump-public-docs](https://github.com/pump-fun/pump-public-docs):

| Program | Instructions | Account types | Wrong names | Time (WebAssembly) |
|---|---|---|---|---|
| pump.fun bonding curve, `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | 56 of 56 | 7 of 7 | 0 | 64 ms |
| pump.fun AMM, `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` | 38 of 38 | 7 of 7 | 0 | 55 ms |

Every recovered discriminator matches the published IDL byte for byte. The
bonding-curve program also yields two account types its IDL does not list,
`GlobalConfig` and `Pool`. Both are pump AMM types, and their discriminators
match the AMM's IDL: the bonding curve checks them when it migrates a coin to the
AMM.

Measured 2026-10-08 on program data dumped near mainnet slot 454,696,749
(SHA-256 of the dumps: `a4b32d32…9f16` and `a8d05e69…697e`). The programs are
upgradeable, so a later dump can differ. To reproduce:

```sh
solana program dump -u mainnet-beta 6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P pump.so
curl -sLO https://raw.githubusercontent.com/pump-fun/pump-public-docs/main/idl/pump.json
sbpf-inspect pump.so > pump.report.json
node scripts/grade-against-idl.mjs pump.report.json pump.json
```

Event names are not recovered on either program, because the names do not
appear anywhere in the binaries. See [Limits](#limits).

## What it reports

**Observed facts**, read directly from the file:

- sBPF version, from `e_flags` the way the Solana loader maps it
- entrypoint, sections and their file offsets
- named call targets with every call site, flagged as registered syscalls or not
- printable strings in data sections

**Inferred names**, each kept only when corroborated:

- Anchor instructions, with the handler name, the name as logged, the
  discriminator, and where the discriminator and the log string sit
- Anchor's own IDL-management instructions, reported as framework instructions
- account and event types, with discriminator and evidence
- whether the program is Anchor, from the markers that say so

Unrecovered facts are listed under `unknowns` in every report.

## How it works

1. Parse the ELF with Blueshift's
   [`sbpf-disassembler`](https://github.com/blueshift-gg/sbpf).
2. Collect every 64-bit immediate the code loads, as `lddw` on sBPF v0 and v1 or
   as `mov32` plus `hor64` on v2 and later. Add every 8-byte window of the data
   sections. That set is everything the program could compare against.
3. Build candidate names. Instruction candidates come from Anchor's
   `Instruction: <Name>` log strings, trying every prefix because Rust packs
   literals back to back (`Instruction: BuyProgram log...`), and trying both
   snake spellings of digit words (`Step2` as `step2` and `step_2`). Account and
   event candidates come from every identifier-like substring of the data
   sections, because names often sit inside longer runs.
4. Hash each candidate the way Anchor does, `sha256("global:" + name)[..8]`,
   `sha256("account:" + Name)[..8]` or `sha256("event:" + Name)[..8]`, and keep
   the name only when those 8 bytes are in the set. A string that merely looks
   like a name is never reported as one.

## Usage

**Command line**

```sh
cargo install --path .
sbpf-inspect program.so            # pretty JSON
sbpf-inspect program.so --compact  # one line
```

Dump a deployed program with `solana program dump -u mainnet-beta <PROGRAM_ID> program.so`.
The zero padding at the end of a dump is fine.

**Node, through WebAssembly**

```sh
wasm-pack build --target nodejs --release --out-dir pkg --out-name sbpf_inspect
```

```js
const { inspect } = require("./pkg/sbpf_inspect.js");
const report = JSON.parse(inspect(require("node:fs").readFileSync("program.so")));
console.log(report.anchor.instructions.map((i) => i.name));
```

`inspect` throws on input that is not a parsable sBPF ELF.

**Rust**

```rust
let report = sbpf_inspect::inspect(&std::fs::read("program.so")?)?;
for ix in &report.anchor.instructions {
    println!("{} {:?}", ix.name, ix.discriminator);
}
```

## Output

Abridged report for the Anchor test program in `fixtures/anchor-demo`:

```json
{
  "elf": { "sbpf_version": "v0", "entrypoint_offset": 32272, "sections": ["…"] },
  "syscalls": [{ "name": "sol_log_data", "registered": true, "call_sites": [106664] }],
  "anchor": {
    "detected": true,
    "instructions": [
      {
        "name": "deposit_v2",
        "log_name": "DepositV2",
        "discriminator": "6d4b4599acda9213",
        "status": "corroborated",
        "log_string_offsets": [167991],
        "discriminator_evidence": [{ "kind": "lddw_immediate", "file_offset": 14152 }]
      }
    ],
    "accounts": [{ "name": "Settings", "discriminator": "dfb3a3beb1e043ad", "discriminator_evidence": ["…"] }],
    "events": [{ "name": "VaultDeposited", "discriminator": "3b3e2bc8dc686443", "discriminator_evidence": ["…"] }]
  },
  "unknowns": ["…"]
}
```

All offsets are byte offsets into the input file. Evidence kinds are
`lddw_immediate`, `mov32_hor64_immediate`, `data_bytes` and `string`.

## Limits

- Instruction names come from Anchor's `Instruction: <Name>` log strings.
  Programs built without those logs, native programs and other frameworks yield
  no instruction names.
- A discriminator counts as found only as a 64-bit immediate or as bytes in a
  data section. Other code shapes, such as two 32-bit comparisons, are missed.
- Account and event names are recovered only when the name appears somewhere in
  the binary. A recovered account type can belong to another program this one
  validates.
- Instruction arguments, account lists, constraints and error codes are not
  recovered yet.
- Tested on sBPF v0 binaries, which is what mainnet programs use today. The v2+
  immediate scan is covered by unit tests only.

## Development

```sh
cargo test                                   # unit tests and fixture tests
scripts/build-fixtures.sh                    # rebuild tests/fixtures from fixtures/ (needs cargo-build-sbf)
node scripts/compare-native-wasm.mjs a.so    # WebAssembly and native reports must be identical
node scripts/grade-against-idl.mjs report.json idl.json
```

`fixtures/anchor-demo` and `fixtures/native-demo` are small programs written
for the tests. Each item in them exercises one case, such as a name packed
against binary bytes, a digit spelling, a name that must stay unrecovered, or a
native program that logs a string shaped like an Anchor instruction.

## Credits and license

Built on Blueshift's `sbpf-disassembler` and `sbpf-common` (MIT). The
discriminator scheme is Anchor's.

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
