# sbpf-inspect

Offline interface recovery for Solana sBPF programs. Give it a compiled program
(a `.so` file, or a dump of a deployed program) and it reports what the binary
contains, which Anchor instructions, accounts and events it implements, and
each instruction's ordered account list with writable and signer flags. Every
name comes with the byte offsets of the evidence behind it.

It runs as a Rust library, a command-line tool, or a 301 KB WebAssembly module
for Node. It never executes the program and never touches the network.

## Results on real programs

### Instruction names

Four mainnet programs, each graded against an answer key the tool never sees:

| Program | Answer key | Instructions | Wrong names | Account types |
|---|---|---|---|---|
| pump.fun bonding curve, `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | published IDL | 56 of 56 | 0 | 7 of 7 |
| pump.fun AMM, `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` | published IDL | 38 of 38 | 0 | 7 of 7 |
| Bordrless companion, `6ZUM1gWBH9hBBNoJoaVAGwSftyZ6CUda6vUZTW9MsJuo`, sBPF v3 | source code | 27 of 27 | 0 | 3 of 6 |
| a closed-source launchpad, `BohF4FAftBwEBoa23sUgM8Vr5HL2nAHLx5s7b1iBK56f`, deleted by its owner | 2,263 runtime log lines | 23 of 23 called | 0 | 11 found, no key |

Notes on each:

- **pump.fun.** Every recovered discriminator matches the published IDL byte for
  byte. The bonding curve also yields two account types its IDL does not list,
  `GlobalConfig` and `Pool`. Both are pump AMM types, and the bonding curve
  checks them when it migrates a coin to the AMM.
- **Bordrless companion.** All 27 handlers in its
  [source](https://github.com/BordrlessDex/bordrless-programs) are recovered and
  none extra. The two instructions it calls on other programs, `burn` and `plan`,
  are reported as `referenced` rather than as handlers. Its published IDL lists
  21 of the 27; the other six were added since. Every instruction call it had
  received on mainnet carries a recovered name. Three of its six account type
  names never appear in the binary, so they cannot be recovered.
- **Deleted launchpad.** The program was closed four days after deployment, so
  there was no file to download. `scripts/rebuild-from-buffer.mjs` rebuilt it
  byte for byte from the upload transactions of its final deployment. The
  answer key comes from the program itself: in each of the 2,263 calls it
  received it logged the instruction it ran, and
  `scripts/answer-key-from-logs.mjs` pairs each call's first 8 bytes with that
  name. All 23 instructions it was ever called with are named correctly. The
  tool also recovers 30 handlers that were never called on mainnet, 11 account
  types and one event, `Graduated`; nothing outside the binary can grade those.

Older Anchor versions compile instruction dispatch byte by byte, which earlier
versions of this tool missed: Marinade, OpenBook v2 and Squads v4 yielded no
instruction names and Kamino Lending 5 of 66. Matching those byte comparisons
recovers all 155 of their IDL instructions, and on 200,000 random
discriminators per program it matched none.

### Account lists

The account-list method was developed on pump.fun, pump AMM, Bordrless and nine
more mainnet programs (Meteora DLMM and DAMM v2, Orca Whirlpools, Kamino
Lending, Squads v4, pump fees, Marinade, OpenBook v2, Drift). It is exact on all
56 pump.fun and 38 pump AMM instructions.

It was then measured once, unchanged, on 20 Anchor programs it had never been
run on, against each one's on-chain IDL. An instruction counts as exact when
every account name, the order and both flags match the IDL.

| Program | Instructions | Account lists exact |
|---|---|---|
| Mango v4, `4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg` | 103 of 103 | 99 of 103 |
| Zeta, `ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD` | 102 of 107 | 85 of 100 |
| marginfi v2, `MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA` | 87 of 91 | 75 of 87 |
| Jupiter Perpetuals, `PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu` | 59 of 59 | 52 of 59 |
| Drift Vaults, `vAuLTsyrvSfZRuRB3XgvkPwNGgYSs9YRYymVebLKoxR` | 38 of 46 | 38 of 38 |
| Raydium LaunchLab, `LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj` | 28 of 28 | 26 of 28 |
| Meteora Alpha Vault, `vaU6kP7iNEGkbmPkLmZfGwiGxd4Mob24QQCie5R9kd2` | 27 of 27 | 27 of 27 |
| Kamino Farms, `FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr` | 27 of 27 | 26 of 27 |
| Meteora Dynamic AMM, `Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB` | 26 of 26 | 25 of 26 |
| Meteora Dynamic Bonding Curve, `dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN` | 26 of 28 | 23 of 26 |
| Kamino Vault, `KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd` | 26 of 29 | 23 of 26 |
| Tensor cNFT marketplace, `TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp` | 20 of 21 | 1 of 20 |
| Metaplex Bubblegum, `BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY` | 17 of 17 | 11 of 17 |
| Pyth Solana Receiver, `rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ` | 13 of 13 | 13 of 13 |
| Jupiter DCA, `DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M` | 12 of 12 | 5 of 12 |
| Meteora Dynamic Vault, `24Uqj9JCLxUeoC3hGfh5W3s9FM9uCHDS2SG3LYwBpyTi` | 12 of 14 | 10 of 12 |
| Jito Tip Distribution, `4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7` | 10 of 10 | 9 of 10 |
| Metaplex Candy Machine Core, `CMACYFENjoBMHzapRXyo1JZkVS6EtaDDzkjMrmQLvr4J` | 8 of 8 | 8 of 8 |
| Jupiter Limit Order v2, `j1o2qRpjcyUwEvwtcfhEQefh773ZgjxcVRry7LDqg5X` | 8 of 8 | 8 of 8 |
| Lifinity v2, `2wT8Yq49kHgDzXuPxZSaeLaH1qbmGXtEyPy64bL7aD3c` | 3 of 3 | 3 of 3 |
| **Total** | **652 of 677** | **567 of 650 (87%)** |

On the 5,385 accounts compared, the writable flag agrees with the IDL on 5,373
and the signer flag on 5,368. The tool marked an account writable where the IDL
did not three times, and each time the IDL is out of date: marginfi's source
declares that account `mut`, and Zeta's binary raises ConstraintMut naming the
account. It never marked an account signer where the IDL did not.

Published IDLs often lag the deployed program, so they are an imperfect answer
key. The tool also named 133 implemented instructions these IDLs do not list
(Bubblegum's on-chain IDL has none of its `_v2` instructions). The Tensor binary
renames fields its IDL still lists under old names (`marketplace_program` for
`tcompProgram`, `rent_destination` for `rentDest`) and checks a `cosigner`
account the IDL lacks; mapping the renames alone makes 6 more of its lists
exact. Jupiter DCA's misses are mostly the tool's: in six instructions, token
accounts the program names only after loading the others (`user_in_ata`,
`fee_ata`) are listed last instead of in their place.

pump.fun was measured 2026-10-08 on program data dumped near mainnet slot
454,696,749 (SHA-256 of the dumps: `a4b32d32…9f16` and `a8d05e69…697e`); the
others on 2026-10-12, the 20-program set near slot 455,888,700. Programs are
upgradeable, so a later dump can differ. To reproduce a row:

```sh
solana program dump -u mainnet-beta 6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P pump.so
curl -sLO https://raw.githubusercontent.com/pump-fun/pump-public-docs/main/idl/pump.json
sbpf-inspect pump.so > pump.report.json
node scripts/grade-against-idl.mjs pump.report.json pump.json pump.so
```

For a program that publishes its IDL on chain, `anchor idl fetch <PROGRAM_ID>`
gives the answer key. Event names are recovered only when they appear in the
binary, which is rare. See [Limits](#limits).

## What it reports

**Observed facts**, read directly from the file:

- sBPF version, from `e_flags` the way the Solana loader maps it
- entrypoint, sections and their file offsets
- named call targets with every call site, flagged as registered syscalls or not
- printable strings in data sections

**Inferred names**, each kept only when corroborated:

- Anchor instructions, with the handler name, the name as logged, the
  discriminator, and where the discriminator and the log string sit. Each is
  marked `implemented` (a handler of this program) or `referenced` (an
  instruction it calls on another program)
- each instruction's accounts in order, with writable and signer flags, where
  each account is loaded, and the Anchor error codes the flags are read from
- Anchor's own IDL-management instructions, reported as framework instructions
- account and event types, with discriminator and evidence
- whether the program is Anchor, from the markers that say so, including the tag
  of Anchor's event self-calls, which carry events rather than instructions

Unrecovered facts are listed under `unknowns` in every report.

## How it works

1. Parse the ELF with Blueshift's
   [`sbpf-disassembler`](https://github.com/blueshift-gg/sbpf).
2. Collect every 64-bit immediate the code loads, as `lddw` (which mainnet v0
   and v3 programs both use) or as `mov32` plus `hor64` on v2 and later. Add
   every 8-byte window of the data sections. That set is everything the program
   could compare against. Also index every conditional jump that compares a
   register with a single byte, for dispatch compiled byte by byte.
3. Build candidate names. Instruction candidates come from Anchor's
   `Instruction: <Name>` log strings, trying every prefix because Rust packs
   literals back to back (`Instruction: BuyProgram log...`), and trying both
   snake spellings of digit words (`Step2` as `step2` and `step_2`). Account and
   event candidates come from every identifier-like substring of the data
   sections, because names often sit inside longer runs.
4. Hash each candidate the way Anchor does, `sha256("global:" + name)[..8]`,
   `sha256("account:" + Name)[..8]` or `sha256("event:" + Name)[..8]`, and keep
   the name only when those 8 bytes are in the set. An instruction name also
   counts when bytes 2 to 7 of its discriminator are compared one at a time, in
   order, by nearby jumps: the decision tree older Anchor versions compile
   dispatch to, which may test the first two bytes elsewhere. A string that
   merely looks like a name is never reported as one.
5. Decide whether each instruction is a handler. A discriminator the code
   compares right after loading it is dispatch, so the instruction is
   `implemented`. One that is only written to memory is building a call to
   another program, so it is `referenced`.

### Account lists

Anchor generates a `try_accounts` function for each instruction. It consumes the
accounts in field order, through a loader call for typed fields or by taking the
next account inline, and attaches the field's name to the error when a load
fails. Constraint checks raise numbered Anchor errors that carry the name too.

1. The instruction's `try_accounts` is the first function called after its log
   string, in control-flow order, that can raise AccountNotEnoughKeys (3005)
   within two call levels. Argument decoding, the handler and `exit` cannot.
2. A must-analysis over its control flow tracks which registers and stack slots
   hold the accounts slice through moves, spills and calls. Each call handed the
   slice, and each inline take that stores the shortened length back, is a load.
3. Account names are read where the code builds them: string slices in
   `.rodata`, names sBPF v3 code assembles from immediate stores, and small
   outlined functions that only build a name. A name passed to a function that
   never returns is a panic message, not an account.
4. Each load gets the first name its failure path reaches, and each error code
   the first name its path reaches. A nested Accounts struct is expanded in
   place. Names that only later checks mention, such as `init` accounts, fill
   the loads that named nothing, in the order the checks run.
5. Writable comes from ConstraintMut (2000). Signer comes from ConstraintSigner
   (2002) or AccountNotSigner (3010), raised by the checks or by the account's
   loader.

Each account's `position` says how its place was established: `loaded` (its own
load names it), `matched` (named only by later checks and matched to an unnamed
load) or `appended` (no load left to match, so its place is unknown).

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
for (const ix of report.anchor.instructions) {
  console.log(ix.name, (ix.accounts ?? []).map((a) => a.name + (a.writable ? " (w)" : "") + (a.signer ? " (s)" : "")));
}
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
        "name": "initialize",
        "log_name": "Initialize",
        "discriminator": "afaf6d1f0d989bed",
        "status": "implemented",
        "log_string_offsets": ["…"],
        "discriminator_evidence": [{ "kind": "lddw_immediate", "file_offset": "…", "use_after_load": "compare" }],
        "accounts_check_offset": 37216,
        "accounts": [
          { "name": "settings", "writable": true, "signer": true, "position": "matched", "load_offset": 37280, "error_codes": [2000, 2002, 2005] },
          { "name": "vault", "writable": true, "signer": true, "position": "matched", "load_offset": 37336, "error_codes": [2000, 2002, 2005] },
          { "name": "authority", "writable": true, "signer": true, "position": "loaded", "load_offset": 37392, "error_codes": [2000], "loader_error_codes": [3005, 3010] },
          { "name": "system_program", "writable": false, "signer": false, "position": "loaded", "load_offset": 37464, "error_codes": [], "loader_error_codes": [3005, 3008, 3009] }
        ]
      }
    ],
    "accounts": [{ "name": "Settings", "discriminator": "dfb3a3beb1e043ad", "discriminator_evidence": ["…"] }],
    "events": [{ "name": "VaultDeposited", "discriminator": "3b3e2bc8dc686443", "discriminator_evidence": ["…"] }]
  },
  "unknowns": ["…"]
}
```

All offsets are byte offsets into the input file. Evidence kinds are
`lddw_immediate`, `mov32_hor64_immediate`, `byte_compare_chain`, `data_bytes`
and `string`.

## Limits

- Instruction names come from Anchor's `Instruction: <Name>` log strings.
  Programs built without those logs, native programs and other frameworks yield
  no instruction names and no account lists. Drift logs only 3 of its
  instruction names, so only those 3 are recovered.
- A discriminator counts as found only as a 64-bit immediate, as bytes in a data
  section, or, for instructions, as a byte-by-byte comparison chain. Other code
  shapes, such as two 32-bit comparisons, are missed.
- Account and event names are recovered only when the name appears somewhere in
  the binary. A recovered account type can belong to another program this one
  validates.
- Account lists list only accounts whose field names the binary embeds. An
  account an IDL adds on its own, such as the `whirlpool_program` Orca's IDL
  appends to every instruction, is not listed.
- An account the program names only after loading the others can be listed
  last instead of in its place, as with Jupiter DCA's token accounts. Positions
  marked `matched` or `appended` rest on weaker evidence than `loaded`.
- Of the constraints, only `mut` and signer are reported. Others (`has_one`,
  `seeds`, `address`) show up as error codes but are not interpreted.
  Instruction arguments are not recovered.
- Tested on mainnet sBPF v0 and v3 binaries. The `mov32` + `hor64` immediate
  shape used by sBPF v2 compilers is covered by unit tests only.
- An instruction whose discriminator is only stored, never compared, is reported
  as `referenced`: usually an instruction this program calls on another program.

## Development

```sh
cargo test                                   # unit tests and fixture tests
scripts/build-fixtures.sh                    # rebuild tests/fixtures from fixtures/ (needs cargo-build-sbf)
node scripts/compare-native-wasm.mjs a.so    # WebAssembly and native reports must be identical
node scripts/grade-against-idl.mjs report.json idl.json [program.so] [--verbose]
```

The grading script reads current and legacy Anchor IDLs, matches instructions by
discriminator, and grades account lists. Given the program file, it also reports
the score leaving out IDL accounts whose names never occur in the binary.

`fixtures/anchor-demo` and `fixtures/native-demo` are small programs written
for the tests. Each item in them exercises one case, such as a name packed
against binary bytes, a digit spelling, a name that must stay unrecovered,
`init`, `mut` and signer accounts, or a native program that logs a string
shaped like an Anchor instruction.

**Grading a program with no IDL.** Two scripts build an answer key from the
chain itself. They read an RPC endpoint from `RPC_URL`; the public endpoint
works but throttles historical lookups heavily.

```sh
# Rebuild a deployed binary from the upload transactions of its deploy buffer,
# which also works after the program has been closed.
node scripts/rebuild-from-buffer.mjs <BUFFER_ADDRESS> program.so
# Pair each call's first 8 bytes with the `Instruction: <Name>` line the program logged.
node scripts/answer-key-from-logs.mjs <PROGRAM_ID> answer-key.json
```

The buffer address of each deployment is in the program-data account's
`deployWithMaxDataLen` and `upgrade` transactions.

## Prior art

Sec3's [IDL Guesser](https://github.com/sec3-service/IDLGuesser), published in
April 2025, introduced recovering Anchor instruction names from their
`Instruction: <Name>` log strings and computing their discriminators, and it
also recovers per-instruction account lists with signer and writable flags.
[solana-idl-extractor](https://github.com/dvrvsimi/solana-idl-extractor) takes a
related approach.

sbpf-inspect is written from scratch and uses no code from either. It differs
in that it:

- reports a name only when its discriminator is found in the binary, with the
  offsets as evidence, including byte-wise dispatch
- gives each account's load offset and the error codes its flags come from, and
  says how its position was established
- recovers account and event type names
- separates a program's handlers from the instructions it calls elsewhere
- works offline on a local file and runs as WebAssembly
- is MIT or Apache-2.0 licensed, so other tools can embed it

## Credits and license

Built on Blueshift's `sbpf-disassembler` and `sbpf-common` (MIT). The
discriminator scheme is Anchor's, and the log-string approach to instruction
names follows Sec3's IDL Guesser.

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
