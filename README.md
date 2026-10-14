# sbpf-inspect

Offline interface recovery for Solana sBPF programs. Give it a compiled program
(a `.so` file, or a dump of a deployed program) and it reports what the binary
contains, which Anchor instructions, accounts and events it implements, each
instruction's ordered account list with writable and signer flags, and the byte
layout of each instruction's arguments. Instructions whose names are not in the
binary are found by their 8-byte discriminators, and for native programs it
finds the instruction dispatch. Every name comes with the byte offsets of the
evidence behind it.

It runs as a Rust library, a command-line tool, or a WebAssembly module for
Node, with no third-party analysis code. It never touches the network. The only
code of the program it runs is the entrypoint's decoding of a made-up input, in
its own interpreter, to find where the instruction data goes.

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

| Program | Instructions | Account lists exact | Argument layouts exact |
|---|---|---|---|
| Mango v4, `4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg` | 103 of 103 | 99 of 103 | 63 of 69 |
| Zeta, `ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD` | 102 of 107 | 85 of 100 | 51 of 76 |
| marginfi v2, `MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA` | 87 of 91 | 75 of 87 | 32 of 43 |
| Jupiter Perpetuals, `PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu` | 59 of 59 | 52 of 59 | 25 of 33 |
| Drift Vaults, `vAuLTsyrvSfZRuRB3XgvkPwNGgYSs9YRYymVebLKoxR` | 46 of 46 | 46 of 46 | 23 of 24 |
| Raydium LaunchLab, `LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj` | 28 of 28 | 26 of 28 | 13 of 13 |
| Meteora Alpha Vault, `vaU6kP7iNEGkbmPkLmZfGwiGxd4Mob24QQCie5R9kd2` | 27 of 27 | 27 of 27 | 14 of 17 |
| Kamino Farms, `FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr` | 27 of 27 | 26 of 27 | 13 of 13 |
| Meteora Dynamic AMM, `Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB` | 26 of 26 | 25 of 26 | 16 of 17 |
| Meteora Dynamic Bonding Curve, `dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN` | 26 of 28 | 23 of 26 | 9 of 9 |
| Kamino Vault, `KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd` | 26 of 29 | 23 of 26 | 15 of 15 |
| Tensor cNFT marketplace, `TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp` | 20 of 21 | 1 of 20 | 12 of 15 |
| Metaplex Bubblegum, `BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY` | 17 of 17 | 11 of 17 | 13 of 13 |
| Pyth Solana Receiver, `rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ` | 13 of 13 | 13 of 13 | 2 of 4 |
| Jupiter DCA, `DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M` | 12 of 12 | 5 of 12 | 7 of 7 |
| Meteora Dynamic Vault, `24Uqj9JCLxUeoC3hGfh5W3s9FM9uCHDS2SG3LYwBpyTi` | 12 of 14 | 10 of 12 | 8 of 8 |
| Jito Tip Distribution, `4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7` | 10 of 10 | 9 of 10 | 5 of 8 |
| Metaplex Candy Machine Core, `CMACYFENjoBMHzapRXyo1JZkVS6EtaDDzkjMrmQLvr4J` | 8 of 8 | 8 of 8 | 3 of 4 |
| Jupiter Limit Order v2, `j1o2qRpjcyUwEvwtcfhEQefh773ZgjxcVRry7LDqg5X` | 8 of 8 | 8 of 8 | 6 of 6 |
| Lifinity v2, `2wT8Yq49kHgDzXuPxZSaeLaH1qbmGXtEyPy64bL7aD3c` | 3 of 3 | 3 of 3 | 3 of 3 |
| **Total** | **660 of 677** | **575 of 658 (87%)** | **333 of 397 (84%)** |

On the 5,464 accounts compared, the writable flag agrees with the IDL on 5,452
and the signer flag on 5,447. The tool marked an account writable where the IDL
did not three times, and each time the IDL is out of date: marginfi's source
declares that account `mut`, and Zeta's binary raises ConstraintMut naming the
account. It never marked an account signer where the IDL did not. The argument
column is different: the argument walk was developed on these programs, so it
is not an unseen measurement (see [Argument layouts](#argument-layouts)). Drift
Vaults' row counts eight instructions earlier versions marked `referenced`; the
search for unnamed instructions shows the program dispatches them (see
[Instructions without names](#instructions-without-names)), and their account
lists, already recovered, are all exact.

Published IDLs often lag the deployed program, so they are an imperfect answer
key. The tool also named 133 implemented instructions these IDLs do not list
(Bubblegum's on-chain IDL has none of its `_v2` instructions). The Tensor binary
renames fields its IDL still lists under old names (`marketplace_program` for
`tcompProgram`, `rent_destination` for `rentDest`) and checks a `cosigner`
account the IDL lacks; mapping the renames alone makes 6 more of its lists
exact. Jupiter DCA's misses are mostly the tool's: in six instructions, token
accounts the program names only after loading the others (`user_in_ata`,
`fee_ata`) are listed last instead of in their place.

### Argument layouts

An instruction is graded when its arguments start with fixed-size values:
structs are expanded into their fields, and the graded prefix ends at the first
vector, string or option. A layout is exact when every field offset and size
matches, a 16- or 32-byte value read in 8-byte parts counting as one. Precision
counts, of the layouts that report fields, those that put every field edge where
the IDL has one.

The walk was developed on the 20 programs above, the three programs at the top
that have IDLs, and one private program the figures here leave out. The nine programs the account-list method was developed on were graded at
the end without changes. Then 13 more Anchor programs were fetched and graded
once (Kamino Liquidity and Scope, Tensor Swap and Whitelist, Squads v3, Jupiter
v4, Switchboard v2 and On-Demand, GooseFX SSL v2, Meteora Stake-for-Fee, Jupiter
Locker, and two governance programs). That run found three gaps, two of which
were then fixed; both runs are shown.

| | Development (23 programs) | Nine graded at the end | 13 new, first run | 13 new, after the fixes |
|---|---|---|---|---|
| Layouts exact | 383 of 457 (84%) | 201 of 227 (89%) | 65 of 111 (59%) | 72 of 112 (64%) |
| Precision | 405 of 437 (93%) | 215 of 223 (96%) | 71 of 74 (96%) | 78 of 87 (90%) |
| Instructions with arguments and no layout | 0 | 0 | 35 | 21 |

The gaps were byte-wise dispatch that extracts each byte from a wider load
(Jupiter v4), a deserializer that returns its value in a register shared with
its error path (Squads v3), and discriminators compared by a helper function
against copies in read-only data (Switchboard On-Demand). The fixes decode
Jupiter v4 fully and Squads v3 too, though Squads v3's public keys come back in
pieces, which is why precision falls. Switchboard On-Demand compares in a loop
the walk does not unroll, so 21 of its instructions get no layout.

The `irregular` flag is the precision signal. Across all four sets, 595 of the
602 layouts not marked irregular are boundary-correct (98.8%), against 103 of
146 marked irregular. Nearly all of those are public keys and other byte arrays
the compiler moves in uneven pieces (4, 2, 8, 1, ...) that then reach a
comparison and show up as fields. An empty layout marked `complete: true`
means no arguments 184 times out of 188; an empty layout without it can still
hide arguments.

Older Anchor versions dispatch byte by byte, and a walk that starts at the
discriminator comparison loses the data pointer they set up before it. On the
20 programs above, such a walk gets 95 layouts exact and finds no reads for 270
instructions. Starting where the data pointer comes from, and following
deserializers that advance a `&mut &[u8]` cursor, is most of the difference.

On the 13 new programs the account lists were also measured unchanged: 202 of
216 exact, with the writable and signer flags each right on 1,883 of 1,884
accounts (two of those instructions count since the search for unnamed
instructions corrected their status). Only 6 of Tensor Swap's 46 IDL
instructions and 1 of Switchboard v2's 54 are named because the deployed
programs implement no others (see
[Instructions without names](#instructions-without-names)).

### Instructions without names

The search for unnamed instructions (see [How it works](#instructions-without-names-1))
was checked on the 45 Anchor programs above that have IDLs. To measure what it
finds on its own, it was also run without skipping the instructions the logs
already name: it found all 1,524 instructions the programs name in their logs,
and the one value it reported that is neither in an IDL nor named by a log is a
real instruction (below).

In normal use it adds what the names miss:

- **Proven dispatch corrects 10 instructions earlier versions marked
  `referenced`.** Drift Vaults implements eight instructions with the same names
  as Drift instructions it calls (`deposit`, `add_insurance_fund_stake`, ...),
  so their discriminators were first seen stored for those calls; the search
  shows the program's own dispatch tests them. The same holds for one
  instruction each in Meteora Stake-for-Fee and the Locked Voter.
- **Instructions no string names.** Meteora Stake-for-Fee dispatches an
  instruction its IDL lacks, `5e6506ffe3bf6002`: its code compares all 8 bytes,
  one at a time, and calls a handler that reads no arguments. Token-2022's
  interface instructions and a transfer hook's are covered below.
- **Deployments smaller than their IDLs.** Drift's dispatch tests 3 values and
  answers anything else with Anchor's InstructionFallbackNotFound: the deployed
  program implements three withdrawal instructions (`withdraw_from_spot_market`,
  `withdraw_from_insurance_fund`, `withdraw_native_sol`) and none of the 241
  its IDL lists. Tensor Swap's dispatch tests 7 values (6 of its IDL's 46
  instructions and one it lacks) and Switchboard v2's 2 (1 of 54). Their IDLs
  are stale; earlier versions of this README blamed missing log strings.

On a closed-source native program on mainnet that selects instructions by 8-byte
ASCII tags, it finds both tags, and the layout it gives the one the program is
called with matches its recent calls field for field. On a Token-2022 transfer
hook that compares its 8-byte discriminators byte by byte in no fixed order, it
finds all six: the interface's `execute`, whose argument is the u64 amount, and
five of the program's own that no string names.

The cost is 11% more time over the 60 programs measured (368 to 410 seconds),
most of it in a few large programs; see [Limits](#limits).

### Native programs

For programs without Anchor, the tool runs each candidate tag load for every
value 0 to 255 and keeps the switch whose handlers reach the most distinct
`Instruction: <Name>` logs. Token-2022 yields 48 tags, 36 of them named by the
handler's own log (0 `InitializeMint`, 3 `Transfer`, ...; the others are
extension families whose logs sit in sub-dispatchers), and the Address Lookup
Table program 5 tags with 4 named. p-token and the Associated Token Account
program log nothing, so their switches are reported unconfirmed.

Token-2022 also implements the SPL token-metadata and token-group interfaces,
whose instructions start with 8-byte discriminators. Earlier versions named 4
of the 9 from log strings; the interfaces' published hash inputs name all 9, and
the search for unnamed instructions confirms they are dispatched. Their layouts
match the interface definitions: `emitter` (Emit) is an option tag, a u64, an
option tag and a u64; `initialize_token_group` a 32-byte authority and a u64;
`updating_field` a field tag and the length of a string.

pump.fun was measured 2026-10-08 on program data dumped near mainnet slot
454,696,749 (SHA-256 of the dumps: `a4b32d32…9f16` and `a8d05e69…697e`); the
others on 2026-10-12, the 20-program set near slot 455,888,700, and the native
programs and the 13 new ones on 2026-10-14 near slot 456,665,800. Programs are
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
- panic locations (source file, line and column) and the instructions that load
  them, and an embedded security.txt

**Inferred names**, each kept only when corroborated:

- Anchor instructions, with the handler name, the name as logged, the
  discriminator, and where the discriminator and the log string sit. Each is
  marked `implemented` (a handler of this program) or `referenced` (an
  instruction it calls on another program)
- each instruction's accounts in order, with writable and signer flags, where
  each account is loaded, and the Anchor error codes the flags are read from
- each instruction's argument layout: field offsets and sizes after the
  discriminator, whether a field was only copied, and whether the walk saw
  everywhere the data went
- names under the SPL interface namespaces (transfer hook, token metadata, token
  group), from log strings or from the interfaces' published hash inputs, some
  of which differ from the instruction's name (`updating_field` for
  UpdateField). They do not count as Anchor detection
- for native programs, the instruction dispatch: tag values, handler offsets,
  and handler names from their logs
- the human-readable messages the program itself carries: its Anchor error
  messages, `msg!` logs and warnings, with the framework's and runtime's own
  removed. The text is in the binary even when the identifiers are not, and it
  often says what an instruction's arguments mean (`"Name is empty or longer
  than 32 characters"`)
- instructions found by their 8-byte discriminator alone, when the binary does
  not hold their names: Anchor instructions that are not logged, and native
  programs' own 8-byte tags, shown as text when they are ASCII. Each comes with
  its argument layout and the comparison that matched it
- Anchor's own IDL-management instructions, reported as framework instructions
- account and event types, with discriminator and evidence
- whether the program is Anchor, from the markers that say so, including the tag
  of Anchor's event self-calls, which carry events rather than instructions

Unrecovered facts are listed under `unknowns` in every report.

## How it works

1. Load the program the way the Solana loader does: a bounds-checked ELF reader
   (programs without section headers included), a decoder for each sBPF
   version, and a replay of the loader's relocations, which name syscalls and
   give `lddw` and pointer slots their values. Build basic blocks and functions,
   and find the functions that never return.
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

### Argument layouts

Anchor decodes arguments with Borsh, field by field, after the dispatch matches
the discriminator. The tool walks each instruction's path through the code by
abstract interpretation, with the instruction data's first 8 bytes known to be
that instruction's discriminator.

1. Find where the code tests the discriminator: a 64-bit constant compared with
   the first 8 data bytes, a byte-by-byte decision tree, or `sol_memcmp_`
   against a copy in read-only data. Search back along the control flow to where
   the data pointer comes from, and start the walk there.
2. Every comparison of discriminator bytes is decided, so the walk follows only
   this instruction's path. A start counts only if it decided all 8 bytes, which
   also rules out places that test discriminators for other reasons.
3. Track every value byte by byte: which data bytes it holds, through shifts,
   ORs and masks (how unaligned values are assembled) and through stack copies
   at any alignment. Calls are entered four levels deep and return what they
   leave in memory, so a deserializer that fills an out-parameter or advances a
   cursor is seen by its caller. Where paths meet, the data pointer that
   advanced further wins, since a decoder advances only on success.
4. A data value the code computes with, compares or hands on is a field with
   that value's size. Data that is only moved is reported from its copies and
   marked `copied`, since the pieces of a copy are the compiler's, not fields.

`complete: true` means the walk reached the instruction's own `Instruction: <Name>`
log with the argument bytes still reachable, and nothing it does not follow (a
deeper call, a call it could not see return, memory outside the stack, a copy of
unknown length) received them. Otherwise fields may be missing. `truncated`
means the walk hit its step budget.

When no traced start works, the walk starts at the entry of each function that
tests the discriminator, guessing the data pointer among the argument registers
and the caller's stack arguments; deciding all 8 bytes is what confirms a
guess.

### Instructions without names

A discriminator is named only through a name in the binary. Instructions the
program does not log, and native programs that select instructions by their own
8-byte tags, are found from the code instead, and reported under
`unnamed_instructions` only when the program's own code proves them.

1. **Run the entrypoint.** A small interpreter runs the program's entrypoint on
   a made-up input with no accounts and 1,024 bytes of instruction data, until
   the entry function holds a pointer into that data. It records two places:
   the first call the entry function hands the data to (to a register the callee
   reads, in the stack arguments, or in a struct it is given a pointer to), and
   the first place it holds the pointer at all, when that is earlier. This works
   whatever decodes the input (solana-program's `deserialize`, Pinocchio, Anchor)
   because the program does the decoding itself.
2. **Discover.** From each place, a walk runs with the first 8 data bytes
   unknown and records every equality test of them against a constant: one
   64-bit comparison, one byte at a time, or `sol_memcmp_`. It follows only the
   not-equal side, so it stays in the dispatch. Fixing the bytes a test covers
   and walking again goes one level down a byte-by-byte decision tree. Below the
   first level a test counts only on a path where every byte fixed so far was
   found equal: elsewhere the code is reading arguments, not choosing an
   instruction.
3. **Prove.** Every value found, and every 64-bit constant the code compares
   with the first 8 bytes of any buffer, is tried as the start of the data on a
   walk from the same place. It counts only when, on one path, equality tests
   find all 8 bytes equal to what they test them against. Bytes keep their
   positions through shifts and masks, so a test of one byte proves one byte; a
   binary search's ordered comparisons prove nothing; and a call the walk does
   not follow is assumed to overwrite the stack it is handed, so a stale pointer
   cannot stand in for an account's data.

A proven value that matches an instruction marked `referenced` (its
discriminator was first seen stored, as when building a call to another
program) marks that instruction `implemented`. The others get an argument
layout as named instructions do, starting from the entrypoint when no start near
the dispatch works.

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

**WebAssembly with no imports**, for a sandbox that instantiates the module with
an empty import object:

```sh
cargo build --release --target wasm32-unknown-unknown --lib --no-default-features
```

The module exports `sbpf_inspect_alloc(len)`, which returns a buffer to copy the
program into, and `sbpf_inspect_run(ptr, len)`, which returns where the JSON
result is as `(ptr << 32) | len`: `{"ok": <report>}`, or `{"error": "..."}` for
input that is not an sBPF program.

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
        ],
        "arguments": { "fields": [{ "offset": 0, "size": 2 }], "fixed_size": 2, "irregular": false, "complete": true, "dispatch_offset": 14072, "truncated": false }
      }
    ],
    "accounts": [{ "name": "Settings", "discriminator": "dfb3a3beb1e043ad", "discriminator_evidence": ["…"] }],
    "events": [{ "name": "VaultDeposited", "discriminator": "3b3e2bc8dc686443", "discriminator_evidence": ["…"] }]
  },
  "panic_locations": [{ "file": "src/lib.rs", "line": 42, "col": 7, "file_offset": "…", "referenced_by": ["…"] }],
  "unknowns": ["…"]
}
```

`initialize` takes `fee_bps: u16`, so its arguments are 2 bytes at offset 0. A
native program's report carries `native_dispatch` instead. Instructions found
without names are listed under `unnamed_instructions`, here for the small native
program the unit tests build, which selects instructions by 8-byte ASCII tags:

```json
"unnamed_instructions": [
  { "discriminator": "5441474f4e453031", "text": "TAGONE01", "match_offset": 168, "arguments": { "fields": [{ "offset": 0, "size": 8 }], "fixed_size": 8, "irregular": false, "complete": true, "dispatch_offset": 144, "truncated": false } }
]
```

All offsets are byte offsets into the input file. Evidence kinds are
`lddw_immediate`, `mov32_hor64_immediate`, `byte_compare_chain`, `data_bytes`
and `string`.

## Limits

- Instruction names come from Anchor's `Instruction: <Name>` log strings.
  Instructions without a name in the binary get no name and no account list,
  only their discriminator and argument layout. For native programs with
  one-byte tags only the dispatch's tags are found, named when their handlers
  log names.
- Instructions without names are found only when the entrypoint can be run to
  the instruction data on an input without accounts, and the dispatch tests all
  8 bytes for equality within four call levels of it. Dispatch that compares in
  a loop, or reads the data only after checking accounts, is missed. The search
  is slow on large native programs whose tag dispatch leads straight into
  argument decoding: Token-2022 takes about 9 seconds natively and 12 as
  WebAssembly.
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
- Argument layouts are offsets and sizes, not names or types: a 1-byte field
  may be a `u8` or a `bool`, and a field after a vector, string or option is
  not placed. A public key or other byte array that the compiler moves in uneven
  pieces and then compares can come back as several fields; such layouts are
  usually marked `irregular`. An empty layout means no arguments only when it is
  marked `complete`, and even then 4 of 188 such claims in the tests were wrong.
- Dispatch that compares the discriminator inside a loop the walk would have to
  unroll, as Switchboard On-Demand's does, gives no layouts.
- Argument walks favour precision over speed: a 400,000-instruction program such
  as Mango v4 takes about 26 seconds natively and 34 as WebAssembly; small
  programs take well under a second.
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
discriminator, and grades account lists and argument layouts. Given the program
file, it also reports the account-list score leaving out IDL accounts whose names
never occur in the binary.

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
- infers argument layouts from the code path, saying which fields it only saw
  copied and whether it followed the data everywhere
- recovers account and event type names
- separates a program's handlers from the instructions it calls elsewhere
- works offline on a local file and runs as WebAssembly
- is MIT or Apache-2.0 licensed, so other tools can embed it

## Credits and license

The ELF reader, decoder and loader replay are this project's own; versions
before 0.3 used Blueshift's `sbpf-disassembler` and `sbpf-common` (MIT). The
discriminator scheme is Anchor's, and the log-string approach to instruction
names follows Sec3's IDL Guesser.

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
