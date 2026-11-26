# fwimg roadmap

Seven lots, in order. Each lot ships as its own release (below v1, a
breaking change bumps MINOR) and is **differentially tested** against the
reference tool named in its row: the reference's output, or the fields it
prints, is the equality oracle, and [docs/spec-notes.md](docs/spec-notes.md)
holds the facts each oracle rests on, with the source line they were read
from. Every decoder is fuzzed with a committed corpus; every bomb test asserts
a refusal under `GOMEMLIMIT`.

Starting point (L1 changes the input side): v0.2.1 — ELF in; flat binary, SREC (S3), Intel HEX (type 04),
legacy uImage (no compression) out.

| Lot | Subject | Reference (oracle) | Release |
|---|---|---|---|
| L1 | Input | `objcopy -I ihex/srec/binary -O binary`, `mkimage -l`, `dumpimage` | v0.3.0 |
| L2 | Output completeness | `objcopy`, `srec_cat` | v0.4.0 |
| L3 | Safety | `objcopy` (gap), `ld` (regions), `srec_cmp` (verify), `mkimage` (epoch) | v0.5.0 |
| L4 | Manifest and `fwimg info` | `sha256sum`, `crc32` (Go `hash/crc32` IEEE), `mkimage -l`, `srec_info` | v0.6.0 |
| L5 | uImage compression, UF2, Verilog | `mkimage -C`, `gzip -d`/`lz4 -d`, `uf2conv.py`, `objcopy -O verilog` | v0.7.0 |
| L6 | wasm build, docs playground | the native CLI (same bytes) | v0.8.0 |
| L7 | FIT, on a new `go-binfmt/fdt` | `dtc`/libfdt, `mkimage -f`/`-E`, `dumpimage` | fdt v0.1.0, fwimg v0.9.0 |

## L1 — input (v0.3.0, shipped)

- Raw binary input with `--base ADDR` (objcopy's `-I binary` needs the
  address supplied the same way).
- Input autodetection: ELF magic, uImage magic `0x27051956`, a first
  non-blank byte `:` (Intel HEX) or `S` + digit (S-record); anything else is
  refused unless `-I binary --base` is given — a raw file is never guessed
  (objcopy does not guess it either, spec-notes §10 e).
- Intel HEX decoder: types 00–05, checksum, 64 KiB wrap under types 02 and
  04 as [intel5] defines it (spec-notes §2.1). Fuzzed; invariant
  `decode(encode(x)) == x`, and against `objcopy -I ihex -O binary`.
- S-record decoder: S0–S3, S5/S6 (count checked), S7–S9; fuzzed likewise.
- uImage reader and verifier: both CRCs, `ih_size` bounded by the file;
  multi-file images with the size table **bounded by `ih_size`** (U-Boot's
  own loop is not, spec-notes §5.3). Field values against `mkimage -l`.

## L2 — output completeness (v0.4.0)

- Intel HEX: type 05 (and type 03) start records; an **address mode**
  option, because the references disagree (spec-notes §2.2–2.3): objcopy
  writes type 02/03 below 1 MiB and 04/05 above, srec_cat writes type 04 by
  default. Each mode is tested against the tool that defines it. Current
  output (type 04 only, matching srec_cat) stays the default.
- S-records: S1/S2 chosen by the highest address (objcopy's rule, spec-notes
  §3.2) or forced by an address length (srec_cat `-address-length`);
  S5/S6 counts — oracle **srec_cat**, since objcopy never writes them.
- `-j` / `-R` with wildcards and `!`; the combination is refused (objcopy
  calls it undefined behaviour).
- `--pad-to`, `--gap-fill`, `--change-addresses`, `--set-start`,
  `--change-start` with objcopy's order and semantics (spec-notes §1.1).
- Line endings: both references write **CRLF**; fwimg writes LF. A
  `--crlf` option makes byte-equal differential tests possible; the default
  is decided in this lot's PR and stated in its release notes.

**Change from the brief:** adds `--gap-fill`, `--change-start`, the IHEX
address mode and line endings, which the sources showed are needed for
byte-equal oracles.

## L3 — safety (v0.5.0)

- Gap diagnosis: when the output spans more than the bytes it holds, name
  the segments and sections on each side of the largest gap and say whether
  LMA ≠ VMA caused it. objcopy only warns on a negative offset (§1.2).
- `--region NAME:ORIGIN:LENGTH` (repeatable) fit check, with ld's message
  shape ("region `X' overflowed by N bytes", §1.3) — ld is the oracle on a
  linker script with the same `MEMORY`.
- Verify-after-write: decode what was written with the L1 decoders and
  compare to the in-memory image; `srec_cmp` is the external oracle.
- `SOURCE_DATE_EPOCH`: **parity with mkimage, not a novelty** (spec-notes
  §5.4). fwimg refuses an unparsable value where mkimage writes 0; with it
  unset, fwimg keeps its deterministic 0 unless `--time` is given (mkimage
  uses the input mtime) — this divergence is documented.

**Change from the brief:** SOURCE_DATE_EPOCH is reclassified from "the
reference does not do it" to parity (claim f is false).

## L4 — manifest and `fwimg info` (v0.6.0)

- `--manifest FILE`: JSON with CRC-32 (IEEE) and SHA-256 of the whole image
  and of each segment, plus addresses, sizes and the source ELF's sections.
  No reference emits one (§10 d); oracles are `sha256sum` and Go's
  `hash/crc32` on the extracted bytes.
- `fwimg info FILE` for every format L1 reads: address ranges, entry,
  uImage fields. Field values against `mkimage -l` and `srec_info`.

## L5 — uImage compression, UF2, Verilog (v0.7.0)

U-Boot defines the compression byte by **container**, not algorithm
(spec-notes §5.2): `lzma` is the legacy `.lzma` file, `lz4` the LZ4 *frame*,
`lzo` the lzop file. mkimage never compresses, so fwimg's oracle is header
equality with `mkimage -C c` on fwimg's payload plus a round trip through the
reference decompressor.

Fleet state, read 2026-11-25 (`gh repo list go-compressions`, local clones):

| uImage type | Fleet library | State |
|---|---|---|
| gzip | Go stdlib `compress/gzip` | available |
| lz4 | `go-compressions/lz4` v0.6.0 | block format and Apple `bv41` frame in its README (clone of 2026-11-16); the standard LZ4 frame writer U-Boot needs is **not confirmed** — added to go-compressions/lz4 first if missing |
| lzma | `go-compressions/xz` v0.3.1 | decodes `.xz`, LZMA2 and `.lzma`; an LZMA encoder is tested internally (`internal/lzmacore`), a public `.lzma` writer is not confirmed |
| lzo | `go-compressions/lzo` v0.4.1 | LZO1X and an lzop reader; writer not confirmed |
| bzip2 | `go-compressions/bzip2` | repository exists, no release |
| zstd | — | **none** in go-compressions |

Ship gzip and lz4 in v0.7.0; lzma, lzo, bzip2 and zstd follow as their
encoders land in go-compressions (one implementation, the lowest shared
library). UF2 (spec-notes §8; family IDs pinned from `uf2families.json`,
oracle Microsoft's `uf2conv.py`) and Verilog (spec-notes §4, oracle
`objcopy -O verilog --verilog-data-width`, trailing-space quirk included).

**Change from the brief:** only gzip and lz4 are in v0.7.0's scope; the
other four depend on encoders the fleet does not yet publish, and xz is not
a uImage compression type at all.

## L6 — wasm build and docs playground (v0.8.0)

`GOOS=js GOARCH=wasm` (and `wasip1`) build of the library and CLI, a test
that the wasm build writes the same bytes as the native one, and a
playground page on the go-binfmt docs site. Prior art: no playground in
`go-binfmt/docs` content; the fleet pattern is go-tex's
`go-tex.github.io/.github/workflows/playground.yml`, reused rather than
redesigned.

## L7 — FIT (go-binfmt/fdt v0.1.0, then fwimg v0.9.0)

1. New repository `go-binfmt/fdt`: DTB v17 reader and writer (spec-notes
   §7), fuzzed, differentially tested against `dtc -I dtb -O dts` and
   libfdt's `fdtget`.
2. FIT in fwimg: write images, configurations and hash nodes ([fitspec]
   §5.2–5.11), embedded and external data (`-E` layout pinned by a
   differential test against `mkimage -E`, spec-notes §6); `fwimg verify`
   with a regression case per FIT CVE listed in spec-notes §6. Signing is
   out of scope until a separate design note.
