<p align="center"><img src="https://raw.githubusercontent.com/go-binfmt/brand/main/social/go-binfmt-fwimg.png" alt="go-binfmt/fwimg" width="720"></p>

# go-binfmt/fwimg

[![CI](https://github.com/go-binfmt/fwimg/actions/workflows/ci.yml/badge.svg)](https://github.com/go-binfmt/fwimg/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-binfmt/fwimg.svg)](https://pkg.go.dev/github.com/go-binfmt/fwimg)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96)](LICENSE)

Turn an ELF executable into the image a fixed-address target loads: a **flat
binary** (`objcopy -O binary`), a **Motorola S-record** (`objcopy -O srec`), an
**Intel HEX** file (`objcopy -O ihex`) or a legacy **U-Boot uImage**
(`mkimage`). Pure Go, standard library only (plus cobra for the CLI), no
binutils, no U-Boot tools, static binaries for Linux, macOS, the BSDs and
Windows.

```
go install github.com/go-binfmt/fwimg/cmd/fwimg@latest

fwimg -O binary -o kernel.img kernel.elf                 # Raspberry Pi kernel.img, QEMU -kernel
fwimg -O ihex   -o fw.hex fw.elf                         # flash programmer
fwimg -O srec   --name fw -o fw.srec fw.elf
fwimg -O uimage --load 0x80000 --entry 0x80000 --name linux -o uImage kernel.elf
```

The input can be any of those too, so any format converts to any other. The
format is recognised by its magic or syntax (ELF, Intel HEX, S-record, uImage)
and `-I` forces it; a raw file is never guessed and needs `-I binary --base`:

```
fwimg -I ihex -O binary -o fw.bin fw.hex
fwimg -I srec -O ihex -o fw.hex fw.srec
fwimg -I binary --base 0x8000000 -O srec -o fw.srec fw.bin
fwimg -O binary -o kernel.bin uImage                     # the payload of a uImage
fwimg info uImage                                        # the header, as mkimage -l prints it
```

## objcopy's options, and the two text formats in detail

Since v0.4.0 the options that shape an image are the ones objcopy has, with
the same names and the same output, byte for byte, CRLF included:

```
fwimg -O srec -j '.text*' -j .rodata -o fw.srec fw.elf   # -j: keep these sections (wildcards * ?)
fwimg -O srec -R '.*' -R '!.text' -o fw.srec fw.elf      # -R: drop these; a leading ! protects a name
fwimg -O srec --gap-fill 0xff --pad-to 0x90400 -o fw.srec fw.elf
fwimg -O ihex --change-addresses 0x100 -o fw.hex fw.elf  # --adjust-vma is the same
fwimg -O ihex --set-start 0x80010 -o fw.hex fw.elf       # or --change-start N (an increment)
fwimg -O srec --srec-addr-len auto --srec-count --crlf -o fw.srec fw.elf
fwimg -O ihex --ihex-mode objcopy --crlf -o fw.hex fw.elf
```

* `-j` / `-R` select by section name and need an ELF with section headers
  (without `-j`/`-R` the image is built from the program headers, as before).
  A name matched by a `!` pattern is never selected, whatever the order; giving
  both `-j` and `-R` is refused, because objcopy calls it undefined.
* `--gap-fill` / `--pad` (the same option, one value) fill the gaps between
  segments, and `--pad-to ADDR` pads the end; the fill is bounded by
  `--max-size` and refused before it is allocated.
* `--change-addresses` / `--adjust-vma` moves the segments and the start
  address; `--change-start` moves the start address only; the later of the two
  on the command line wins, as in objcopy. `--set-start` (or `--entry`) sets it.
* S-record: `--srec-addr-len 16|24|32|auto` writes S1/S9, S2/S8 or S3/S7 (auto
  picks the shortest that holds the highest address, as objcopy does), and
  `--srec-count` adds the S5 (or S6) count record, as srec_cat does.
* Intel HEX: `--ihex-mode linear` (default) writes type 04 and type 05 records,
  as srec_cat; `objcopy` writes type 02 below 1 MiB and type 03 for the start
  address. A start address is written in both (new in v0.4.0: an ELF's entry
  was dropped from Intel HEX before).
* `--crlf` ends every line with CR LF, as objcopy and srec_cat do (LF by default).

## Safety checks (v0.5.0)

```
fwimg -O binary --region FLASH=0x8000000:1M --region RAM=0x20000000:128K -o fw.bin fw.elf
fwimg -O binary --gap-warn 4 -o fw.bin fw.elf            # warn when the hole is over 4x the payload
fwimg -O binary --no-verify -o fw.bin fw.elf             # skip the read-back
SOURCE_DATE_EPOCH=1700000000 fwimg -O uimage --load 0x80000 -o uImage fw.elf
fwimg -O uimage --time 1700000000 --load 0x80000 -o uImage fw.elf
```

* **Gap diagnosis.** When the image would span far more than it holds, the
  refusal names the `PT_LOAD` segments and sections on each side of the largest
  gap with their LMA and VMA, and says which of `--use-vaddr` or `-R .data`
  fits. Below the refusal threshold, `--gap-warn N` (default 8) prints a warning
  when the hole is more than N times the payload. objcopy only warns on a
  negative offset.
* **`--region NAME=START:SIZE`** (repeatable, `K`/`M` suffixes) refuses a
  segment that overflows its region or lies outside every region, naming the
  segment and the byte excess, in the shape of ld's "region `X' overflowed by N
  bytes".
* **Verify after write** is on by default. The output is read back with the
  decoders (binary, S-record, Intel HEX, uImage) and compared byte for byte and
  address by address, start address included. On a mismatch the command fails and
  no file is left behind. The file is written by unlink and create, as in
  v0.4.2; verification is skipped for a non-regular output (device, symlink).
  `--no-verify` turns it off; its cost is in the CI `bench` job summary.
* **`SOURCE_DATE_EPOCH`** sets the uImage time, as mkimage does
  (tools/imagetool.c). An invalid value is **refused** (mkimage writes 0).
  `--time` overrides it. With neither, the time stays **0**, deterministic;
  mkimage uses the input file's mtime instead, which is the one documented
  difference.

## Manifest, info and verify (v0.6.0)

```
fwimg -O ihex --manifest fw.json -o fw.hex fw.elf        # the image, described
fwimg info fw.hex                                        # any input: format, start, ranges, hashes
fwimg info --json fw.elf                                 # the same facts, as a manifest
fwimg verify --manifest fw.json fw.hex                   # re-read an image, check every hash
fwimg verify --manifest fw.json -I binary --base 0x8000000 fw.bin
```

* **The manifest** is JSON with a fixed key order: `format`, `base`, `entry`
  (null without one), `pad`, `size`, `data_size`, the CRC-32 and SHA-256 of the
  whole image, and per segment (and per `--region`) its address, size,
  `source` (the input file) and both hashes. An ELF input also lists its
  allocated sections. A uImage output adds its header fields. The same input
  and options give the same bytes: there is **no timestamp** unless
  `SOURCE_DATE_EPOCH` is set, then `created` is that time in UTC.
* **Addresses are strings** (`"0x8000000"`, lowercase hex) because a JSON number
  cannot hold 64 bits; sizes are integers. The hashes cover the flat image
  from `base`, the gaps filled with `pad`, which is what `-O binary` writes.
* **The schema** is `schema/manifest-1.schema.json`, JSON Schema 2020-12, with
  `additionalProperties: false` everywhere, published at
  `https://go-binfmt.github.io/fwimg/manifest-1.schema.json` and embedded in
  the library as `fwimg.ManifestSchema`. A change that is not backward
  compatible makes `manifest-2`; `schema_version` says which one a file is.
* **`info`** reads ELF, Intel HEX, S-record, uImage or (`-I binary --base`) a
  raw file. A uImage is listed exactly as `mkimage -l` does; the others print
  the manifest's facts as text, or as JSON with `--json`.
* **`verify`** recomputes from the image's bytes, in whatever format it is in,
  the base, size, start address and the hashes of the whole image and of every
  segment and region. A manifest written for the S-record checks the flat
  binary of the same image. `data_size` is not compared (a flat binary counts
  its padding). Every difference is listed; exit status 1 on any. The start
  address is compared only if the image has one.
* A manifest is read with a size bound (16 MiB, 65536 entries per list), unknown keys are refused, and
  the reader is fuzzed (`FuzzReadManifest`).

The library is `github.com/go-binfmt/fwimg`: `NewManifest`, `ReadManifest`,
`(*Manifest).JSON` and `Verify`, `ELFManifestSections`, `UImageStored`, and
`Flatten`, `SREC`, `IHEX`,
`UImage`, the L2 additions `ELFImage`, `ELFSections` (with `SectionSelect`),
`EncodeSRECOpts` and `EncodeIHEXOpts`, with `Image.GapFill`, `PadTo` and
`Offset`; the readers `DecodeIHEX`, `DecodeSREC`, `ParseUImage`, `RawImage`
and `Detect` (an `Image` of sparse segments), plus `ArchFromELF` (takes the ELF `e_machine` number) / `ArchFromName` for the uImage architecture code.

```go
flat, base, err := fwimg.Flatten(f, size, fwimg.FlattenOptions{Pad: 0xff})
srec, err := fwimg.SREC(uint32(base), flat, "fw", entry, 0)
```

This code started as `github.com/go-coff/peln/fwimg`, which is now deprecated:
the PE/COFF and UEFI side lives in go-coff, and an ELF-to-firmware converter has
nothing to do with it. `pectl objcopy` uses this module.

## The input is untrusted

An ELF header says where each segment lives and how big it is; none of that is
checked by the format. `Flatten` and the encoders refuse, with an error that wraps
a sentinel (`errors.Is`) and with nothing allocated for it:

| input | refusal |
|---|---|
| two segments far apart in memory (the image would be the distance between them) | `ErrTooLarge`: the image is bounded by `FlattenOptions.MaxSize` (default 256 MiB, `--max-size`) *before* `make` |
| a segment whose file range ends past the input, or whose offset + size wraps | `ErrRange`, checked against the input size you pass to `Flatten` |
| a load address + size that wraps 2^64 | `ErrAddrOverflow` |
| segments that overlap (the work would otherwise be unbounded) | `ErrOverlap` |
| `SREC`/`IHEX` data that runs past 4 GiB (it used to wrap to 0 silently) | `ErrAddrOverflow` |
| `UImage` payload of 4 GiB or more (the header field would be truncated) | `ErrFormat` |
| an S-record name or line length the one-byte count cannot hold, an Intel HEX line above 255 bytes | `ErrFormat` |
| a default `--load` / `--entry` taken from a 64-bit ELF that does not fit 32 bits | refused by the CLI: give the flag |
| an Intel HEX or S-record file with a bad checksum, no end record, records after it, overlapping records or data past 4 GiB | `ErrChecksum`, `ErrSyntax`, `ErrOverlap`, `ErrAddrOverflow`, with the line number |
| text with records scattered far apart (each piece costs the decoder) | `ErrTooLarge`: data bytes plus 16 bytes per separate piece count against `DecodeOptions.MaxSize` |
| a uImage with a bad header or data CRC, an `ih_size` past the file, or a multi-file table that does not end inside the payload | `ErrFormat` / `ErrRange` |

Every one of these has a test that asserts the refusal; the memory bomb runs under
a memory limit and asserts that nothing is allocated. Sizes are `int` on 32-bit
platforms, so CI runs the whole suite as `GOARCH=386` (native) and `s390x` (big
endian, under qemu). `FuzzFlatten` feeds arbitrary bytes to the parser and checks
that whatever is accepted survives the SREC and IHEX encoders byte for byte;
`FuzzIHEX`, `FuzzSREC` and `FuzzUImage` do the same for the readers (an accepted
file encodes and decodes to the same image). The corpora are committed under
`testdata/fuzz`, replayed on every run, and fuzzed 60 s each in CI. `govulncheck` runs on every push and daily.

Two fixes beyond the refusals, both found while porting:

* Intel HEX for an image in the last 64 KiB of the address space was written
  without its extended-address record (the upper half `0xFFFF` collided with the
  "unset" marker), so a loader would have put it at the bottom of memory. Records
  also no longer cross a 64 KiB boundary when the start is not aligned.
* The S-record header (S0) carries the 2-byte address the format defines, not a
  4-byte one.

## Tested against objcopy and mkimage

`differential_test.go` links a freestanding ELF with gcc and a linker script (two
`PT_LOAD` segments with a gap between them, and a `.bss` that must not be emitted),
converts it with GNU objcopy and U-Boot's mkimage, and compares:

* `-O binary` (gap filled with `0x00` and with `0xff`): byte for byte;
* `-O srec`, `-O ihex`: every byte objcopy records is at the same address in ours,
  the entry address is equal, and what we add (the gap) is the pad byte;
* `uimage` for kernel, standalone and firmware types: byte for byte, header CRC
  and data CRC included.

The input side (`differential_input_test.go`) reads what objcopy and srec_cat
write (`-O ihex`, `-O srec`, `--srec-forceS3`, `--srec-len`, raw files placed with
`--change-addresses` / `-offset`), reads back to the same bytes objcopy reads from
our files, and compares `Listing` with `mkimage -l` for six header shapes and a
multi-file image; `dumpimage` extracts our payload.

`differential_l2_test.go` covers the v0.4.0 options: the S-record (auto and S3)
and Intel HEX (objcopy mode) files are compared with objcopy's byte for byte
(S0 header aside, objcopy takes its text from the file name) for `--gap-fill`,
`--pad-to`, `-j` and `-R` with wildcards and `!`, `--change-addresses`,
`--adjust-vma`, `--set-start` and `--change-start`; the S5 count and the linear
Intel HEX are compared with srec_cat's.

`l4_differential_test.go` compares a manifest's ranges and start address with
`srec_info` (Motorola and Intel files), and a file srec_cat rewrites still
matches the manifest. `fwimg info` of a uImage prints `Listing`, which is the
`mkimage -l` comparison above.

CI installs `gcc binutils srecord u-boot-tools` and sets `FWIMG_REQUIRE_DIFF`, so a missing
tool is a failure and not a skip; elsewhere the lane skips with the reason stated.
Nothing binary is committed.

## Benchmark

Single core, process wall time, interleaved rounds, medians, against GNU objcopy
2.44 and mkimage on the same files (`internal/bench`, pinned with `taskset -c 0`).
The `uimage` row compares mkimage wrapping an already flat file with fwimg doing
the whole job from the ELF, so it is the conservative one. Linux/arm64 container
on Apple silicon, 40 rounds; the CI `bench` job prints the same table for the
Ubuntu x86-64 runner into its job summary.

| file | operation | reference | fwimg | reference / fwimg |
|---|---|---:|---:|---:|
| small (1 KiB) | `-O binary` | 450µs | 670µs | 0.7x |
| small (1 KiB) | `-O srec` | 450µs | 650µs | 0.7x |
| small (1 KiB) | `-O ihex` | 430µs | 640µs | 0.7x |
| small (1 KiB) | `-O uimage` | 3.80ms | 1.33ms | 2.9x |
| 4 MiB | `-O binary` | 1.64ms | 1.49ms | 1.1x |
| 4 MiB | `-O srec` | 12.29ms | 10.01ms | 1.2x |
| 4 MiB | `-O ihex` | 11.24ms | 9.61ms | 1.2x |
| 4 MiB | `-O uimage` | 23.17ms | 2.62ms | 8.8x |
| 32 MiB | `-O binary` | 7.04ms | 6.95ms | 1.0x |
| 32 MiB | `-O srec` | 84.76ms | 70.23ms | 1.2x |
| 32 MiB | `-O ihex` | 73.44ms | 66.04ms | 1.1x |
| 32 MiB | `-O uimage` | 176.64ms | 13.31ms | 13.3x |

On a 1 KiB file fwimg is behind objcopy by the fixed cost of starting a Go process
and the cobra command tree; that gap is tracked as an open performance issue.
The 1 KiB rows above were measured before fwimg stopped importing `debug/elf`
(v0.2.0 reads the program headers with `elfpatch.Parse` instead, which removes
`debug/dwarf`, `compress/flate` and `internal/zstd` from the process). A Go
process that does nothing already costs about as much as objcopy at this size,
and cobra adds most of the rest. The CI `bench` job prints that floor on the
runner (1 KiB, `-O binary`, 60 rounds, Ubuntu x86-64, one core):

| objcopy | fwimg | cobra-only | hello (empty main) | fwimg minus cobra-only | noise |
|---:|---:|---:|---:|---:|---:|
| 1.626ms | 2.625ms | 2.274ms | 1.384ms | 348µs | 86µs |

About 350µs of the gap is fwimg's own work, beyond the noise; it is tracked in
go-binfmt/fwimg#2. `internal/startup` times processes and counts page faults.
From 4 MiB up it is even or faster, and mkimage is far slower.

The decode rows (`-I ihex` / `-I srec` to a flat binary, reading a text file
objcopy and srec_cat would read) are in the CI table. It is the `bench` job of
the CI run 45888191102 on main at `2d5d60c2d0f0` (v0.4.3), quoted as printed
(Ubuntu x86-64 runner, GNU objcopy 2.46, 60 rounds, one core, load average
1.22 at the start):

| file | operation | reference | fwimg | reference / fwimg |
|---|---|---:|---:|---:|
| small (1 KiB) | `-O binary` | 1.26ms | 2.09ms | 0.6x |
| small (1 KiB) | `-O srec` | 1.27ms | 2.05ms | 0.6x |
| small (1 KiB) | `-O ihex` | 1.25ms | 2.09ms | 0.6x |
| small (1 KiB) | `-O uimage` (mkimage: flat file in) | 2ms | 2.2ms | 0.9x |
| small (1 KiB) | `-I ihex -O binary` | 1.21ms | 2.11ms | 0.6x |
| small (1 KiB) | `-I srec -O binary` | 1.21ms | 2.1ms | 0.6x |
| 4 MiB | `-O binary` | 4.07ms | 4.46ms | 0.9x |
| 4 MiB | `-O srec` | 26.05ms | 23.38ms | 1.1x |
| 4 MiB | `-O ihex` | 24.11ms | 21.53ms | 1.1x |
| 4 MiB | `-O uimage` (mkimage: flat file in) | 33.36ms | 7.1ms | 4.7x |
| 4 MiB | `-I ihex -O binary` | 63.59ms | 39.68ms | 1.6x |
| 4 MiB | `-I srec -O binary` | 58.05ms | 39.75ms | 1.5x |
| 32 MiB | `-O binary` | 30.01ms | 30.93ms | 1.0x |
| 32 MiB | `-O srec` | 206.26ms | 157.8ms | 1.3x |
| 32 MiB | `-O ihex` | 185.48ms | 143.11ms | 1.3x |
| 32 MiB | `-O uimage` (mkimage: flat file in) | 286.31ms | 36.15ms | 7.9x |
| 32 MiB | `-I ihex -O binary` | 483.35ms | 289.91ms | 1.7x |
| 32 MiB | `-I srec -O binary` | 440.42ms | 301.2ms | 1.5x |

Reading text is faster than objcopy from 4 MiB up (1.5x to 1.7x). The rows
where fwimg is behind are the 1 KiB ones (process start, above) and
`-O binary` at 4 MiB (0.9x here, 0.92x on the run of the pull request that
mapped the input). The flat write was 0.5x and 0.6x at 4 and 32 MiB before
v0.4.2: it built a second image and truncated an existing output in place
(go-binfmt/fwimg#17). v0.4.2 streams the segments and unlinks an existing
output first, as objcopy does; v0.4.3 maps an ELF input instead of reading it.
The 32 MiB row is now even to 1.2x between runs; the 4 MiB row is behind by
about 0.3 ms, a start-up cost of the Go runtime (some 330 more page faults
than objcopy), the same one as the 1 KiB rows.

## Development

```
go test ./...                                  # unit, CLI, fuzz-corpus replay; differential skips without Linux tools
go run ./internal/mkcorpus                     # regenerate testdata/fuzz/FuzzFlatten
go test -run '^$' -fuzz '^FuzzFlatten$' -fuzztime 60s .
go run ./internal/bench -fwimg ./fwimg
```

What comes next, lot by lot, is in [ROADMAP.md](ROADMAP.md); the format
facts each differential test asserts, with the source line they were read
from, are in [docs/spec-notes.md](docs/spec-notes.md).

Licence: BSD-3-Clause.
