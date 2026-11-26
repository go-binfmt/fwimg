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

The library is `github.com/go-binfmt/fwimg`: `Flatten`, `SREC`, `IHEX`,
`UImage`, plus `ArchFromELF` (takes the ELF `e_machine` number) / `ArchFromName` for the uImage architecture code.

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

Every one of these has a test that asserts the refusal; the memory bomb runs under
a memory limit and asserts that nothing is allocated. Sizes are `int` on 32-bit
platforms, so CI runs the whole suite as `GOARCH=386` (native) and `s390x` (big
endian, under qemu). `FuzzFlatten` feeds arbitrary bytes to the parser and checks
that whatever is accepted survives the SREC and IHEX encoders byte for byte; the
corpus is committed under `testdata/fuzz/FuzzFlatten`, replayed on every run, and
fuzzed 60 s in CI. `govulncheck` runs on every push and daily.

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

CI installs `gcc binutils u-boot-tools` and sets `FWIMG_REQUIRE_DIFF`, so a missing
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
