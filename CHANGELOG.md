# Changelog

Versions are `vMAJOR.MINOR.PATCH`; below v1 a breaking change bumps the MINOR.

## v0.8.1

* The flat-binary write has a byte budget of its own (`writeFlat`): it hands the
  writer at most the `--max-size` limit (default 256 MiB) and then refuses with
  `ErrTooLarge`, independently of the `CheckFlat` refusal made before it. With
  only `CheckFlat` guarding it, one wrong comparison turned the "distant
  segments" refusal case into a file as long as the distance between two
  segments (a 227 GiB file measured on a developer's disk, which then filled).
* `fwimg` removes the output file when writing it fails, instead of leaving the
  partial file.
* Tests: the budget is asserted without `CheckFlat` in front of it, against a
  sink that only counts bytes; the partial-file removal is asserted.

## v0.8.0

WebAssembly (ROADMAP lot L6):

* `GOOS=js GOARCH=wasm` and `GOOS=wasip1 GOARCH=wasm` builds of the CLI, in CI
  and attached to the release (`fwimg-js-wasm.wasm`, `fwimg-wasip1-wasm.wasm`,
  with the matching `fwimg-wasm_exec.js`).
* `playground/engine.js` (release asset `fwimg-playground.js`): runs the
  CLI in a browser or node over an in-memory file system; input bounded to
  32 MiB, `--max-size` defaulting to 128 MiB, a new instance per run.
* A same-bytes test, wasm against native (exit code, stdout, stderr, output
  bytes), under node and a wasip1 runtime (wazero); required in CI.
* `internal/wasmbench`: wasm against native timings at 1 KiB, 4 MiB, 32 MiB.
* A client-side playground on the go-binfmt docs site.

The js module is 7.2 MB (1.9 MB with gzip -9). Measured on a CI runner, wasm
is 4.6x to 13x slower than native at 32 MiB (README, "WebAssembly and the
playground"); that gap is an open performance defect, not a gate.

No change to the CLI or the library.

New formats (ROADMAP lot L5):

* `--uimage-comp none|gzip|lz4`: a compressed uImage (`ih_comp` 1 gzip, 5 lz4;
  the CRCs cover the compressed bytes; the gzip stream is reproducible).
  Reading one decompresses it, bounded by `--max-size`.
* `-O uf2` with `--uf2-family NAME|NUMBER`, and `-I uf2`.
* `-O verilog` with `--verilog-data-width 1..8` and `--verilog-endian`, and
  `-I verilog`.
* `info`, `verify` and the JSON manifest cover the three; the manifest schema
  lists `uf2` and `verilog` as formats (schema version unchanged).
* Library: `EncodeUF2`, `DecodeUF2`, `VerifyUF2`, `EncodeVerilog`,
  `DecodeVerilog`, `CompressPayload`, `DecompressPayload`, `UF2Families`,
  `ParseUF2Family`, `Image.Family`, `FormatUF2`, `FormatVerilog`.

Behaviour change: a uImage whose payload is not a valid gzip stream is now
refused with `ErrSyntax` (it used to be read as raw bytes).

Quality: fuzz targets `FuzzUF2`, `FuzzVerilog`, `FuzzUImageComp` with committed
corpora; bomb tests under a memory limit; CI differential lanes against mkimage
(compressed headers), `uf2conv.py` and objcopy (`-O verilog`), required (a
missing reference tool fails the lane); bench rows against the same tools.
