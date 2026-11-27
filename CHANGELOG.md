# Changelog

Versions are `vMAJOR.MINOR.PATCH`; below v1 a breaking change bumps the MINOR.

## v0.7.0

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
