# fwimg spec notes

The facts the implementation lots in [ROADMAP.md](../ROADMAP.md) are built on,
each with the source it was read from. They are the **equality oracles** for
the tests: where a section says "objcopy writes X", a differential test
asserts fwimg writes X under the matching options, and where two references
disagree the note says so and names which one a test compares against.

Only sources that were opened are cited. Opened on 2026-11-25:

| Tag | Source | Revision read |
|---|---|---|
| **[texi]** | GNU binutils manual source, `binutils/doc/binutils.texi` | binutils 2.47 release tarball (signature alongside) |
| **[bfd]** | BFD back ends `bfd/srec.c`, `bfd/ihex.c`, `bfd/verilog.c`, `bfd/binary.c`; `binutils/objcopy.c`; `ld/ldlang.c` | binutils 2.47 |
| **[uboot]** | U-Boot `include/image.h`, `tools/mkimage.c`, `tools/default_image.c`, `tools/imagetool.c`, `tools/fit_image.c`, `boot/image.c`, `doc/mkimage.1`, `doc/usage/fit/source_file_format.rst` | `git.u-boot-project.org/u-boot/u-boot.git` master `9d67454e920b`, 2026-11-24 |
| **[fitspec]** | Flattened Image Tree Specification, <https://fitspec.osfw.foundation/> | v1.0 (revision 2026-APR-11) |
| **[dtspec]** | Devicetree Specification ch. 5 "Flattened Devicetree (DTB) Format", <https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html> | "stable" |
| **[srec_cat]** **[srec_cmp]** **[srec_input]** | SRecord manual pages, <https://srecord.sourceforge.net/man/man1/> `srec_cat.1`, `srec_cmp.1`, `srec_input.1` | SRecord 1.65 |
| **[srec5]** **[intel5]** | SRecord format pages `srec_motorola(5)`, `srec_intel(5)`, <https://srecord.sourceforge.net/man/man5/> | SRecord 1.65 |
| **[uf2]** | <https://github.com/microsoft/uf2> `README.md` (raw, master) | master |
| **[nvd]** | NVD CVE API, `keywordSearch=U-Boot` (all 79 results read) | 2026-11-25 |

**Not opened:** the Intel *Hexadecimal Object File Format Specification,
Rev. A (1988)* PDF itself (the archive.org copy timed out). [intel5] states
it is derived from that document; every Intel HEX fact below is cited to
[intel5] or to [bfd] and to nothing else.

---

## 1. GNU objcopy behaviour

### 1.1 Options

| Option | Semantics | Source |
|---|---|---|
| `-I bfdname` | "Consider the source file's object format to be *bfdname*, rather than attempting to deduce it." Without it objcopy **deduces** the input format through BFD. | [texi] 1365–1367, 1402–1405 |
| `-O bfdname` | Output format. `-O binary` "will essentially produce a memory dump … The memory dump will start at the load address of the lowest section copied". | [texi] 1372–1377, 1407–1410 |
| `-j pattern` | Copy only matching sections; repeatable; wildcards; a leading `!` excludes. | [texi] 1429–1446 |
| `-R pattern` | Remove matching sections; repeatable; wildcards; leading `!` keeps. **`-j` and `-R` together is undefined behaviour.** fwimg refuses the combination. | [texi] 1448–1464 |
| `--gap-fill val` | Fills gaps between sections, by **LMA**, by growing the lower section. | [texi] 1683–1687 |
| `--pad-to addr` | Pads to the **load address** `addr` by growing the last section, with the gap-fill byte (default 0). A `--pad-to` below the end is a silent no-op (`if (lma + size < _pad_to)`). | [texi] 1689–1692; [bfd] objcopy.c 3331–3352 |
| `--set-start val` | Sets the start (entry) address; "Not all object file formats support setting the start address." | [texi] 1694–1697; objcopy.c 2813–2834 |
| `--change-start incr` | Adds to the start address; applied after `--set-start` (`start = set_start; start += change_start`). | [texi] 1699–1704; objcopy.c 2813–2817 |
| `--change-addresses incr` / `--adjust-vma incr` | Adds `incr` to the VMA **and** LMA of every section **and** to the start address. "this does not relocate the sections". | [texi] 1706–1714 |
| `--srec-len=n` | Maximum **data** bytes per S-record (the manual says it "covers both address, data and crc fields", but the code clamps the data count: `_bfd_srec_len > MAXCHUNK - type - 2` → `255 - type - 2`, and 0 → 1). Default 16. | [texi] 1918–1921; [bfd] srec.c 124–132, 1032–1035 |
| `--srec-forceS3` | S3 data records only. | [texi] 1923–1925; srec.c 896–899 |
| `--verilog-data-width=n` | Bytes per Verilog data word; endianness from the input target. | [texi] 2266–2269 |

### 1.2 LMA versus VMA, and the huge-gap case

- All image back ends place data at the section **LMA**: `binary.c` sets
  `s->filepos = (s->lma - low)` with `low` the lowest LMA of the loadable,
  allocated sections that have contents ([bfd] binary.c 247–267); SREC uses
  `entry->where = section->lma + offset` (srec.c 909), Verilog likewise
  (verilog.c 140).
- **The only diagnostic for a large span** is a warning when a section's file
  offset is *negative*: "warning: writing section `%pA' at huge (ie negative)
  file offset" (binary.c 277–288). A positive gap of any size (e.g. `.text` at
  0x08000000 and `.data` LMA = VMA at 0x20000000) produces a file of that
  size silently. Nothing names the sections or the LMA/VMA split that caused it.

### 1.3 Memory regions

objcopy has no notion of a memory region. **ld** does: the linker script
`MEMORY` command ([texi] `ld/ld.texi` node MEMORY, line 6531) and the error
"region `%s' overflowed by %lu bytes" ([bfd] ldlang.c 6037–6050). That check
runs at link time, on the linker script's regions, not on an image.

---

## 2. Intel HEX

### 2.1 Record layout ([intel5]; [bfd] ihex.c 25–120)

```
:LL AAAA TT DD…DD CC
```

`LL` data byte count, `AAAA` 16-bit load offset (big-endian), `TT` type.

| Type | Name | LL | Payload |
|---|---|---|---|
| 00 | Data | n | n data bytes at the current base + AAAA |
| 01 | End of file | 00 | none (AAAA usually 0000) |
| 02 | Extended Segment Address | 02 | USBA; base = USBA << 4 |
| 03 | Start Segment Address | 04 | CS (2 bytes), IP (2 bytes) |
| 04 | Extended Linear Address | 02 | ULBA; base = ULBA << 16 |
| 05 | Start Linear Address | 04 | EIP, 32 bits big-endian |

**Checksum:** two's complement of the 8-bit sum of every byte from LL to the
last data byte inclusive; the sum of all bytes including the checksum is 0
([intel5]).

**Wrap rules** ([intel5]): under a type-02 base a byte's address is
`SBA + ((offset + index) mod 64K)`, i.e. a record crossing a 64 KiB boundary
wraps inside its segment; under type 04 the wrap is at 2^32. Both srec_cat
([intel5]) and objcopy (ihex.c 857–859) split records so none crosses a
64 KiB boundary — fwimg already does (`fwimg.go` IHEX).

**Decoder consequence (L1):** a record that crosses 64 KiB under either base
type is legal input and wraps; the decoder must implement the wrap, not
refuse it, and the fuzz invariant is "decode(encode(x)) == x".

### 2.2 What objcopy writes (oracle for `-O ihex`)

From ihex.c 757–899:

1. 16 data bytes per record (`CHUNK 16`, line 130). Records sorted by address.
2. Base selection per record: while the extended linear base is 0 and the
   address is `<= 0xFFFFF`, objcopy writes **type 02** records
   (`segbase = where & 0xf0000`, payload `segbase >> 4`); once an address is
   above 0xFFFFF it writes a type-02 `0000` (if a segment base was set) and
   then **type 04** records (lines 805–852).
3. Addresses above 32 bits are refused unless they are sign-extended 32-bit
   values (lines 772–790).
4. Start address, **only if non-zero**: `<= 0xFFFFF` → **type 03** with
   `CS = (start & 0xF0000) >> 4`, `IP = start & 0xFFFF`; otherwise
   **type 05** (lines 870–895).
5. EOF `:00000001FF`. Uppercase hex; lines end in **CRLF** (lines 718–744).

### 2.3 What srec_cat writes

`srec_cat -o x -Intel` defaults to "i32hex" (type 04 linear addressing);
`-address-length=3` selects "i16hex" (type 02), `-address-length=2` "i8hex"
(16-bit, no extension records) ([srec_cat] `-Address_Length`).

**The references disagree** for data between 64 KiB and 1 MiB: objcopy
writes type 02, srec_cat type 04. fwimg v0.2.1 writes type 04 only, i.e. it
matches srec_cat's default and **not** objcopy. L2 makes the address mode an
option and tests each mode against the tool that defines it.

---

## 3. Motorola S-records

### 3.1 Record layout ([srec5]; [bfd] srec.c 44–72)

```
S T LL AA…AA DD…DD CC
```

| Type | Address bytes | Content |
|---|---|---|
| S0 | 2 | header; address normally 0000, data = descriptive text |
| S1 / S2 / S3 | 2 / 3 / 4 | data |
| S5 | 2 | no data; the address field is the count of S1/S2/S3 records |
| S6 | 3 | no data; the same count, up to 24 bits |
| S7 / S8 / S9 | 4 / 3 / 2 | termination of an S3 / S2 / S1 block; address = execution start |

`LL` counts the bytes after itself: address + data + checksum. **Checksum:**
the ones' complement of the low byte of the sum of LL, address and data bytes
([srec5]; srec.c computes `255 - (sum & 0xff)`, lines 990–993).

### 3.2 What objcopy writes (oracle for `-O srec`)

From srec.c 890–1148:

1. **One** data record type for the whole file, chosen from the highest
   address written: S1 if every byte is `<= 0xFFFF`, S2 if `<= 0xFFFFFF`,
   else S3; `--srec-forceS3` forces S3 (lines 896–906).
2. S0 at address 0 carrying the **output file name**, truncated to 40 bytes
   (lines 1005–1016). fwimg takes the name from `--name`; the differential
   test passes the same name both ways.
3. 16 data bytes per record by default (`--srec-len`, §1.1).
4. **No S5/S6** record is ever written (the writer is header, data,
   terminator; lines 1123–1148).
5. The terminator is always written, type `10 - datatype` (S9/S8/S7), with
   the start address, 0 when there is none (lines 1062–1067).
6. Uppercase hex; lines end in **CRLF** (lines 997–998).

### 3.3 What srec_cat writes

Default output is Motorola; "the smallest possible address length is
emitted, this will be S19 for data in the first 64KB"; `-address-length=3`
forces S28, `=4` S37. Header, data-count (S5/S6), execution-start and footer
records are each switchable (`-Enable` / `-Disable`) ([srec_cat]). srec_cat
writes a single S5 when the count fits in 16 bits, otherwise S6 ([srec5]).

**S5/S6 oracle is srec_cat**: objcopy never writes them.

---

## 4. Verilog hex (`objcopy -O verilog`)

From [bfd] verilog.c 23–330 and [texi] 2266–2269:

- One `@ADDR` line per contiguous chunk, `ADDR` = byte address / data width,
  8 uppercase hex digits (16 when the address is `>= 2^32`), CRLF.
- A chunk whose address is not a multiple of the width is refused
  (`bfd_error_invalid_operation`, lines 302–307).
- Then lines of at most **16 bytes**: width 1 → `XX XX …` separated by single
  spaces, no trailing space. Width > 1, little-endian input → each word's
  bytes reversed, words separated by spaces, a short tail emitted reversed.
  Width > 1, big-endian → bytes in order with a space after every complete
  word, **including a trailing space at the end of the line** (the code
  carries a FIXME, lines 230–233, 274–285). The oracle keeps that quirk.
- srec_cat's `-VMem` is a different Verilog flavour ([srec_cat]); fwimg's
  `-O verilog` follows objcopy.

---

## 5. U-Boot legacy image (uImage)

### 5.1 Header ([uboot] include/image.h 315–339)

64 bytes, all integers **big-endian**:

| Off | Field | Size | Notes |
|---|---|---|---|
| 0 | `ih_magic` | 4 | `0x27051956` |
| 4 | `ih_hcrc` | 4 | CRC-32 of the 64-byte header with this field zeroed |
| 8 | `ih_time` | 4 | creation time, seconds since the epoch |
| 12 | `ih_size` | 4 | data size |
| 16 | `ih_load` | 4 | load address |
| 20 | `ih_ep` | 4 | entry point |
| 24 | `ih_dcrc` | 4 | CRC-32 of the data |
| 28 | `ih_os` / `ih_arch` / `ih_type` / `ih_comp` | 1 each | |
| 32 | `ih_name` | 32 | `memcpy` of `strnlen(name, 32)` bytes: **not** NUL-terminated at 32 bytes (image.h 1040–1048) |

CRC-32 is zlib's `crc32(0, …)` (IEEE, reflected, = Go `hash/crc32.ChecksumIEEE`):
default_image.c 79–105 (verify) and 121–165 (write: data CRC first, then the
header CRC over the header with `ih_hcrc` = 0).

### 5.2 Compression byte ([uboot] image.h 250–260; boot/image.c 187–217)

| Value | Name | Magic U-Boot expects |
|---|---|---|
| 0 | none | — |
| 1 | gzip | `1f 8b` |
| 2 | bzip2 | `42 5a` |
| 3 | lzma | `5d 00` — the **legacy `.lzma` ("LZMA alone")** container, not `.xz` |
| 4 | lzo | `89 4c` — the **lzop** container |
| 5 | lz4 | `04 22` — the **LZ4 frame** (`LZ4F_MAGIC 0x184D2204`, image.h 315), not a raw block |
| 6 | zstd | `28 b5` — a zstd frame |

"The image data should have already been compressed using this compression
type. **mkimage will not automatically compress image data.**" and `-C`
defaults to gzip ([uboot] doc/mkimage.1 163–177; tools/mkimage.c 28
`.comp = IH_COMP_GZIP`). The differential oracle for L5 is therefore:
header fields byte-equal to `mkimage -C <c>` run on fwimg's compressed
payload, plus "decompressing the payload with the reference decompressor
gives the input back". Byte equality of the compressed stream with another
compressor is not a goal.

### 5.3 Multi-file images (`-T multi`)

The payload starts with a table of big-endian `uint32` sizes terminated by a
zero entry; images follow, each padded to 4 bytes (boot/image.c 268–335;
`mkimage -T multi -d a:b:c`, doc/mkimage.1 224–228). U-Boot's own reader
counts entries with `for (i = 0; size[i]; ++i)` — **no bound against
`ih_size`** (boot/image.c 277–279). fwimg's reader (L1) bounds the table and
every component by `ih_size` and refuses overlap or overflow.

### 5.4 Timestamp and SOURCE_DATE_EPOCH

`imagetool_get_source_date()` (tools/imagetool.c 176–194): if
`SOURCE_DATE_EPOCH` is unset the time is the **input file's mtime**
(default_image.c 126, `sbuf->st_mtime`); if set it is `strtol(…, 10)`;
if `gmtime()` rejects it, mkimage prints "SOURCE_DATE_EPOCH is not valid" and
uses **0**. The FIT path calls the same function (fit_image.c 145).

fwimg v0.2.1 writes `Time` from the caller, default 0 (`fwimg.go`
`UImageOptions`). L3 adds `SOURCE_DATE_EPOCH` with mkimage's precedence but
**refuses** an unparsable value instead of silently writing 0.

### 5.5 Listing

`mkimage -l` "lists the information contained in the header of an existing
U-Boot image", autodetecting the type unless `-T` is given ([uboot]
doc/mkimage.1 69–102). For multi-file images the listing prints each
component size (boot/image.c 383–400). `fwimg info` (L4) prints the same
fields; the differential test compares field values, not layout.

---

## 6. FIT (Flattened Image Tree) — what a writer needs

From [fitspec] (sections cited) — the U-Boot tree now points there
([uboot] doc/usage/fit/source_file_format.rst).

- Root: `timestamp` (mandatory, seconds since 1970, §5.2.2), `description`
  (§5.2.1), `#address-cells` (§5.2.3, sizes `load` and `entry`; omissible
  when neither is used). Children `images` and `configurations` are
  mandatory (§5.2.4).
- Image node (§5.3): mandatory `description`, `type`, `compression`
  (`"none"` also for data the loader must not decompress, §5.3.1);
  `os` mandatory for `kernel`; `arch` mandatory for standalone, kernel,
  firmware, ramdisk, fdt; `data` unless external (§5.3.2); `load` / `entry`.
  Optional children `hash-N`, `signature-N` (§5.3.3).
- Hash node (§5.4.1): `algo` ∈ {crc16-ccitt (2), crc32 (4), md5 (16),
  sha1 (20), sha256 (32), sha384 (48), sha512 (64)} bytes, and `value`.
- `/configurations` carries `default` (§5.10.1); a configuration node has
  `description`, `kernel` or `firmware`, optional `fdt` (base then overlays),
  `ramdisk`, `loadables`, `compatible`, … (§5.11).
- External data (§5.1.3, §5.3.2): `data-size`; `data-offset` into an image
  store that **starts after the last byte of the DTB, aligned to 4 bytes**;
  or `data-position`, an absolute address. mkimage `-E` externalises, `-p`
  fixes positions, `-B` aligns each image. The spec does not state the
  origin of `data-offset` explicitly beyond "within the image store"; L7
  fixes it by a differential test against `mkimage -E`.

Security history ([nvd]) that the FIT reader must be tested against:
CVE-2018-1000205 (verified-boot signature validation bypass with a crafted
FIT), CVE-2018-3968 (missing FIT signature enforcement lets a legacy image
boot), CVE-2020-10648 (verified-boot bypass with a crafted FIT),
CVE-2021-27097 ("mishandles a modified FIT"), CVE-2021-27138 ("mishandles
use of unit addresses in a FIT"), CVE-2023-39902 (crafted FIT overwrites SPL
memory), CVE-2026-46728 (signature check bypassed "because hashed-nodes is
omitted from a hash"); for the legacy header, CVE-2024-38433 (an
unprotected uImage header parsed by a boot block). Each becomes a regression
case for `fwimg verify`: duplicate unit names, unit-address aliasing, hashes
that do not cover the nodes they claim, and external data overlapping the
DTB or each other are refused.

---

## 7. Devicetree blob (DTB v17) — for go-binfmt/fdt

From [dtspec] §5:

- Block order: header, memory reservation block, structure block, strings
  block; gaps allowed (§5.1).
- Header (§5.2): ten big-endian `uint32` — `magic 0xd00dfeed`, `totalsize`,
  `off_dt_struct`, `off_dt_strings`, `off_mem_rsvmap`, `version` (17),
  `last_comp_version` (16), `boot_cpuid_phys`, `size_dt_strings`,
  `size_dt_struct`.
- Memory reservation block (§5.3): 8-byte aligned; pairs of big-endian
  `uint64` (address, size), terminated by (0, 0).
- Structure block (§5.4): 4-byte aligned; tokens `FDT_BEGIN_NODE 1`
  (NUL-terminated name, zero-padded to 4), `FDT_END_NODE 2`, `FDT_PROP 3`
  (`len`, `nameoff`, value zero-padded to 4), `FDT_NOP 4`, `FDT_END 9`
  (exactly one, last). Properties precede subnodes (§5.4.2).
- Strings block (§5.5): NUL-terminated names, no alignment.

Reader invariants for the fuzzer: every offset and size inside `totalsize`,
blocks not overlapping, `nameoff` inside the strings block and its string
NUL-terminated there, nesting depth bounded, exactly one `FDT_END`,
properties before subnodes.

---

## 8. UF2

From [uf2]: 512-byte blocks, all fields little-endian `uint32`:

| Off | Field |
|---|---|
| 0 | magic `0x0A324655` ("UF2\n") |
| 4 | magic `0x9E5D5157` |
| 8 | flags: `0x1` not main flash, `0x1000` file container, `0x2000` familyID present, `0x4000` MD5 present, `0x8000` extension tags present |
| 12 | target address |
| 16 | payload size (256 typical, at most 476) |
| 20 | block number, from 0 |
| 24 | total blocks in the file |
| 28 | file size, family ID, or 0 |
| 32 | data, 476 bytes, zero-padded |
| 508 | final magic `0x0AB16F30` |

Payload size and target address 4-byte aligned; "256 is always correct".
Family IDs: `utils/uf2families.json` in the same repository; fwimg embeds a
copy pinned by commit and tests it against that file.

---

## 9. Comparison tools

- **srec_cmp** compares two load files "for equality … irrespective of the
  load order of the data", each file named with its own format
  ([srec_cmp] DESCRIPTION; the format options are those of [srec_input],
  shared by srec_cat, srec_cmp and srec_info). Exit 0 only when equal.
  The page does not mention comparing execution start addresses.
- **Format detection in SRecord**: none by default — an input without a
  format option is read as Motorola; `-Guess` opts in and may scan the file
  several times ([srec_input]).
- **CRC insertion**: `-CRC32_Big_Endian` / `-CRC32_Little_Endian address`
  insert a 4-byte CRC *into the image* ([srec_input]).

---

## 10. "The reference does not do X" — verdicts

| Claim | Verdict | Evidence |
|---|---|---|
| (a) explains a huge gap from LMA/VMA | **True** | objcopy only warns on a *negative* file offset; a positive gap is written silently and unexplained ([bfd] binary.c 277–288) |
| (b) memory-region fit check | **Partial** | ld checks `MEMORY` regions at link time ("region … overflowed", ldlang.c 6037–6050); objcopy, srec_cat and mkimage do not check an image against a region |
| (c) verify-after-write | **Partial** | no reference re-reads what it wrote; a separate `srec_cmp` run ([srec_cmp]) or `mkimage -l` / dumpimage (which checks both CRCs, default_image.c 54–105) does it as a second step |
| (d) JSON manifest with hashes | **True** | none emits one; srec_cat inserts a CRC into the image ([srec_input]), FIT stores hash nodes inside the FIT ([fitspec] §5.4) |
| (e) input format autodetection | **False** for objcopy, **partial** for SRecord | objcopy deduces the input format unless `-I` is given ([texi] 1365–1367, 1404–1405); SRecord defaults to Motorola and detects only with `-Guess` ([srec_input]). Raw binary input is never detected by either: objcopy needs `-I binary` |
| (f) SOURCE_DATE_EPOCH in mkimage | **False** | mkimage honours it (tools/imagetool.c 176–194; default_image.c 126; fit_image.c 145) |
| (g) srec_cmp already compares images regardless of format | **True** (data), start address unstated | [srec_cmp] DESCRIPTION; [srec_input] |
