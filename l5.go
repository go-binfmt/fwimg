package fwimg

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/go-compressions/lz4"
)

// L5: the payload compressions a uImage can carry. U-Boot names the
// compression by container, not by algorithm (docs/spec-notes.md 5.2): code 1 is
// a gzip file, code 5 an LZ4 frame (LZ4F_MAGIC 0x184D2204, include/image.h:
// IH_COMP_LZ4 = 5), not a raw block. mkimage never compresses, so the payload is
// compressed here and the header only records which container it is.
const (
	// CompLZ4 is IH_COMP_LZ4: the payload is one standard LZ4 frame.
	CompLZ4 = 5
)

// CompFromName maps a --uimage-comp name (none, gzip, lz4) to the header code.
func CompFromName(s string) (byte, error) {
	switch s {
	case "", "none":
		return CompNone, nil
	case "gzip":
		return CompGzip, nil
	case "lz4":
		return CompLZ4, nil
	}
	return 0, fmt.Errorf("%w: unknown uimage compression %q (want none, gzip, lz4)", ErrFormat, s)
}

// CompressPayload compresses payload into the container comp names. CompNone
// returns it as it is. The output is reproducible: a gzip file has no
// modification time, no name and the fixed header of the best-compression
// level, an LZ4 frame is lz4.CompressFrame's deterministic one. A comp this
// package cannot write is refused (ErrFormat).
func CompressPayload(payload []byte, comp byte) ([]byte, error) {
	switch comp {
	case CompNone:
		return payload, nil
	case CompGzip:
		var b bytes.Buffer
		// BestCompression is a valid level and a bytes.Buffer never fails to
		// write, so none of these three can return an error: they are ignored
		// rather than guarded by a branch no input reaches.
		zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
		// A zero Header is what makes it reproducible: ModTime zero writes MTIME 0.
		_, _ = zw.Write(payload)
		_ = zw.Close()
		return b.Bytes(), nil
	case CompLZ4:
		return lz4.CompressFrame(payload), nil
	}
	return nil, fmt.Errorf("%w: cannot write a %s compressed uImage payload", ErrFormat, nameOr(uimageComp, comp, "unknown"))
}

// DecompressPayload is the inverse of CompressPayload for a payload of at most
// maxOut decompressed bytes (zero means DefaultMaxSize; the bound is capped at
// the largest int). A payload that expands past it is refused with ErrTooLarge,
// before it is held in memory for gzip (the reader stops one byte past the
// bound) and before the buffer is made for LZ4 (lz4.DecompressFrameLimit). A
// stream that is not the container, or is cut or damaged, is ErrSyntax. A comp
// this package cannot read is ErrFormat.
func DecompressPayload(payload []byte, comp byte, maxOut uint64) ([]byte, error) {
	limit := maxFill(maxOut)
	if limit > math.MaxInt32 {
		limit = math.MaxInt32
	}
	switch comp {
	case CompNone:
		if uint64(len(payload)) > limit {
			return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, len(payload), limit)
		}
		return payload, nil
	case CompGzip:
		zr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("uimage: %w: gzip: %v", ErrSyntax, err)
		}
		defer zr.Close()
		out, err := io.ReadAll(io.LimitReader(zr, int64(limit)+1))
		if err != nil {
			return nil, fmt.Errorf("uimage: %w: gzip: %v", ErrSyntax, err)
		}
		if uint64(len(out)) > limit {
			return nil, fmt.Errorf("%w: the gzip payload expands past %d bytes", ErrTooLarge, limit)
		}
		return out, nil
	case CompLZ4:
		out, err := lz4.DecompressFrameLimit(payload, int(limit))
		switch {
		case errors.Is(err, lz4.ErrTooLarge):
			return nil, fmt.Errorf("%w: the LZ4 payload expands past %d bytes", ErrTooLarge, limit)
		case err != nil:
			return nil, fmt.Errorf("uimage: %w: lz4: %v", ErrSyntax, err)
		}
		return out, nil
	}
	return nil, fmt.Errorf("uimage: %w: the payload is %s compressed", ErrFormat, nameOr(uimageComp, comp, "unknown"))
}
