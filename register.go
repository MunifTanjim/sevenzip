package sevenzip

import (
	"errors"
	"io"
	"sync"

	"github.com/bodgit/sevenzip/internal/aes7z"
	"github.com/bodgit/sevenzip/internal/bcj2"
	"github.com/bodgit/sevenzip/internal/bra"
	"github.com/bodgit/sevenzip/internal/brotli"
	"github.com/bodgit/sevenzip/internal/bzip2"
	"github.com/bodgit/sevenzip/internal/deflate"
	"github.com/bodgit/sevenzip/internal/delta"
	"github.com/bodgit/sevenzip/internal/lz4"
	"github.com/bodgit/sevenzip/internal/lzma"
	"github.com/bodgit/sevenzip/internal/lzma2"
	"github.com/bodgit/sevenzip/internal/zstd"
)

// Decompressor describes the function signature that decompression/decryption
// methods must implement to return a new instance of themselves. They are
// passed any property bytes, the size of the stream and a slice of at least
// one io.ReadCloser's providing the stream(s) of bytes.
type Decompressor func([]byte, uint64, []io.ReadCloser) (io.ReadCloser, error)

var (
	//nolint:gochecknoglobals
	decompressors sync.Map

	errNeedOneReader = errors.New("copy: need exactly one reader")
)

func newCopyReader(_ []byte, _ uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errNeedOneReader
	}
	// just return the passed io.ReadCloser)
	return readers[0], nil
}

// https://github.com/ip7z/7zip/blob/main/DOC/Methods.txt
type MethodId []byte

var (
	MethodIdCopy    = MethodId{0x00}
	MethodIdDelta   = MethodId{0x03}
	MethodIdLZMA    = MethodId{0x03, 0x01, 0x01}
	MethodIdBCJ     = MethodId{0x03, 0x03, 0x01, 0x03}
	MethodIdBCJ2    = MethodId{0x03, 0x03, 0x01, 0x1b}
	MethodIdPPC     = MethodId{0x03, 0x03, 0x02, 0x05}
	MethodIdARM     = MethodId{0x03, 0x03, 0x05, 0x01}
	MethodIdSPARC   = MethodId{0x03, 0x03, 0x08, 0x05}
	MethodIdDeflate = MethodId{0x04, 0x01, 0x08}
	MethodIdBzip2   = MethodId{0x04, 0x02, 0x02}
	MethodIdZstd    = MethodId{0x04, 0xf7, 0x11, 0x01}
	MethodIdBrotli  = MethodId{0x04, 0xf7, 0x11, 0x02}
	MethodIdLZ4     = MethodId{0x04, 0xf7, 0x11, 0x04}
	MethodId7ZAES   = MethodId{0x06, 0xf1, 0x07, 0x01}
	MethodIdLZMA2   = MethodId{0x21}
)

//nolint:gochecknoinits
func init() {
	// Copy
	RegisterDecompressor(MethodIdCopy, Decompressor(newCopyReader))
	// Delta
	RegisterDecompressor(MethodIdDelta, Decompressor(delta.NewReader))
	// LZMA
	RegisterDecompressor(MethodIdLZMA, Decompressor(lzma.NewReader))
	// BCJ
	RegisterDecompressor(MethodIdBCJ, Decompressor(bra.NewBCJReader))
	// BCJ2
	RegisterDecompressor(MethodIdBCJ2, Decompressor(bcj2.NewReader))
	// PPC
	RegisterDecompressor(MethodIdPPC, Decompressor(bra.NewPPCReader))
	// ARM
	RegisterDecompressor(MethodIdARM, Decompressor(bra.NewARMReader))
	// SPARC
	RegisterDecompressor(MethodIdSPARC, Decompressor(bra.NewSPARCReader))
	// Deflate
	RegisterDecompressor(MethodIdDeflate, Decompressor(deflate.NewReader))
	// Bzip2
	RegisterDecompressor(MethodIdBzip2, Decompressor(bzip2.NewReader))
	// Zstandard
	RegisterDecompressor(MethodIdZstd, Decompressor(zstd.NewReader))
	// Brotli
	RegisterDecompressor(MethodIdBrotli, Decompressor(brotli.NewReader))
	// LZ4
	RegisterDecompressor(MethodIdLZ4, Decompressor(lz4.NewReader))
	// AES-CBC-256 & SHA-256
	RegisterDecompressor(MethodId7ZAES, Decompressor(aes7z.NewReader))
	// LZMA2
	RegisterDecompressor(MethodIdLZMA2, Decompressor(lzma2.NewReader))
}

// RegisterDecompressor allows custom decompressors for a specified method ID.
func RegisterDecompressor(method []byte, dcomp Decompressor) {
	decompressors.Store(string(method), dcomp)
}

func decompressor(method []byte) Decompressor {
	di, ok := decompressors.Load(string(method))
	if !ok {
		return nil
	}

	if d, ok := di.(Decompressor); ok {
		return d
	}

	return nil
}
