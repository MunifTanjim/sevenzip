// Package aes7z implements the 7-zip AES decryption.
package aes7z

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
)

var (
	errAlreadyClosed          = errors.New("aes7z: already closed")
	errNeedOneReader          = errors.New("aes7z: need exactly one reader")
	errInsufficientProperties = errors.New("aes7z: not enough properties")
	errNoPasswordSet          = errors.New("aes7z: no password set")
	errUnsupportedMethod      = errors.New("aes7z: unsupported compression method")
	errNotSeekable            = errors.New("aes7z: underlying reader is not seekable")
	errNegativeSeek           = errors.New("aes7z: negative seek position")
	errSeekEOF                = errors.New("aes7z: seek past end of file")
	errInvalidWhence          = errors.New("aes7z: invalid whence")
)

const (
	ioBufSize      = 65536 // bufio buffer: 64KB to reduce underlying I/O calls
	decryptBufSize = 4096  // decrypt chunk: 256 AES blocks per CryptBlocks call
)

type readCloser struct {
	rc       io.ReadCloser
	rs       io.ReadSeeker // non-nil if underlying reader supports seeking; aliases rc (same object)
	br       *bufio.Reader // buffered reads from rc; reset on seek
	salt, iv []byte
	origIV   []byte // original IV preserved for seeking back to block 0
	cycles   int
	block    cipher.Block // kept for recreating CBC on seek
	cbc      cipher.BlockMode
	buf      bytes.Buffer
	dbuf     [decryptBufSize]byte // reusable buffer for multi-block decrypt
	pos      int64                // current position in decrypted stream
	size     int64                // total decrypted stream size
}

func (rc *readCloser) Close() error {
	if rc.rc == nil {
		return errAlreadyClosed
	}

	if err := rc.rc.Close(); err != nil {
		return fmt.Errorf("aes7z: error closing: %w", err)
	}

	rc.rc = nil

	return nil
}

func (rc *readCloser) Password(p string) error {
	key, err := calculateKey(p, rc.cycles, rc.salt)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes7z: error creating cipher: %w", err)
	}

	rc.block = block
	rc.cbc = cipher.NewCBCDecrypter(block, rc.iv)

	return nil
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.rc == nil {
		return 0, errAlreadyClosed
	}

	if rc.cbc == nil {
		return 0, errNoPasswordSet
	}

	if rc.size > 0 && rc.pos >= rc.size {
		return 0, io.EOF
	}

	for rc.buf.Len() < len(p) {
		needed := len(p) - rc.buf.Len()
		readSize := min(needed, decryptBufSize)
		// Round up to AES block boundary
		readSize = (readSize + aes.BlockSize - 1) &^ (aes.BlockSize - 1)

		n, err := io.ReadAtLeast(rc.br, rc.dbuf[:readSize], aes.BlockSize)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, fmt.Errorf("aes7z: error reading block: %w", err)
			}

			if n == 0 {
				break
			}
		}

		n -= n % aes.BlockSize // round down to block boundary

		if n == 0 {
			break
		}

		rc.cbc.CryptBlocks(rc.dbuf[:n], rc.dbuf[:n])

		_, _ = rc.buf.Write(rc.dbuf[:n])
	}

	n, err := rc.buf.Read(p)

	// Clamp to size — ciphertext may be padded to block boundary, so the
	// final decrypted block can contain padding bytes beyond the logical size.
	if rc.size > 0 && rc.pos+int64(n) > rc.size {
		n = int(rc.size - rc.pos)
		err = io.EOF
	}

	rc.pos += int64(n)

	if err != nil && !errors.Is(err, io.EOF) {
		err = fmt.Errorf("aes7z: error reading: %w", err)
	}

	return n, err
}

// Seek sets the decryption position within the stream. It supports random
// access by exploiting CBC decryption's property: to decrypt block N, only
// ciphertext block N-1 (as IV) and block N are needed.
func (rc *readCloser) Seek(offset int64, whence int) (int64, error) {
	if rc.rs == nil {
		return 0, errNotSeekable
	}

	if rc.block == nil {
		return 0, errNoPasswordSet
	}

	var abs int64

	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = rc.pos + offset
	case io.SeekEnd:
		abs = rc.size + offset
	default:
		return 0, errInvalidWhence
	}

	if abs < 0 {
		return 0, errNegativeSeek
	}

	if abs > rc.size {
		return 0, errSeekEOF
	}

	// At EOF — just reset buffer, no block decryption needed
	if abs == rc.size {
		rc.buf.Reset()
		rc.pos = abs

		return abs, nil
	}

	blockNum := abs / aes.BlockSize
	blockOffset := abs % aes.BlockSize

	// Determine IV for the target block
	var iv [aes.BlockSize]byte

	if blockNum == 0 {
		copy(iv[:], rc.origIV)
	} else {
		// Read the previous ciphertext block to use as IV
		ivSeekPos := (blockNum - 1) * aes.BlockSize

		if _, err := rc.rs.Seek(ivSeekPos, io.SeekStart); err != nil {
			return 0, fmt.Errorf("aes7z: error seeking for IV: %w", err)
		}

		if _, err := io.ReadFull(rc.rs, iv[:]); err != nil {
			return 0, fmt.Errorf("aes7z: error reading IV block: %w", err)
		}
	}

	// Reset CBC with the computed IV
	rc.cbc = cipher.NewCBCDecrypter(rc.block, iv[:])

	// Position underlying reader at the target block
	targetPos := blockNum * aes.BlockSize

	if _, err := rc.rs.Seek(targetPos, io.SeekStart); err != nil {
		return 0, fmt.Errorf("aes7z: error seeking to block: %w", err)
	}

	// Reset buffered reader after repositioning underlying reader
	rc.br.Reset(rc.rc)

	// Clear decrypted buffer
	rc.buf.Reset()

	// If not block-aligned, decrypt the partial block and keep the remainder
	if blockOffset > 0 {
		var block [aes.BlockSize]byte

		if _, err := io.ReadFull(rc.br, block[:]); err != nil {
			return 0, fmt.Errorf("aes7z: error reading partial block: %w", err)
		}

		rc.cbc.CryptBlocks(block[:], block[:])

		rc.buf.Write(block[blockOffset:])
	}

	rc.pos = abs

	return abs, nil
}

// NewReader returns a new AES-256-CBC & SHA-256 io.ReadCloser. The Password
// method must be called before attempting to call Read so that the block
// cipher is correctly initialised. If the underlying reader supports
// io.ReadSeeker, the returned reader will also support Seek for random access.
func NewReader(p []byte, size uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errNeedOneReader
	}

	// Need at least two bytes initially
	if len(p) < 2 {
		return nil, errInsufficientProperties
	}

	if p[0]&0xc0 == 0 {
		return nil, errUnsupportedMethod
	}

	rc := new(readCloser)

	salt := p[0]>>7&1 + p[1]>>4
	iv := p[0]>>6&1 + p[1]&0x0f

	if len(p) != int(2+salt+iv) {
		return nil, errInsufficientProperties
	}

	rc.salt = p[2 : 2+salt]
	rc.iv = make([]byte, aes.BlockSize)
	copy(rc.iv, p[2+salt:])

	// Preserve original IV for seeking back to block 0
	rc.origIV = make([]byte, aes.BlockSize)
	copy(rc.origIV, rc.iv)

	rc.cycles = int(p[0] & 0x3f)
	rc.size = int64(size) //nolint:gosec
	rc.rc = readers[0]
	rc.br = bufio.NewReaderSize(rc.rc, ioBufSize)

	// Detect seekable underlying reader
	if rs, ok := readers[0].(io.ReadSeeker); ok {
		rc.rs = rs
	}

	return rc, nil
}
