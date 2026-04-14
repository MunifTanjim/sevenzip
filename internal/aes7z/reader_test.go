package aes7z

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seekableReadCloser wraps a bytes.Reader to implement io.ReadSeeker and io.ReadCloser.
type seekableReadCloser struct {
	*bytes.Reader
}

func (s *seekableReadCloser) Close() error { return nil }

func TestReadCloser_Seek(t *testing.T) {
	t.Parallel()

	// Create test plaintext (64 bytes = 4 AES blocks)
	plaintext := make([]byte, 64)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// Generate a random AES-256 key and IV
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	// Encrypt the plaintext using AES-256-CBC
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	// Build properties: cycles=0x3f (use key directly), no salt, 16-byte IV
	// Byte 0: 0xc0 | 0x3f = 0xff (bits 7-6 for IV high, bit 5-0 for cycles)
	//   IV high bits: (0xff >> 6) & 1 = 1
	//   Salt high bit: (0xff >> 7) & 1 = 1
	// Byte 1: salt_low=0, iv_low=15 → 0x0f
	//   Salt size: 1 + 0 = 1 (from high bit)
	//   IV size: 1 + 15 = 16
	// That means we need 1 byte of salt.
	//
	// Simpler: use cycles=0x3f, salt=0, iv=16
	// Byte 0: 0x40 | 0x3f = 0x7f → iv_high=1, salt_high=0, cycles=0x3f
	// Byte 1: salt_low=0, iv_low=15 → 0x0f
	// Salt size: 0 + 0 = 0
	// IV size: 1 + 15 = 16
	props := make([]byte, 2+0+16)
	props[0] = 0x7f // iv_high=1, salt_high=0, cycles=0x3f
	props[1] = 0x0f // salt_low=0, iv_low=15
	copy(props[2:], iv)

	// With cycles=0x3f, the key derivation uses the password bytes directly as key.
	// We need to construct the password such that SHA-256 of (salt + utf16le(password))
	// equals our key. Instead, let's use the key derivation path properly.
	//
	// Actually, with cycles=0x3f, calculateKey does:
	//   return append(b, make([]byte, max(0, 32-len(b)))...), nil
	// where b = salt + utf16le(password)
	// So we need utf16le(password) to equal our 32-byte key.
	// This is tricky with arbitrary key bytes. Let's just construct the readCloser directly.

	underlying := &seekableReadCloser{bytes.NewReader(ciphertext)}
	rc := &readCloser{
		rc:     underlying,
		rs:     underlying,
		br:     bufio.NewReader(underlying),
		iv:     make([]byte, aes.BlockSize),
		origIV: make([]byte, aes.BlockSize),
		block:  block,
		size:   int64(len(plaintext)),
	}
	copy(rc.iv, iv)
	copy(rc.origIV, iv)
	rc.cbc = cipher.NewCBCDecrypter(block, iv)

	// Read all data first to verify basic decryption works
	decrypted := make([]byte, len(plaintext))
	n, err := io.ReadFull(rc, decrypted)
	require.NoError(t, err)
	assert.Equal(t, len(plaintext), n)
	assert.Equal(t, plaintext, decrypted)

	// Test SeekStart to beginning
	pos, err := rc.Seek(0, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	// Read again from start
	decrypted2 := make([]byte, len(plaintext))
	n, err = io.ReadFull(rc, decrypted2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)

	// Test seek to block-aligned position (block 2 = offset 32)
	pos, err = rc.Seek(32, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(32), pos)

	partial := make([]byte, 32)
	n, err = io.ReadFull(rc, partial)
	require.NoError(t, err)
	assert.Equal(t, plaintext[32:], partial)

	// Test seek to non-block-aligned position (offset 5)
	pos, err = rc.Seek(5, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(5), pos)

	rest := make([]byte, 59)
	n, err = io.ReadFull(rc, rest)
	require.NoError(t, err)
	assert.Equal(t, plaintext[5:], rest)

	// Test SeekCurrent
	_, _ = rc.Seek(10, io.SeekStart)
	pos, err = rc.Seek(5, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(15), pos)

	// Test SeekEnd
	pos, err = rc.Seek(-16, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(48), pos)

	last := make([]byte, 16)
	n, err = io.ReadFull(rc, last)
	require.NoError(t, err)
	assert.Equal(t, plaintext[48:], last)

	// Test backward seek
	_, _ = rc.Seek(32, io.SeekStart)
	pos, err = rc.Seek(5, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(5), pos)

	data := make([]byte, 10)
	n, err = io.ReadFull(rc, data)
	require.NoError(t, err)
	assert.Equal(t, plaintext[5:15], data)

	// Test error cases
	_, err = rc.Seek(-1, io.SeekStart)
	assert.ErrorIs(t, err, errNegativeSeek)

	_, err = rc.Seek(int64(len(plaintext))+1, io.SeekStart)
	assert.ErrorIs(t, err, errSeekEOF)

	_, err = rc.Seek(0, 99)
	assert.ErrorIs(t, err, errInvalidWhence)
}

func TestReadCloser_Seek_NonBlockAligned(t *testing.T) {
	t.Parallel()

	// 50 bytes = 3 full blocks + 2 bytes. Ciphertext padded to 64 bytes (4 blocks).
	plaintext := make([]byte, 50)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	// Pad plaintext to block boundary for encryption
	padded := make([]byte, 64)
	copy(padded, plaintext)

	ciphertext := make([]byte, 64)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	underlying := &seekableReadCloser{bytes.NewReader(ciphertext)}
	rc := &readCloser{
		rc:     underlying,
		rs:     underlying,
		br:     bufio.NewReader(underlying),
		iv:     make([]byte, aes.BlockSize),
		origIV: make([]byte, aes.BlockSize),
		block:  block,
		size:   50, // logical size, not padded size
	}
	copy(rc.iv, iv)
	copy(rc.origIV, iv)
	rc.cbc = cipher.NewCBCDecrypter(block, iv)

	// Read all — should get exactly 50 bytes, no padding leaked
	data := make([]byte, 64)
	n, err := rc.Read(data)
	assert.Equal(t, 50, n)
	assert.Equal(t, plaintext, data[:n])

	// Seek to non-aligned position near end
	pos, err := rc.Seek(45, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(45), pos)

	tail := make([]byte, 10)
	n, err = rc.Read(tail)
	assert.Equal(t, 5, n) // only 5 bytes remain (50-45)
	assert.Equal(t, plaintext[45:50], tail[:n])

	// Seek to exact size (EOF) — should not leak padding
	pos, err = rc.Seek(50, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(50), pos)

	n, err = rc.Read(data)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, io.EOF)

	// Seek back to 0 and re-read
	pos, err = rc.Seek(0, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	data2 := make([]byte, 50)
	n, err = io.ReadFull(rc, data2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, data2)
}

func TestReadCloser_Seek_NotSeekable(t *testing.T) {
	t.Parallel()

	rc := &readCloser{}

	_, err := rc.Seek(0, io.SeekStart)
	assert.ErrorIs(t, err, errNotSeekable)
}

func TestReadCloser_Seek_NoPassword(t *testing.T) {
	t.Parallel()

	rc := &readCloser{
		rs: &seekableReadCloser{bytes.NewReader(nil)},
	}

	_, err := rc.Seek(0, io.SeekStart)
	assert.ErrorIs(t, err, errNoPasswordSet)
}
