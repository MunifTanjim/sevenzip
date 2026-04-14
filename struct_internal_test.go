package sevenzip

import (
	"bytes"
	"io"
	"math"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileReadCloser_Seek(t *testing.T) {
	t.Parallel()

	r, err := OpenReader(filepath.Join("testdata", "t0.7z"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err = r.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	require.GreaterOrEqual(t, len(r.File), 1)

	rc, _, _, err := r.folderReader(r.si, r.File[0].folder)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err = rc.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	_, err = rc.Seek(0, math.MaxInt)
	assert.Equal(t, err, errInvalidWhence)

	_, err = rc.Seek(-1, io.SeekStart)
	assert.Equal(t, err, errNegativeSeek)

	n, err := rc.Seek(1, io.SeekCurrent)
	assert.Equal(t, int64(1), n)
	assert.NoError(t, err) //nolint:testifylint

	// Backward seek works for Copy-only folders (optimized direct seek)
	n, err = rc.Seek(-1, io.SeekCurrent)
	assert.NoError(t, err) //nolint:testifylint
	assert.Equal(t, int64(0), n)

	_, err = rc.Seek(int64(r.File[0].UncompressedSize)+1, io.SeekStart) //nolint:gosec
	assert.Equal(t, err, errSeekEOF)

	n, err = rc.Seek(int64(r.File[0].UncompressedSize), io.SeekStart) //nolint:gosec
	assert.Equal(t, n, int64(r.File[0].UncompressedSize))             //nolint:gosec
	assert.NoError(t, err)                                            //nolint:testifylint

	n, err = rc.Seek(0, io.SeekEnd)
	assert.Equal(t, n, int64(r.File[0].UncompressedSize)) //nolint:gosec
	assert.NoError(t, err)
}

func TestFolderReadCloser_Seek_EncryptedOnly(t *testing.T) {
	t.Parallel()

	// t5.7z: encrypted (AES) + uncompressed (Copy), password="password"
	// Contains "bar" (4 bytes) and "foo" (4 bytes) in separate folders
	r, err := OpenReaderWithPassword(filepath.Join("testdata", "t5.7z"), "password")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, r.Close())
	}()

	require.GreaterOrEqual(t, len(r.File), 1)

	rc, _, _, err := r.folderReader(r.si, r.File[0].folder)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, rc.Close())
	}()

	// Verify the folder is detected as directly seekable
	assert.True(t, rc.canSeekOptimized(), "encrypted-only folder should support optimized seeking")

	fileSize := int64(r.File[0].UncompressedSize) //nolint:gosec

	// Test forward seek (should use optimized path)
	pos, err := rc.Seek(1, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pos)

	// Backward seek works for encrypted-only folders (optimized direct seek)
	pos, err = rc.Seek(-1, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	// Forward seek to end
	pos, err = rc.Seek(fileSize, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, fileSize, pos)

	// SeekEnd to end
	pos, err = rc.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, fileSize, pos)

	// Error cases
	_, err = rc.Seek(-1, io.SeekStart)
	assert.Equal(t, errNegativeSeek, err)

	_, err = rc.Seek(fileSize+1, io.SeekStart)
	assert.Equal(t, errSeekEOF, err)

	_, err = rc.Seek(0, math.MaxInt)
	assert.Equal(t, errInvalidWhence, err)
}

func TestFile_Open_Seek_EncryptedOnly(t *testing.T) {
	t.Parallel()

	// t5.7z: encrypted (AES) + uncompressed (Copy), password="password"
	r, err := OpenReaderWithPassword(filepath.Join("testdata", "t5.7z"), "password")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, r.Close())
	}()

	require.GreaterOrEqual(t, len(r.File), 1)

	// Open the first file
	f := r.File[0]
	rc, err := f.Open()
	require.NoError(t, err)

	defer func() {
		require.NoError(t, rc.Close())
	}()

	// Read entire file
	allData, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, int(f.UncompressedSize), len(allData))

	// Seek back to beginning via the fileReader
	seeker, ok := rc.(io.Seeker)
	require.True(t, ok, "fileReader should implement io.Seeker")

	pos, err := seeker.Seek(0, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	// Re-read and verify
	allData2, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(allData, allData2), "re-read after seek should produce same data")
}

func TestFile_Open_BackwardSeek_EncryptedOnly(t *testing.T) {
	t.Parallel()

	r, err := OpenReaderWithPassword(filepath.Join("testdata", "t5.7z"), "password")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, r.Close())
	}()

	require.GreaterOrEqual(t, len(r.File), 1)

	f := r.File[0]
	rc, err := f.Open()
	require.NoError(t, err)

	defer func() {
		require.NoError(t, rc.Close())
	}()

	// Read all data for reference
	allData, err := io.ReadAll(rc)
	require.NoError(t, err)

	seeker := rc.(io.Seeker)

	// Seek back to middle and read remainder
	mid := int64(len(allData)) / 2
	pos, err := seeker.Seek(mid, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, mid, pos)

	remainder, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, allData[mid:], remainder, "backward seek to middle should produce correct tail data")

	// Seek back to start again and read first byte
	pos, err = seeker.Seek(0, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	first := make([]byte, 1)
	n, err := rc.Read(first)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, allData[0], first[0])
}

func TestFolder_IsEncryptedOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		coders   []*coder
		expected bool
	}{
		{
			name:     "AES only",
			coders:   []*coder{{id: MethodId7ZAES}},
			expected: true,
		},
		{
			name:     "AES + Copy",
			coders:   []*coder{{id: MethodId7ZAES}, {id: MethodIdCopy}},
			expected: true,
		},
		{
			name:     "Copy only",
			coders:   []*coder{{id: MethodIdCopy}},
			expected: false,
		},
		{
			name:     "LZMA2 only",
			coders:   []*coder{{id: MethodIdLZMA2}},
			expected: false,
		},
		{
			name:     "AES + LZMA2",
			coders:   []*coder{{id: MethodId7ZAES}, {id: MethodIdLZMA2}},
			expected: false,
		},
		{
			name:     "empty coders",
			coders:   []*coder{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &folder{coder: tt.coders}
			assert.Equal(t, tt.expected, f.isEncryptedOnly())
		})
	}
}
