package sevenzip

import (
	"bytes"
	"io"
	"io/fs"
)

var _ fs.FileInfo = (*ArchiveEntry)(nil)

// ArchiveEntry represents a single entry in a 7-zip archive.
type ArchiveEntry struct {
	fs.FileInfo
	file           *File
	CompressedSize int64
	isCompressed   bool
	isEncrypted    bool
}

func (e *ArchiveEntry) IsCompressed() bool {
	return e.isCompressed
}

func (e *ArchiveEntry) IsEncrypted() bool {
	return e.isEncrypted
}

func (e *ArchiveEntry) Open() (io.ReadCloser, error) {
	return e.file.Open()
}

// Iter iterates through files in a 7-zip archive.
type Iter struct {
	r                    *Reader
	index                int
	err                  error
	isCompressedByFolder map[int]struct{}
	isEncryptedByFolder  map[int]struct{}

	HasCompression bool
	HasEncryption  bool
}

// Iter returns an iterator for all files in the archive.
func (r *Reader) Iter() *Iter {
	it := &Iter{
		r:                    r,
		index:                -1,
		isCompressedByFolder: map[int]struct{}{},
		isEncryptedByFolder:  map[int]struct{}{},
	}
	if r.si.unpackInfo != nil {
		for folderIdx, folder := range r.si.unpackInfo.folder {
			for _, coder := range folder.coder {
				if bytes.Equal(coder.id, MethodIdCopy) {
					continue
				}
				if bytes.Equal(coder.id, MethodId7ZAES) {
					it.isEncryptedByFolder[folderIdx] = struct{}{}
				} else {
					it.isCompressedByFolder[folderIdx] = struct{}{}
				}
			}
		}
		it.HasCompression = len(it.isCompressedByFolder) > 0
		it.HasEncryption = len(it.isEncryptedByFolder) > 0
	}
	return it
}

func (it *Iter) Next() bool {
	if it.err != nil {
		return false
	}
	it.index++
	return it.index < len(it.r.File)
}

func (it *Iter) Entry() *ArchiveEntry {
	file := it.r.File[it.index]
	entry := &ArchiveEntry{
		FileInfo: file.FileInfo(),
		file:     file,
	}

	_, entry.isCompressed = it.isCompressedByFolder[file.folder]
	_, entry.isEncrypted = it.isEncryptedByFolder[file.folder]

	if it.r.si.packInfo != nil && it.r.si.unpackInfo != nil {
		compressedSize := uint64(0)
		if file.folder < len(it.r.si.unpackInfo.folder) {
			folder := it.r.si.unpackInfo.folder[file.folder]
			packedOffset := 0
			for i := 0; i < file.folder; i++ {
				packedOffset += len(it.r.si.unpackInfo.folder[i].packed)
			}
			for i := 0; i < len(folder.packed); i++ {
				if packedOffset+i < len(it.r.si.packInfo.size) {
					compressedSize += it.r.si.packInfo.size[packedOffset+i]
				}
			}
		}
		entry.CompressedSize = int64(compressedSize)
	}

	return entry
}

func (it *Iter) Err() error {
	return it.err
}
