package keytab

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFile atomically writes kt to path with mode 0600.
func (kt *Keytab) WriteFile(name string) error {
	path, _, err := ResolveName(name, nil)
	if err != nil {
		return err
	}
	b, err := kt.Marshal()
	if err != nil {
		return fmt.Errorf("error marshaling keytab: %v", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	kt.name = path
	return nil
}

// AppendToFile appends entries to a keytab while holding an advisory exclusive lock.
// A missing or empty file is initialized as a version 2 keytab.
func AppendToFile(name string, entries ...Entry) error {
	path, _, err := ResolveName(name, nil)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Creation may race, but the lock serializes header inspection and each append.
	if err := lockFile(f); err != nil {
		return err
	}
	defer unlockFile(f)

	info, err := f.Stat()
	if err != nil {
		return err
	}
	version := uint8(2)
	var endian binary.ByteOrder = binary.BigEndian
	writeHeader := info.Size() == 0
	if writeHeader {
		if err := f.Chmod(0600); err != nil {
			return err
		}
	} else {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		existing := new(Keytab)
		if err := existing.Unmarshal(data); err != nil {
			return fmt.Errorf("cannot append to invalid keytab: %v", err)
		}
		version = existing.version
		endian = existing.byteOrder
	}

	var appendData []byte
	if writeHeader {
		appendData = append(appendData, keytabFirstByte, version)
	}
	for _, entry := range entries {
		record, err := entry.marshal(int(version), endian)
		if err != nil {
			return err
		}
		appendData = append(appendData, record...)
	}
	if len(appendData) == 0 {
		return nil
	}
	if _, err := f.Write(appendData); err != nil {
		return err
	}
	return f.Sync()
}
