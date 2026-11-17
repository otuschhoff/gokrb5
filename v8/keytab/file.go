package keytab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/otuschhoff/gokrb5/v8/internal/fileio"
)

// WriteFile atomically writes kt to path with mode 0600.
func (kt *Keytab) WriteFile(name string) error {
	path, _, err := ResolveName(name, nil)
	if err != nil {
		return err
	}
	b, err := kt.Marshal()
	if err != nil {
		return fmt.Errorf("error marshaling keytab: %w", err)
	}
	if err := fileio.AtomicWrite(path, b, syncDir); err != nil {
		return fmt.Errorf("write keytab: %w", err)
	}
	kt.name = path
	return nil
}

// AppendToFile appends entries to a keytab while holding an advisory exclusive lock.
// A missing or empty file is initialized as a version 2 keytab.
func AppendToFile(name string, entries ...Entry) (err error) {
	path, _, err := ResolveName(name, nil)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close keytab: %w", closeErr))
		}
	}()
	// Creation may race, but the lock serializes header inspection and each append.
	if err := lockFile(f); err != nil {
		return err
	}
	defer func() {
		if unlockErr := unlockFile(f); unlockErr != nil {
			err = errors.Join(err, unlockErr)
		}
	}()

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
			return fmt.Errorf("cannot append to invalid keytab: %w", err)
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
	if _, err := io.Copy(f, bytes.NewReader(appendData)); err != nil {
		return err
	}
	return f.Sync()
}
