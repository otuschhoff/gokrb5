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
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
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

	version, endian, writeHeader, err := appendTarget(f)
	if err != nil {
		return err
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

// appendTarget inspects f and returns the format version and byte order to
// append with, reporting writeHeader for an empty file whose header must be
// written first. An empty file is initialized as a version 2 big-endian
// keytab; a non-empty file must parse as a valid keytab.
func appendTarget(f *os.File) (uint8, binary.ByteOrder, bool, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, nil, false, err
	}
	if info.Size() == 0 {
		if cerr := f.Chmod(0o600); cerr != nil {
			return 0, nil, false, cerr
		}
		return 2, binary.BigEndian, true, nil
	}
	if _, serr := f.Seek(0, io.SeekStart); serr != nil {
		return 0, nil, false, serr
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return 0, nil, false, err
	}
	existing := new(Keytab)
	if uerr := existing.Unmarshal(data); uerr != nil {
		return 0, nil, false, fmt.Errorf("cannot append to invalid keytab: %w", uerr)
	}
	return existing.version, existing.byteOrder, false, nil
}
