package pac

import (
	"encoding/binary"
	"fmt"
	"io"
)

func readPACUint32(r io.Reader, field string) (uint32, error) {
	var data [4]byte
	if _, err := io.ReadFull(r, data[:]); err != nil {
		return 0, fmt.Errorf("read %s: %w", field, err)
	}
	return binary.LittleEndian.Uint32(data[:]), nil
}

func readPACBytes(r io.Reader, size int, field string) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return data, fmt.Errorf("read %s: %w", field, err)
	}
	return data, nil
}
