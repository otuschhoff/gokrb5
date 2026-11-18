package crypto

import "fmt"

// cryptoOperation labels failures without changing the values returned by a profile.
type cryptoOperation string

func (op cryptoOperation) wrap(err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (op cryptoOperation) bytes(data []byte, err error) ([]byte, error) {
	return data, op.wrap(err)
}

func (op cryptoOperation) blocks(iv, ciphertext []byte, err error) ([]byte, []byte, error) {
	return iv, ciphertext, op.wrap(err)
}
