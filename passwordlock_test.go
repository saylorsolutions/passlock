package passlock

import (
	"fmt"
	"runtime/debug"
	"testing"

	testify "github.com/stretchr/testify/require"
)

func TestEncryptBytes(t *testing.T) {
	assert := testify.New(t)

	badPassword := []byte("s3cre+")
	data := []byte("some data that needs to be encrypted")

	encrypted, err := EncryptBytes(badPassword, data)
	assert.NoError(err, "Should be no error from encryption")
	assert.NotEqual(data, encrypted)

	decrypted, err := DecryptBytes(badPassword, encrypted)
	assert.NoError(err, "Should be no error from decryption")
	assert.Equal(data, decrypted)
}

func TestEncryptBytes_Negative(t *testing.T) {
	validPassword := []byte("s3cre+")
	validData := []byte("some data that needs to be encrypted")

	tests := map[string]struct {
		pass []byte
		data []byte
	}{
		"Nil pass":   {pass: nil, data: validData},
		"Nil data":   {pass: validPassword, data: nil},
		"Both nil":   {pass: nil, data: nil},
		"Empty pass": {pass: []byte{}, data: validData},
		"Empty data": {pass: validPassword, data: []byte{}},
		"Both empty": {pass: []byte{}, data: []byte{}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := EncryptBytes(tc.pass, tc.data); err == nil {
				t.Fatal("Should have thrown an error")
			}
		})
	}
}

func TestDecryptBytes_Negative(t *testing.T) {
	validPassword := []byte("s3cre+")
	validData, err := EncryptBytes(validPassword, []byte("some data that needs to be encrypted"))
	if err != nil {
		t.Fatalf("Failed to encrypt test data")
	}

	tests := map[string]struct {
		pass []byte
		data []byte
	}{
		"Nil pass":   {pass: nil, data: validData},
		"Nil data":   {pass: validPassword, data: nil},
		"Both nil":   {pass: nil, data: nil},
		"Empty pass": {pass: []byte{}, data: validData},
		"Empty data": {pass: validPassword, data: []byte{}},
		"Both empty": {pass: []byte{}, data: []byte{}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					debug.PrintStack()
					t.Fatalf("Panic recovered: %v\n", r)
				}
			}()

			if _, err := DecryptBytes(tc.pass, tc.data); err == nil {
				t.Fatal("Should have thrown an error")
			} else {
				fmt.Println("Error thrown as expected:", err)
			}
		})
	}
}
