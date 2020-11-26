package main

import (
	"fmt"
	"log"

	passlock "github.com/saylorsolutions/password-lock"
)

// GenericDataStructure is an example data structure that holds an encrypted payload with a string identifier to allow
// application code to reference the encrypted data.
// The data structure can be safely transferred over an insecure network after construction with NewDataStructure.
type GenericDataStructure struct {
	Identifier string // Identifier is a string used to relate to the encrypted data.
	Secret     []byte // Secret holds the encrypted data for later decryption.
}

// NewDataStructure creates a new GenericDataStructure with the identifier and secret data encrypted using the provided
// password bytes.
func NewDataStructure(identifier string, password, secretData []byte) (*GenericDataStructure, error) {
	secret, err := passlock.EncryptBytes(password, secretData)
	if err != nil {
		return nil, err
	}
	return &GenericDataStructure{
		Identifier: identifier,
		Secret:     secret,
	}, nil
}

func main() {
	password := []byte("Pa$$w0rd")
	fmt.Println("Encrypting secret data...")
	data, err := NewDataStructure("ID 1234", password, []byte("Encrypt this"))
	if err != nil {
		log.Fatalf("Failed to encrypt data: %v\n", err)
	}
	fmt.Println("Data structure created with encrypted data")

	/* ... Some logic to pass the data structure around ... */

	fmt.Println("Decrypting data...")
	secret, err := passlock.DecryptBytes(password, data.Secret)
	if err != nil {
		log.Fatalf("Failed to decrypt data: %v\n", err)
	}
	fmt.Printf("The decrypted secret is '%s'\n", string(secret))
}
