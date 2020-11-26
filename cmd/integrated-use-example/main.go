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
	secret     []byte // secret holds the encrypted data for later decryption.
}

// NewDataStructure creates a new GenericDataStructure with the identifier.
func NewDataStructure(identifier string) *GenericDataStructure {
	return &GenericDataStructure{
		Identifier: identifier,
	}
}

// SetSecret uses the provided password and secret data to encrypt and set the internal value of the structure. If the
// password or data is invalid, or if an error occurs during encryption, then err will be non-nil.
func (ds *GenericDataStructure) SetSecret(password, secret []byte) error {
	encryptedData, err := passlock.EncryptBytes(password, secret)
	if err != nil {
		return err
	}
	ds.secret = encryptedData
	return nil
}

// GetSecret uses the provided password to decrypt the internal value of the structure and return the decrypted value.
// If the data can not be verified due to an incorrect password or if the data has been tampered with then a non-nil
// error will be returned.
func (ds *GenericDataStructure) GetSecret(password []byte) (decryptedData []byte, err error) {
	decryptedData, err = passlock.DecryptBytes(password, ds.secret)
	return decryptedData, err
}

func main() {
	password := []byte("Pa$$w0rd")
	data := NewDataStructure("ID 1234")
	fmt.Println("Encrypting secret data...")
	err := data.SetSecret(password, []byte("Encrypt this"))
	if err != nil {
		log.Fatalf("Failed to encrypt data: %v\n", err)
	}
	fmt.Println("Data structure secret set with encrypted data")

	/* ... Some logic to pass the data structure around ... */

	fmt.Println("Decrypting data...")
	secret, err := data.GetSecret(password)
	if err != nil {
		log.Fatalf("Failed to decrypt data: %v\n", err)
	}
	fmt.Printf("The decrypted secret is '%s'\n", string(secret))
}
