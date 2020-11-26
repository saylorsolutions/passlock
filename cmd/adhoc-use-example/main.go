package main

import (
	"fmt"
	"log"

	passlock "github.com/saylorsolutions/password-lock"
)

func main() {
	password := []byte("Pa$$w0rd")
	fmt.Println("Encrypting secret data...")
	data, err := passlock.EncryptBytes(password, []byte("Encrypt this"))
	if err != nil {
		log.Fatalf("Failed to encrypt data: %v\n", err)
	}
	fmt.Println("Ready to send encrypted data")

	/* ... Some logic to send the data ... */

	fmt.Println("Decrypting data...")
	secret, err := passlock.DecryptBytes(password, data)
	if err != nil {
		log.Fatalf("Failed to decrypt data: %v\n", err)
	}
	fmt.Printf("The decrypted secret is '%s'\n", string(secret))
}
