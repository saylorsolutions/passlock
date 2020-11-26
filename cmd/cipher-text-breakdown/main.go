package main

import (
	"fmt"

	passlock "github.com/saylorsolutions/password-lock"
)

const gcmNonceLen = 12
const scryptSaltLen = 32
const authenticationTagLen = 16

func main() {
	secretData := []byte("secret sauce")
	password := []byte("Pa$$w0rd")
	cipherText, err := passlock.EncryptBytes(password, secretData)
	if err != nil {
		panic("An error occurred encrypting data!")
	}

	totalCipherTextLen := len(cipherText)
	fmt.Printf("Length of encrypted data: %d\n", totalCipherTextLen)
	fmt.Printf("Actual cipher text length plus authentication tag is total length - GCM nonce length - scrypt salt length\n")
	actualCipherTextLen := totalCipherTextLen - gcmNonceLen - scryptSaltLen
	fmt.Printf("\t%d - %d - %d = %d\n", totalCipherTextLen, gcmNonceLen, scryptSaltLen, actualCipherTextLen)
	fmt.Printf("Removing the authentication tag length (%d) from the cipher text length yields the same size as the input\n", authenticationTagLen)
	fmt.Printf("\t%d - %d = %d\n", actualCipherTextLen, authenticationTagLen, actualCipherTextLen-authenticationTagLen)
	fmt.Printf("\tlen('%s') = %d\n\n", string(secretData), len(secretData))

	fmt.Printf("This means that for any input size of n bytes, the encrypted size will be n + %d + %d + %d bytes\n", gcmNonceLen, scryptSaltLen, authenticationTagLen)
}
