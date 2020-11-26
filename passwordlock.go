// encryption provides a non-portable but easy to use process to password encrypt data. Data nonces and salts are
// completely handled by the processing methods, so the user only needs to concern themselves with managing the
// password, plaintext, and ciphertext data.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/scrypt"
)

const (
	iterations        int = 1_048_576
	relativeBlockSize     = 8
	cpuCost               = 1
	aesKeySize            = 32 // 256 bit key
)

// generateKey creates a 256 bit AES key and returns the key and the salt. If any error occurs during the process of
// generating the key, then err will be non-nil. If the inputSalt parameter is nil then a secure randomly generated
// salt value will be used and returned.
func generateKey(pass, inputSalt []byte) (key, salt []byte, err error) {
	salt = make([]byte, 32)
	if inputSalt == nil || len(inputSalt) == 0 {
		if _, err = rand.Read(salt); err != nil {
			return
		}
	} else {
		salt = inputSalt
	}
	if key, err = scrypt.Key(pass, salt, iterations, relativeBlockSize, cpuCost, aesKeySize); err != nil {
		return
	}

	return
}

// EncryptBytes will encrypt the data using the password to generate a random key. The key salt will be appended to
// the data for later use. A data nonce is prepended to the ciphertext for later verification of the decrypted
// plaintext. Neither salt nor nonce being exposed provides any opportunity for an adversary to breach the protections
// of the sealed data, as these are generated using a secure random source, which doesn't inform any attack attempt.
func EncryptBytes(pass, data []byte) (cipherText []byte, err error) {
	if pass == nil || len(pass) == 0 {
		return nil, errors.New("invalid password: empty")
	}
	if data == nil || len(data) == 0 {
		return nil, errors.New("invalid data: empty")
	}

	key, salt, err := generateKey(pass, nil)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return
	}

	cipherText = append(gcm.Seal(nonce, nonce, data, nil), salt...)
	return
}

// DecryptBytes will decrypt the data using the provided password and the embedded salt to reconstruct the original key.
// The decrypted data will be validated with the previously prepended data nonce.
func DecryptBytes(pass, data []byte) (plainText []byte, err error) {
	if pass == nil || len(pass) == 0 {
		return nil, errors.New("invalid password: empty")
	}
	if data == nil || len(data) == 0 {
		return nil, errors.New("invalid data: empty")
	}

	saltBytesIdx := len(data) - 32
	salt, data := data[saltBytesIdx:], data[:saltBytesIdx]

	key, _, err := generateKey(pass, salt)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err = gcm.Open(nil, nonce, cipherText, nil)

	return
}
