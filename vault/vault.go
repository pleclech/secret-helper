package vault

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"strings"
)

const (
	DefaultFileMode = 0666
)

var (
	// ErrEmptyPassword is returned when password is empty
	ErrEmptyPassword = errors.New("password is blank")

	// ErrInvalidFormat is returned when secret content is not valid
	ErrInvalidFormat = errors.New("invalid secret format")

	// ErrInvalidPadding is returned when invalid key is used
	ErrInvalidPadding = errors.New("invalid padding")
)

// Encrypt encrypts the input string with the vault password
func Encrypt(input string, password string, pad int) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}

	salt, err := generateRandomBytes(saltLength)
	if err != nil {
		return "", err
	}
	key := generateKey([]byte(password), salt)

	// Encrypt the secret content
	data, err := encrypt([]byte(input), salt, key)
	if err != nil {
		return "", err
	}

	// Hash the secret content
	hash := hmac.New(sha256.New, key.hmacKey)
	hash.Write(data)
	hashSum := hash.Sum(nil)

	// Encode the secret payload
	return encodeSecret(&secret{data: data, salt: salt, hmac: hashSum}, key, pad)
}

// EncryptFile encrypts the input string and saves it into the file
func EncryptFile(path string, input string, password string) error {
	result, err := Encrypt(input, password, 0)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, []byte(result), DefaultFileMode)
}

// Return true if the input maybe encrypted as an ansible vault
func MaybeEncrypted(input string) bool {
	scanner := bufio.NewScanner(strings.NewReader(input))

	if !scanner.Scan() {
		return false
	}

	return strings.HasPrefix(strings.TrimSpace(scanner.Text()), VaultHeader)
}

// Decrypt decrypts the input string with the vault password
func Decrypt(input string, password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}

	lines := strings.Split(input, "\n")

	// Valid secret must include header and body
	if len(lines) < 2 {
		return "", ErrInvalidFormat
	}

	// Validate the vault file format
	if strings.TrimSpace(lines[0]) != VaultHeader {
		return "", ErrInvalidFormat
	}

	decoded, err := hex.DecodeString(strings.Join(lines[1:], ""))
	if err != nil {
		return "", err
	}

	secret, err := decodeSecret(string(decoded))
	if err != nil {
		return "", err
	}

	key := generateKey([]byte(password), secret.salt)
	if err := checkDigest(secret, key); err != nil {
		return "", err
	}

	result, err := decrypt(secret, key)
	if err != nil {
		return "", err
	}

	return result, nil
}

// DecryptFile decrypts the content of the file with the vault password
func DecryptFile(path string, password string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Decrypt(string(data), password)
}
