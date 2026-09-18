package db

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

const (
	EncryptionPrefix   = "enc:v1:"
	DefaultFallbackKey = "msnp_server_default_master_salt_key_2026"
)

// IsEncrypted checks if the value is an encrypted password token.
func IsEncrypted(val string) bool {
	return strings.HasPrefix(val, EncryptionPrefix)
}

// deriveKeys derives signing key (16 bytes) and encryption key (16 bytes) from secretKey via SHA-256.
func deriveKeys(secretKey string) (signingKey, encryptionKey []byte) {
	if secretKey == "" {
		secretKey = DefaultFallbackKey
	}
	hash := sha256.Sum256([]byte(secretKey))
	return hash[:16], hash[16:]
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid block size in padding")
	}
	padLen := int(data[length-1])
	if padLen == 0 || padLen > blockSize || padLen > length {
		return nil, errors.New("invalid padding length")
	}
	for i := length - padLen; i < length; i++ {
		if data[i] != byte(padLen) {
			return nil, errors.New("invalid padding byte")
		}
	}
	return data[:length-padLen], nil
}

// EncryptPassword encrypts a plaintext password using Fernet-compatible AES-128-CBC + HMAC-SHA256.
// Output format: enc:v1:<base64url_token>
func EncryptPassword(plaintext, secretKey string) string {
	if plaintext == "" {
		return ""
	}
	if IsEncrypted(plaintext) {
		return plaintext
	}

	signingKey, encryptionKey := deriveKeys(secretKey)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return plaintext
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return plaintext
	}

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Build Fernet token payload: version (0x80) + timestamp (8 bytes) + iv (16 bytes) + ciphertext
	payload := make([]byte, 1+8+aes.BlockSize+len(ciphertext))
	payload[0] = 0x80
	binary.BigEndian.PutUint64(payload[1:9], uint64(time.Now().Unix()))
	copy(payload[9:25], iv)
	copy(payload[25:], ciphertext)

	// HMAC-SHA256 over payload
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(payload)
	tag := mac.Sum(nil)

	fullToken := append(payload, tag...)
	tokenStr := base64.URLEncoding.EncodeToString(fullToken)
	return EncryptionPrefix + tokenStr
}

// DecryptPassword decrypts a password token. If not encrypted, returns as-is.
// Fully interoperable with Python's cryptography.fernet tokens.
func DecryptPassword(ciphertext, secretKey string) string {
	if ciphertext == "" {
		return ""
	}
	if !IsEncrypted(ciphertext) {
		return ciphertext
	}

	tokenStr := strings.TrimSpace(strings.TrimPrefix(ciphertext, EncryptionPrefix))
	raw, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		return ciphertext
	}

	// Fernet minimum length: 1 (version) + 8 (timestamp) + 16 (IV) + 16 (min ciphertext) + 32 (HMAC) = 73 bytes
	if len(raw) < 73 || raw[0] != 0x80 {
		return ciphertext
	}

	signingKey, encryptionKey := deriveKeys(secretKey)

	dataToVerify := raw[:len(raw)-32]
	expectedTag := raw[len(raw)-32:]

	mac := hmac.New(sha256.New, signingKey)
	mac.Write(dataToVerify)
	computedTag := mac.Sum(nil)

	if !hmac.Equal(expectedTag, computedTag) {
		return ciphertext
	}

	iv := raw[9:25]
	cipherBytes := raw[25 : len(raw)-32]

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return ciphertext
	}

	if len(cipherBytes)%aes.BlockSize != 0 {
		return ciphertext
	}

	decryptedPadded := make([]byte, len(cipherBytes))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decryptedPadded, cipherBytes)

	unpadded, err := pkcs7Unpad(decryptedPadded, aes.BlockSize)
	if err != nil {
		return ciphertext
	}

	return string(unpadded)
}
