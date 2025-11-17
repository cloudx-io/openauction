package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
)

// HashAlgorithm specifies which hash function to use in RSA-OAEP decryption
type HashAlgorithm string

const (
	// HashAlgorithmSHA256 uses SHA-256 (recommended, default)
	HashAlgorithmSHA256 HashAlgorithm = "SHA-256"
	// HashAlgorithmSHA1 uses SHA-1 (legacy support for client compatibility)
	HashAlgorithmSHA1 HashAlgorithm = "SHA-1"
)

// GenerateRSAKeyPair generates a new RSA-2048 key pair using crypto/rand
// In a TEE environment, crypto/rand uses NSM-enhanced entropy
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	return privateKey, nil
}

// newHash creates the appropriate implementation of hash.Hash,
// or returns an error if the algorithm is unsupported.
func newHash(hashAlg HashAlgorithm) (hash.Hash, error) {
	switch hashAlg {
	case HashAlgorithmSHA256:
		return sha256.New(), nil
	case HashAlgorithmSHA1:
		return sha1.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlg)
	}
}

// DecryptHybrid decrypts data encrypted with hybrid RSA-OAEP + AES-256-GCM encryption
// Parameters:
//   - encryptedAESKey: RSA-encrypted AES key (base64-encoded)
//   - encryptedPayload: AES-GCM encrypted data (base64-encoded)
//   - nonce: GCM nonce (base64-encoded)
//   - privateKey: RSA private key for decrypting the AES key
//   - hashAlg: Hash algorithm for RSA-OAEP (HashAlgorithmSHA256 or HashAlgorithmSHA1)
//
// # Returns the decrypted plaintext bytes
//
// Note: SHA-1 support (HashAlgorithmSHA1) is provided for legacy client compatibility.
// SHA-256 (HashAlgorithmSHA256) is strongly recommended for new implementations.
func DecryptHybrid(encryptedAESKey, encryptedPayload, nonceB64 string, privateKey *rsa.PrivateKey, hashAlg HashAlgorithm) ([]byte, error) {
	// Decode base64 inputs
	encryptedAESKeyBytes, err := base64.StdEncoding.DecodeString(encryptedAESKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted AES key: %w", err)
	}

	encryptedPayloadBytes, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted payload: %w", err)
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Step 1: Create the hash implementation for the selected algorithm
	hasher, err := newHash(hashAlg)
	if err != nil {
		return nil, err
	}

	// Step 2: Decrypt AES key using RSA-OAEP with the selected hash algorithm
	aesKey, err := rsa.DecryptOAEP(hasher, rand.Reader, privateKey, encryptedAESKeyBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	// Validate AES key length (should be 32 bytes for AES-256)
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("invalid AES key length: expected 32 bytes, got %d", len(aesKey))
	}

	// Step 3: Decrypt payload using AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Validate nonce length
	if len(nonceBytes) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: expected %d bytes, got %d", aesgcm.NonceSize(), len(nonceBytes))
	}

	// Decrypt and authenticate
	plaintext, err := aesgcm.Open(nil, nonceBytes, encryptedPayloadBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	return plaintext, nil
}
