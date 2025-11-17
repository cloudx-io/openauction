package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
)

// HybridEncryptionResult contains the results of hybrid encryption
type HybridEncryptionResult struct {
	EncryptedAESKey  string
	EncryptedPayload string
	Nonce            string
}

// EncryptHybridWithHash encrypts data using hybrid RSA-OAEP + AES-256-GCM encryption
// with a specified hash algorithm for RSA-OAEP
// This is for testing purposes only - it simulates what bidders will do in production
// Returns HybridEncryptionResult with base64-encoded values
func EncryptHybridWithHash(plaintext []byte, publicKey *rsa.PublicKey, hashAlg HashAlgorithm) (*HybridEncryptionResult, error) {
	// Create the hash implementation for the selected algorithm
	hasher, err := newHash(hashAlg)
	if err != nil {
		return nil, err
	}

	// Generate random AES-256 key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt plaintext with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonceBytes := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := aesgcm.Seal(nil, nonceBytes, plaintext, nil)

	// Encrypt AES key with RSA-OAEP using the selected hash algorithm
	encryptedAESKeyBytes, err := rsa.EncryptOAEP(hasher, rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Return base64-encoded values
	return &HybridEncryptionResult{
		EncryptedAESKey:  base64.StdEncoding.EncodeToString(encryptedAESKeyBytes),
		EncryptedPayload: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonceBytes),
	}, nil
}
