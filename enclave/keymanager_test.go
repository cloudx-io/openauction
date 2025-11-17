package main

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/peterldowns/testy/assert"
)

func TestNewKeyManager(t *testing.T) {
	km, err := NewKeyManager()
	assert.NoError(t, err)
	assert.NotNil(t, km)
	assert.NotNil(t, km.privateKey)
	assert.NotNil(t, km.PublicKey)
}

func TestKeyManager_PublicKeyPEM(t *testing.T) {
	km, err := NewKeyManager()
	assert.NoError(t, err)

	pemStr, err := km.PublicKeyPEM()
	assert.NoError(t, err)
	assert.NotEqual(t, pemStr, "")

	// Verify PEM format
	assert.True(t, strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(pemStr), "-----END PUBLIC KEY-----"))

	// Verify we can parse it back
	block, _ := pem.Decode([]byte(pemStr))
	assert.NotNil(t, block)
	assert.Equal(t, "PUBLIC KEY", block.Type)

	// Verify we can parse the public key
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err)
}

func TestKeyManager_UniqueKeys(t *testing.T) {
	km1, _ := NewKeyManager()
	km2, _ := NewKeyManager()
	km3, _ := NewKeyManager()

	// Verify PEM strings are unique
	pem1, _ := km1.PublicKeyPEM()
	pem2, _ := km2.PublicKeyPEM()
	pem3, _ := km3.PublicKeyPEM()

	assert.NotEqual(t, pem1, pem2)
	assert.NotEqual(t, pem1, pem3)
	assert.NotEqual(t, pem2, pem3)
}

func TestKeyManager_EncryptDecryptRoundTrip(t *testing.T) {
	km, err := NewKeyManager()
	assert.NoError(t, err)

	plaintext := []byte("test message for encryption")

	// Encrypt with public key
	result, err := EncryptHybridWithHash(plaintext, km.PublicKey, HashAlgorithmSHA256)
	assert.NoError(t, err)

	// Decrypt with private key
	decrypted, err := DecryptHybrid(result.EncryptedAESKey, result.EncryptedPayload, result.Nonce, km.privateKey, HashAlgorithmSHA256)
	assert.NoError(t, err)
	assert.Equal(t, string(plaintext), string(decrypted))
}
