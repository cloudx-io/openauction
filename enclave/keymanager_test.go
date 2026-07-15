package main

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/peterldowns/testy/assert"
)

func TestNewKeyManager(t *testing.T) {
	attester := CreateMockEnclave(t)
	km, err := NewKeyManager(attester)
	assert.NoError(t, err)
	assert.NotNil(t, km)

	epoch := km.currentEpoch()
	assert.NotNil(t, epoch)
	assert.NotNil(t, epoch.privateKey)
	assert.NotNil(t, epoch.PublicKey)

	// The current epoch's key attestation is generated up front and cached.
	assert.NotEqual(t, "", string(epoch.cachedAttestation))
	assert.NotNil(t, epoch.cachedAttestationUs)
}

func TestKeyManager_PublicKeyPEM(t *testing.T) {
	attester := CreateMockEnclave(t)
	km, err := NewKeyManager(attester)
	assert.NoError(t, err)

	pemStr, err := km.currentEpoch().publicKeyPEM()
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
	attester := CreateMockEnclave(t)
	km1, _ := NewKeyManager(attester)
	km2, _ := NewKeyManager(attester)
	km3, _ := NewKeyManager(attester)

	// Verify PEM strings are unique
	pem1, _ := km1.currentEpoch().publicKeyPEM()
	pem2, _ := km2.currentEpoch().publicKeyPEM()
	pem3, _ := km3.currentEpoch().publicKeyPEM()

	assert.NotEqual(t, pem1, pem2)
	assert.NotEqual(t, pem1, pem3)
	assert.NotEqual(t, pem2, pem3)
}

func TestKeyManager_EncryptDecryptRoundTrip(t *testing.T) {
	attester := CreateMockEnclave(t)
	km, err := NewKeyManager(attester)
	assert.NoError(t, err)

	plaintext := []byte("test message for encryption")

	// Encrypt with the current epoch's public key
	result, err := EncryptHybridWithHash(plaintext, km.currentEpoch().PublicKey, HashAlgorithmSHA256)
	assert.NoError(t, err)

	// Decrypt by trying live epochs; the current epoch resolves it.
	enc := encryptedPriceFromResult(result)
	decrypted, epoch, err := km.DecryptBid(enc, HashAlgorithmSHA256)
	assert.NoError(t, err)
	assert.NotNil(t, epoch)
	assert.Equal(t, string(plaintext), string(decrypted))
}

// TestKeyManager_RotationRetainsPriorEpoch verifies that after rotation a bid
// sealed to a prior epoch's key still decrypts, and resolves to that prior epoch.
func TestKeyManager_RotationRetainsPriorEpoch(t *testing.T) {
	attester := CreateMockEnclave(t)
	km, err := NewKeyManager(attester)
	assert.NoError(t, err)

	priorEpoch := km.currentEpoch()

	// Seal a payload to the prior epoch's key.
	result, err := EncryptHybridWithHash([]byte(`{"price": 1.23}`), priorEpoch.PublicKey, HashAlgorithmSHA256)
	assert.NoError(t, err)

	// Rotate: mint a new current epoch. The prior epoch is still within
	// retention, so it stays live.
	newEpoch, err := km.addEpoch(attester)
	assert.NoError(t, err)
	// Compare by pointer identity; keyEpoch has unexported fields.
	assert.True(t, priorEpoch != newEpoch)
	assert.True(t, km.currentEpoch() == newEpoch)
	assert.Equal(t, 2, km.epochCount())

	// The bid still decrypts and resolves to the prior epoch.
	enc := encryptedPriceFromResult(result)
	_, resolved, err := km.DecryptBid(enc, HashAlgorithmSHA256)
	assert.NoError(t, err)
	assert.True(t, resolved == priorEpoch)
}

// TestKeyManager_DecryptBid_NoMatchingEpoch verifies that a bid sealed to an
// unrelated key fails to decrypt against all live epochs.
func TestKeyManager_DecryptBid_NoMatchingEpoch(t *testing.T) {
	attester := CreateMockEnclave(t)
	km, err := NewKeyManager(attester)
	assert.NoError(t, err)

	// Encrypt to a key that no epoch holds.
	strangerKey, err := GenerateRSAKeyPair()
	assert.NoError(t, err)
	result, err := EncryptHybridWithHash([]byte(`{"price": 9.99}`), &strangerKey.PublicKey, HashAlgorithmSHA256)
	assert.NoError(t, err)

	enc := encryptedPriceFromResult(result)
	_, _, err = km.DecryptBid(enc, HashAlgorithmSHA256)
	assert.Error(t, err)
}
