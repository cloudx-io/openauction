package main

import (
	"encoding/base64"
	"testing"

	"github.com/peterldowns/testy/assert"
	"github.com/peterldowns/testy/check"

	"github.com/cloudx-io/openauction/enclaveapi"
)

func encPrice(aesKey, payload, nonce []byte) *enclaveapi.EncryptedBidPrice {
	return &enclaveapi.EncryptedBidPrice{
		AESKeyEncrypted:  base64.StdEncoding.EncodeToString(aesKey),
		EncryptedPayload: base64.StdEncoding.EncodeToString(payload),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
	}
}

func TestCiphertextFingerprint_Deterministic(t *testing.T) {
	enc := encPrice([]byte("aeskey"), []byte("payload"), []byte("nonce123"))

	fp1, err := ciphertextFingerprint(enc)
	assert.NoError(t, err)
	fp2, err := ciphertextFingerprint(enc)
	assert.NoError(t, err)

	check.Equal(t, fp1, fp2)
}

func TestCiphertextFingerprint_OverDecodedBytes(t *testing.T) {
	aesKey := []byte("aeskey-bytes")
	payload := []byte("payload-bytes")
	nonce := []byte("nonce-bytes!")

	original := encPrice(aesKey, payload, nonce)

	// Re-encode via a decode/re-encode round-trip (the standard-base64 form the
	// enclave accepts). The fingerprint is over the decoded bytes, so it is
	// identical regardless of which string object carried those bytes.
	roundTripped := &enclaveapi.EncryptedBidPrice{
		AESKeyEncrypted:  reencodeStd(t, original.AESKeyEncrypted),
		EncryptedPayload: reencodeStd(t, original.EncryptedPayload),
		Nonce:            reencodeStd(t, original.Nonce),
	}

	fpOriginal, err := ciphertextFingerprint(original)
	assert.NoError(t, err)
	fpRoundTripped, err := ciphertextFingerprint(roundTripped)
	assert.NoError(t, err)

	check.Equal(t, fpOriginal, fpRoundTripped)
}

// reencodeStd decodes a standard-base64 string and re-encodes it as standard
// base64, producing a value that decodes to identical bytes. Test-only helper.
func reencodeStd(t *testing.T, std string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(std)
	assert.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestCiphertextFingerprint_DomainSeparation(t *testing.T) {
	// Same concatenation ("ab"+"c" vs "a"+"bc") must not collide because each
	// field is length-prefixed.
	encA := encPrice([]byte("ab"), []byte("c"), []byte("nonce"))
	encB := encPrice([]byte("a"), []byte("bc"), []byte("nonce"))

	fpA, err := ciphertextFingerprint(encA)
	assert.NoError(t, err)
	fpB, err := ciphertextFingerprint(encB)
	assert.NoError(t, err)

	check.NotEqual(t, fpA, fpB)
}

func TestCiphertextFingerprint_DifferentFieldsDiffer(t *testing.T) {
	base := encPrice([]byte("aeskey"), []byte("payload"), []byte("nonce123"))
	diffKey := encPrice([]byte("aeskeyX"), []byte("payload"), []byte("nonce123"))
	diffPayload := encPrice([]byte("aeskey"), []byte("payloadX"), []byte("nonce123"))
	diffNonce := encPrice([]byte("aeskey"), []byte("payload"), []byte("nonce124"))

	fpBase, err := ciphertextFingerprint(base)
	assert.NoError(t, err)
	fpKey, err := ciphertextFingerprint(diffKey)
	assert.NoError(t, err)
	fpPayload, err := ciphertextFingerprint(diffPayload)
	assert.NoError(t, err)
	fpNonce, err := ciphertextFingerprint(diffNonce)
	assert.NoError(t, err)

	check.NotEqual(t, fpBase, fpKey)
	check.NotEqual(t, fpBase, fpPayload)
	check.NotEqual(t, fpBase, fpNonce)
}

func TestCiphertextFingerprint_InvalidBase64(t *testing.T) {
	enc := &enclaveapi.EncryptedBidPrice{
		AESKeyEncrypted:  "not valid base64 !!!",
		EncryptedPayload: "dGVzdA==",
		Nonce:            "dGVzdA==",
	}
	_, err := ciphertextFingerprint(enc)
	check.Error(t, err)
}

func TestCiphertextDedup_RecordAndCheckDuplicate(t *testing.T) {
	var dedup ciphertextDedup
	enc := encPrice([]byte("aeskey"), []byte("payload"), []byte("nonce123"))

	fp, err := ciphertextFingerprint(enc)
	assert.NoError(t, err)

	// First observation is not a duplicate; subsequent ones are.
	check.False(t, dedup.recordAndCheckDuplicate(fp))
	check.True(t, dedup.recordAndCheckDuplicate(fp))
	check.True(t, dedup.recordAndCheckDuplicate(fp))
}

func TestCiphertextDedup_IndependentSetsPerEpoch(t *testing.T) {
	var dedupA ciphertextDedup
	var dedupB ciphertextDedup
	enc := encPrice([]byte("aeskey"), []byte("payload"), []byte("nonce123"))

	fp, err := ciphertextFingerprint(enc)
	assert.NoError(t, err)

	// Recording in one set does not affect another (per-epoch isolation).
	check.False(t, dedupA.recordAndCheckDuplicate(fp))
	check.False(t, dedupB.recordAndCheckDuplicate(fp))
	check.True(t, dedupA.recordAndCheckDuplicate(fp))
	check.True(t, dedupB.recordAndCheckDuplicate(fp))
}
