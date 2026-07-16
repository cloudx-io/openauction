package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/cloudx-io/openauction/enclaveapi"
)

// ciphertextDedup records the ciphertext fingerprints already seen within a
// single key epoch. It is owned by that epoch (see keyEpoch.dedup) and is
// released when the epoch ages out, so its memory is bounded by how many
// distinct bids can be sealed to one key during the retention window and it
// needs no clock-based expiry of its own.
//
// A sync.Map is used so that concurrent auctions decrypting bids under the same
// epoch contend per-fingerprint rather than on a single lock.
type ciphertextDedup struct {
	seen sync.Map // map[[32]byte]struct{} with lock-free reads
}

// recordAndCheckDuplicate records a ciphertext fingerprint and reports whether
// it had already been seen for this epoch. It returns true when the fingerprint
// is a duplicate (the bid is a byte-identical replay) and false when it is the
// first time the fingerprint has been observed.
//
// The check-and-record is atomic: LoadOrStore ensures that if two auctions
// submit the same ciphertext concurrently under the same epoch, exactly one sees
// it as new and the other sees it as a duplicate.
func (d *ciphertextDedup) recordAndCheckDuplicate(fingerprint [32]byte) bool {
	_, loaded := d.seen.LoadOrStore(fingerprint, struct{}{})
	return loaded
}

// ciphertextFingerprint computes a SHA-256 fingerprint over the encrypted bid's
// bytes: the RSA-encrypted AES key, the AES-GCM ciphertext, and the GCM nonce.
//
// The fingerprint is taken over the base64-DECODED bytes so that a bid which is
// merely re-encoded (e.g. different base64 padding or alphabet) but carries the
// same ciphertext bytes still collides and is caught as a replay. Each field is
// length-prefixed with a fixed-width big-endian length before hashing so that
// the boundaries between fields are unambiguous and no concatenation of one
// field's bytes into the next can forge a different-but-equal fingerprint
// (domain separation).
//
// Authenticated encryption (the AES-GCM tag) and RSA-OAEP make any
// different-but-decryptable ciphertext impossible to forge without the
// plaintext, so a byte-identical resubmission is the only replayable artifact —
// which this fingerprint detects.
func ciphertextFingerprint(enc *enclaveapi.EncryptedBidPrice) ([32]byte, error) {
	aesKey, err := base64.StdEncoding.DecodeString(enc.AESKeyEncrypted)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decode encrypted AES key: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(enc.EncryptedPayload)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decode encrypted payload: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decode nonce: %w", err)
	}

	h := sha256.New()
	writeLengthPrefixed(h, aesKey)
	writeLengthPrefixed(h, payload)
	writeLengthPrefixed(h, nonce)

	var fingerprint [32]byte
	copy(fingerprint[:], h.Sum(nil))
	return fingerprint, nil
}

// writeLengthPrefixed writes an 8-byte big-endian length followed by the field
// bytes, giving each field an unambiguous boundary in the hash input.
func writeLengthPrefixed(h io.Writer, field []byte) {
	var lengthPrefix [8]byte
	binary.BigEndian.PutUint64(lengthPrefix[:], uint64(len(field)))
	// hash.Hash.Write never returns an error.
	_, _ = h.Write(lengthPrefix[:])
	_, _ = h.Write(field)
}
