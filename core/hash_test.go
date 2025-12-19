package core

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestComputeBidHash(t *testing.T) {
	bidID := "bid_123"
	price := 2.50
	nonce := "test_nonce_456"

	hash := ComputeBidHash(bidID, price, nonce)

	// Verify hash is 64 characters (SHA256 hex encoding)
	if len(hash) != 64 {
		t.Errorf("ComputeBidHash() hash length = %d, want 64", len(hash))
	}

	// Verify hash contains only hex characters
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("ComputeBidHash() contains non-hex character: %c", c)
		}
	}

	// Same inputs should produce same hash (deterministic)
	hash2 := ComputeBidHash(bidID, price, nonce)
	if hash != hash2 {
		t.Errorf("ComputeBidHash() not deterministic")
	}

	// Different inputs should produce different hashes
	hash3 := ComputeBidHash(bidID, price+1, nonce)
	if hash == hash3 {
		t.Errorf("Different inputs should produce different hashes")
	}

	// Verify exact hash calculation
	expectedData := fmt.Sprintf("%s|%.6f|%s", bidID, price, nonce)
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(expectedData)))
	if hash != expectedHash {
		t.Errorf("ComputeBidHash() = %v, want %v", hash, expectedHash)
	}
}

func TestComputeBidHash_PriceFormatting(t *testing.T) {
	// Test that price is formatted to exactly 6 decimal places
	nonce := "test"

	// These should produce the same hash because they're the same to 6 decimal places
	hash1 := ComputeBidHash("bid-1", 2.123456, nonce)
	hash2 := ComputeBidHash("bid-1", 2.1234560, nonce)
	hash3 := ComputeBidHash("bid-1", 2.12345600000, nonce)

	if hash1 != hash2 || hash1 != hash3 {
		t.Errorf("Prices with same 6 decimal places should produce same hash")
	}

	// These should produce different hashes (differ in 6th decimal)
	hash4 := ComputeBidHash("bid-1", 2.123456, nonce)
	hash5 := ComputeBidHash("bid-1", 2.123457, nonce)

	if hash4 == hash5 {
		t.Errorf("Prices with different 6th decimal should produce different hashes")
	}
}

func TestComputeBidHash_DifferentInputs(t *testing.T) {
	nonce := "test-nonce"

	// Different bid IDs should produce different hashes
	hash1 := ComputeBidHash("bid-1", 2.50, nonce)
	hash2 := ComputeBidHash("bid-2", 2.50, nonce)
	if hash1 == hash2 {
		t.Errorf("Different bid IDs should produce different hashes")
	}

	// Different prices should produce different hashes
	hash3 := ComputeBidHash("bid-1", 2.50, nonce)
	hash4 := ComputeBidHash("bid-1", 2.51, nonce)
	if hash3 == hash4 {
		t.Errorf("Different prices should produce different hashes")
	}

	// Different nonces should produce different hashes
	hash5 := ComputeBidHash("bid-1", 2.50, "nonce-1")
	hash6 := ComputeBidHash("bid-1", 2.50, "nonce-2")
	if hash5 == hash6 {
		t.Errorf("Different nonces should produce different hashes")
	}
}

func TestComputeBidHash_EdgeCases(t *testing.T) {
	testCases := []struct {
		name  string
		bidID string
		price float64
		nonce string
	}{
		{"zero price", "bid-1", 0.0, "nonce"},
		{"high price", "bid-1", 999.999999, "nonce"},
		{"many decimals", "bid-2", 1.234567891234, "nonce"},
		{"negative price", "bid-3", -1.50, "nonce"},
		{"empty bid ID", "", 2.50, "nonce"},
		{"empty nonce", "bid-1", 2.50, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash := ComputeBidHash(tc.bidID, tc.price, tc.nonce)

			// Verify the hash is deterministic
			hash2 := ComputeBidHash(tc.bidID, tc.price, tc.nonce)
			if hash != hash2 {
				t.Errorf("Hash not deterministic for bidID=%s, price=%f, nonce=%s",
					tc.bidID, tc.price, tc.nonce)
			}

			// Verify hash format
			if len(hash) != 64 {
				t.Errorf("Hash has wrong length: got %d, want 64", len(hash))
			}

			// Verify hash contains only hex characters
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("Hash contains non-hex character: %c", c)
				}
			}
		})
	}
}

func TestComputeRequestHash(t *testing.T) {
	auctionID := "auction-123"
	roundID := 1
	nonce := "test-nonce"

	hash := ComputeRequestHash(auctionID, roundID, nonce)

	// Verify hash is 64 characters (SHA256 hex encoding)
	if len(hash) != 64 {
		t.Errorf("ComputeRequestHash() hash length = %d, want 64", len(hash))
	}

	// Verify hash contains only hex characters
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("ComputeRequestHash() contains non-hex character: %c", c)
		}
	}

	// Test determinism
	hash2 := ComputeRequestHash(auctionID, roundID, nonce)
	if hash != hash2 {
		t.Errorf("ComputeRequestHash() not deterministic")
	}

	// Test that different inputs produce different hashes
	hash3 := ComputeRequestHash(auctionID, roundID+1, nonce)
	if hash == hash3 {
		t.Errorf("Different round IDs should produce different hashes")
	}

	hash4 := ComputeRequestHash("different-auction", roundID, nonce)
	if hash == hash4 {
		t.Errorf("Different auction IDs should produce different hashes")
	}

	hash5 := ComputeRequestHash(auctionID, roundID, "different-nonce")
	if hash == hash5 {
		t.Errorf("Different nonces should produce different hashes")
	}

	// Verify exact hash calculation
	expectedData := fmt.Sprintf("%s|%d|%s", auctionID, roundID, nonce)
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(expectedData)))
	if hash != expectedHash {
		t.Errorf("ComputeRequestHash() = %v, want %v", hash, expectedHash)
	}
}

func TestComputeAdjustmentFactorsHash(t *testing.T) {
	nonce := "test-nonce"
	factors := map[string]float64{
		"meta":     1.0,
		"appnexus": 0.95,
		"pubmatic": 1.15,
	}

	hash := ComputeAdjustmentFactorsHash(factors, nonce)

	// Verify hash is 64 characters (SHA256 hex encoding)
	if len(hash) != 64 {
		t.Errorf("ComputeAdjustmentFactorsHash() hash length = %d, want 64", len(hash))
	}

	// Verify hash contains only hex characters
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("ComputeAdjustmentFactorsHash() contains non-hex character: %c", c)
		}
	}

	// Test determinism
	hash2 := ComputeAdjustmentFactorsHash(factors, nonce)
	if hash != hash2 {
		t.Errorf("ComputeAdjustmentFactorsHash() not deterministic")
	}

	// Test that different nonces produce different hashes
	hash3 := ComputeAdjustmentFactorsHash(factors, "different-nonce")
	if hash == hash3 {
		t.Errorf("Different nonces should produce different hashes")
	}

	// Test that different factors produce different hashes
	differentFactors := map[string]float64{
		"meta":     1.0,
		"appnexus": 0.96, // Different value
		"pubmatic": 1.15,
	}
	hash4 := ComputeAdjustmentFactorsHash(differentFactors, nonce)
	if hash == hash4 {
		t.Errorf("Different adjustment factors should produce different hashes")
	}
}

func TestComputeAdjustmentFactorsHash_Sorting(t *testing.T) {
	nonce := "test"

	// These should produce the same hash because they're the same factors, just in different map iteration order
	factors1 := map[string]float64{"meta": 1.0, "appnexus": 0.95}
	factors2 := map[string]float64{"appnexus": 0.95, "meta": 1.0}

	hash1 := ComputeAdjustmentFactorsHash(factors1, nonce)
	hash2 := ComputeAdjustmentFactorsHash(factors2, nonce)

	if hash1 != hash2 {
		t.Errorf("Same factors in different order should produce same hash due to sorting")
	}

	// Verify exact calculation with sorted keys
	expectedData := "test|appnexus:0.950000|meta:1.000000"
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(expectedData)))
	if hash1 != expectedHash {
		t.Errorf("ComputeAdjustmentFactorsHash() = %v, want %v", hash1, expectedHash)
	}
}

func TestComputeAdjustmentFactorsHash_EmptyMap(t *testing.T) {
	nonce := "test-nonce"
	emptyFactors := map[string]float64{}

	hash := ComputeAdjustmentFactorsHash(emptyFactors, nonce)

	// Verify hash is 64 characters
	if len(hash) != 64 {
		t.Errorf("ComputeAdjustmentFactorsHash() hash length = %d, want 64", len(hash))
	}

	// Empty map should produce hash of just the nonce
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(nonce)))
	if hash != expectedHash {
		t.Errorf("Empty map should hash just the nonce")
	}
}

func TestComputeBidHashEncrypted(t *testing.T) {
	bidID := "bid-123"
	encryptedPayload := "fiiphOfYHw70adwG15VdAR5lHdez+wL4aYKFuYXJYYD0LpvmF9pZ+hIPdGzzpIUcz/1ZZ/5E/1Rg233u1DR4x0gKA49pa/AVi2aAGpT5qttV1m8N4k4="
	nonce := "test-nonce"

	hash := ComputeBidHashEncrypted(bidID, encryptedPayload, nonce)

	// Verify hash is 64 characters (SHA256 hex encoding)
	if len(hash) != 64 {
		t.Errorf("ComputeBidHashEncrypted() hash length = %d, want 64", len(hash))
	}

	// Verify hash contains only hex characters
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("ComputeBidHashEncrypted() contains non-hex character: %c", c)
		}
	}

	// Test determinism
	hash2 := ComputeBidHashEncrypted(bidID, encryptedPayload, nonce)
	if hash != hash2 {
		t.Errorf("ComputeBidHashEncrypted() not deterministic")
	}

	// Test that different encrypted payloads produce different hashes
	hash3 := ComputeBidHashEncrypted(bidID, "different_payload", nonce)
	if hash == hash3 {
		t.Errorf("Different encrypted payloads should produce different hashes")
	}

	// Verify exact hash calculation
	expectedData := fmt.Sprintf("%s|%s|%s", bidID, encryptedPayload, nonce)
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(expectedData)))
	if hash != expectedHash {
		t.Errorf("ComputeBidHashEncrypted() = %v, want %v", hash, expectedHash)
	}
}

func TestComputeBidHashEncrypted_VsUnencrypted(t *testing.T) {
	bidID := "bid-123"
	price := 99.99
	encryptedPayload := "some_encrypted_data"
	nonce := "test-nonce"

	// Encrypted and unencrypted hashes should be different
	hashUnencrypted := ComputeBidHash(bidID, price, nonce)
	hashEncrypted := ComputeBidHashEncrypted(bidID, encryptedPayload, nonce)

	if hashUnencrypted == hashEncrypted {
		t.Errorf("Encrypted and unencrypted bid hashes should be different")
	}
}
