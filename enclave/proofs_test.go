package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/peterldowns/testy/check"

	"github.com/cloudx-io/openauction/core"
	"github.com/cloudx-io/openauction/enclaveapi"
)

func checkBidHashPattern(t *testing.T, test string) {
	t.Helper()
	validBidHash := `^[a-f0-9]+$`
	matched, err := regexp.MatchString(validBidHash, test)
	check.Nil(t, err)
	check.True(t, matched)
}

func TestGenerateBidHash(t *testing.T) {
	bidID := "bid_123"
	price := 2.50
	nonce := "test_nonce_456"

	hash := generateBidHash(bidID, price, nonce)

	check.Equal(t, 64, len(hash))
	checkBidHashPattern(t, hash)

	// Same inputs should produce same hash
	hash2 := generateBidHash(bidID, price, nonce)
	check.Equal(t, hash2, hash)

	// Different inputs should produce different hashes
	hash3 := generateBidHash(bidID, price+1, nonce)
	check.NotEqual(t, hash, hash3)

	expectedData := fmt.Sprintf("%s|%.6f|%s", bidID, price, nonce)
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(expectedData)))
	check.Equal(t, expectedHash, hash)
}

func TestGenerateSecureRandomBytes(t *testing.T) {
	// Test basic functionality
	bytes1, err1 := generateSecureRandomBytes(32)
	bytes2, err2 := generateSecureRandomBytes(32)

	check.NoError(t, err1)
	check.NoError(t, err2)
	check.Equal(t, 32, len(bytes1))
	check.Equal(t, 32, len(bytes2))

	// Randomness: should be different
	check.NotEqual(t, bytes1, bytes2)

	// Test different lengths
	bytes8, err3 := generateSecureRandomBytes(8)
	check.NoError(t, err3)
	check.Equal(t, 8, len(bytes8))
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err1 := generateNonce()
	check.NoError(t, err1)

	nonce2, err2 := generateNonce()
	check.NoError(t, err2)

	// Should be 32 bytes = 64 hex characters
	check.Equal(t, 64, len(nonce1))
	check.Equal(t, 64, len(nonce2))

	// Should be valid hex
	checkBidHashPattern(t, nonce1)
	checkBidHashPattern(t, nonce2)

	// Should be different (cryptographically random)
	check.NotEqual(t, nonce1, nonce2)
}

func TestCalculateRequestHash(t *testing.T) {
	req := enclaveapi.EnclaveAuctionRequest{
		AuctionID: "auction_123",
		RoundID:   2,
	}
	nonce := "test_nonce"

	hash := calculateRequestHash(req, nonce)

	check.Equal(t, 64, len(hash))
	checkBidHashPattern(t, hash)

	hash2 := calculateRequestHash(req, nonce)
	check.Equal(t, hash2, hash)
}

func TestCalculateAdjustmentFactorsHash(t *testing.T) {
	adjustmentFactors := map[string]float64{
		"bidder_a": 1.0,
		"bidder_b": 0.95,
	}
	nonce := "test_nonce"

	hash := calculateAdjustmentFactorsHash(adjustmentFactors, nonce)

	check.Equal(t, 64, len(hash))
	checkBidHashPattern(t, hash)

	hash2 := calculateAdjustmentFactorsHash(adjustmentFactors, nonce)
	check.Equal(t, hash2, hash)

	emptyHash := calculateAdjustmentFactorsHash(map[string]float64{}, nonce)
	check.Equal(t, 64, len(emptyHash))
	check.NotEqual(t, hash, emptyHash)
}

func TestGenerateAttestation(t *testing.T) {
	req := enclaveapi.EnclaveAuctionRequest{
		AuctionID: "test_auction",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.50}},
		},
	}

	winner := &core.CoreBid{ID: "winning_bid", Bidder: "winner_bidder", Price: 3.0}
	runnerUp := &core.CoreBid{ID: "runner_up_bid", Bidder: "runner_up_bidder", Price: 2.5}

	// Test with nil enclave handle (error case)
	bidHashes := []string{"hash1", "hash2"}
	attestationDoc, err := GenerateAttestation(nil, req, bidHashes, "test_request_hash", "test_adj_hash",
		"test_bid_nonce", "test_req_nonce", "test_adj_nonce", winner, runnerUp)

	// Should fail with nil enclave handle
	check.Error(t, err)
	check.Nil(t, attestationDoc)
	check.True(t, strings.Contains(err.Error(), "enclave attester is nil"))
}

func TestGenerateAttestationWithMock(t *testing.T) {
	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_mock",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.50, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{"bidder_a": 1.0},
	}

	winner := &core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.50}

	// Create a mock enclave that returns properly formatted CBOR
	mockEnclave := CreateMockEnclave(t)

	// Generate bid hash
	bidHashNonce := "test_bid_nonce"
	bidHash := generateBidHash("bid1", 2.50, bidHashNonce)

	// Test successful attestation generation with mock
	attestationDoc, err := GenerateAttestation(mockEnclave, req, []string{bidHash}, "test_request_hash", "test_adj_hash",
		bidHashNonce, "test_req_nonce", "test_adj_nonce", winner, nil)

	// Should succeed with mock enclave
	check.NoError(t, err)
	check.NotNil(t, attestationDoc)
	check.Equal(t, "test-enclave-12345", attestationDoc.ModuleID)
	check.Equal(t, "SHA384", attestationDoc.DigestAlgorithm)
	check.NotNil(t, attestationDoc.UserData)
	check.Equal(t, attestationDoc.UserData.AuctionID, req.AuctionID)
	// Verify winner fields
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Equal(t, winner.ID, attestationDoc.UserData.Winner.ID)
	check.Equal(t, winner.Price, attestationDoc.UserData.Winner.Price)

	// Verify all PCRs are extracted with realistic production values
	check.NotNil(t, attestationDoc.PCRs)
	check.NotEqual(t, "", attestationDoc.PCRs.ImageFileHash)
	check.NotEqual(t, "", attestationDoc.PCRs.KernelHash)
	check.NotEqual(t, "", attestationDoc.PCRs.ApplicationHash)
	check.NotEqual(t, "", attestationDoc.PCRs.IAMRoleHash)
	check.NotEqual(t, "", attestationDoc.PCRs.InstanceIDHash)
}

func TestGenerateAttestationWithEncryptedBids(t *testing.T) {
	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_encrypted_bids",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			// Encrypted bid with EncryptedPrice populated
			{
				CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 0.0, Currency: "USD"}, // Price will be encrypted
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  "dGVzdF9lbmNyeXB0ZWRfYWVzX2tleV9kYXRh",     // Mock base64 RSA-encrypted AES key
					EncryptedPayload: "dGVzdF9lbmNyeXB0ZWRfcHJpY2VfcGF5bG9hZA==", // Mock base64 AES-GCM encrypted {"price": 3.75}
					Nonce:            "dGVzdF9ub25jZV8xMmJ5dGVz",                 // Mock base64 12-byte GCM nonce
				},
			},
			// Another encrypted bid
			{
				CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder_c", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  "YW5vdGhlcl90ZXN0X2VuY3J5cHRlZF9rZXk=",
					EncryptedPayload: "YW5vdGhlcl9lbmNyeXB0ZWRfcGF5bG9hZA==",
					Nonce:            "YW5vdGhlcl9ub25jZV8xMmI=",
				},
			},
		},
		AdjustmentFactors: map[string]float64{
			"bidder_b": 0.95,
			"bidder_c": 1.1,
		},
	}

	// These represent the decrypted bid prices (what should be used for merkle tree)
	winner := &core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 3.75, Currency: "USD"}
	runnerUp := &core.CoreBid{ID: "bid3", Bidder: "bidder_c", Price: 3.50, Currency: "USD"}

	// Create a mock enclave that returns properly formatted CBOR
	mockEnclave := CreateMockEnclave(t)

	// Generate nonce for bid hashing
	bidHashNonce := "test_bid_nonce_for_encrypted_bids"

	// Calculate bid hashes from decrypted prices
	hash2 := generateBidHash(winner.ID, winner.Price, bidHashNonce)     // Decrypted price
	hash3 := generateBidHash(runnerUp.ID, runnerUp.Price, bidHashNonce) // Decrypted price

	// Build list of bid hashes
	bidHashes := []string{hash2, hash3}

	// Test successful attestation generation with encrypted bids
	attestationDoc, err := GenerateAttestation(mockEnclave, req, bidHashes, "test_request_hash", "test_adj_hash",
		bidHashNonce, "test_req_nonce", "test_adj_nonce", winner, runnerUp)

	// Should succeed with mock enclave
	check.NoError(t, err)
	check.NotNil(t, attestationDoc)
	check.Equal(t, "test-enclave-12345", attestationDoc.ModuleID)
	check.Equal(t, "SHA384", attestationDoc.DigestAlgorithm)

	// Verify user data structure for encrypted bid scenario
	check.NotNil(t, attestationDoc.UserData)
	check.Equal(t, attestationDoc.UserData.AuctionID, req.AuctionID)
	check.Equal(t, attestationDoc.UserData.RoundID, req.RoundID)
	check.NotEqual(t, "", attestationDoc.UserData.RequestHash)
	check.NotEqual(t, "", attestationDoc.UserData.AdjustmentFactorsHash)

	// Verify winner and runner-up from decrypted encrypted bids
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.NotNil(t, attestationDoc.UserData.RunnerUp)
	check.Equal(t, winner.ID, attestationDoc.UserData.Winner.ID)
	check.Equal(t, 3.75, attestationDoc.UserData.Winner.Price)
	check.Equal(t, runnerUp.ID, attestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 3.50, attestationDoc.UserData.RunnerUp.Price)

	// Verify bid hashes are computed from decrypted prices
	check.Equal(t, 2, len(attestationDoc.UserData.BidHashes))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, hash2))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, hash3))

	// Verify all PCRs are extracted
	check.NotNil(t, attestationDoc.PCRs)
	check.NotEqual(t, "", attestationDoc.PCRs.ImageFileHash)
	check.NotEqual(t, "", attestationDoc.PCRs.KernelHash)
	check.NotEqual(t, "", attestationDoc.PCRs.ApplicationHash)
	check.NotEqual(t, "", attestationDoc.PCRs.IAMRoleHash)
	check.NotEqual(t, "", attestationDoc.PCRs.InstanceIDHash)
}

func TestGenerateKeyAttestation(t *testing.T) {
	// Test with nil enclave handle (error case)
	privateKey, err := GenerateRSAKeyPair()
	check.NoError(t, err)

	testToken := "550e8400-e29b-41d4-a716-446655440000"
	keyAttestation, err := GenerateKeyAttestation(nil, &privateKey.PublicKey, testToken)

	// Should fail with nil enclave handle
	check.Error(t, err)
	check.Nil(t, keyAttestation)
	check.True(t, strings.Contains(err.Error(), "enclave attester is nil"))
}

func TestGenerateKeyAttestationWithMock(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := GenerateRSAKeyPair()
	check.NoError(t, err)

	// Create a mock enclave that returns properly formatted CBOR
	mockEnclave := CreateMockEnclave(t)

	// Generate a test token
	testToken := "550e8400-e29b-41d4-a716-446655440000"

	// Test successful key attestation generation with mock
	keyAttestation, err := GenerateKeyAttestation(mockEnclave, &privateKey.PublicKey, testToken)

	// Should succeed with mock enclave
	check.NoError(t, err)
	check.NotNil(t, keyAttestation)
	check.Equal(t, "test-enclave-12345", keyAttestation.ModuleID)
	check.Equal(t, "SHA384", keyAttestation.DigestAlgorithm)

	// Verify user data structure
	check.NotNil(t, keyAttestation.UserData)
	check.Equal(t, "RSA-2048", keyAttestation.UserData.KeyAlgorithm)
	check.NotEqual(t, "", keyAttestation.UserData.PublicKey)
	check.Equal(t, testToken, keyAttestation.UserData.AuctionToken)

	// Verify public key is in PEM format
	check.True(t, strings.Contains(keyAttestation.UserData.PublicKey, "-----BEGIN PUBLIC KEY-----"))
	check.True(t, strings.Contains(keyAttestation.UserData.PublicKey, "-----END PUBLIC KEY-----"))

	// Verify all PCRs are extracted with realistic production values
	check.NotNil(t, keyAttestation.PCRs)
	check.NotEqual(t, "", keyAttestation.PCRs.ImageFileHash)
	check.NotEqual(t, "", keyAttestation.PCRs.KernelHash)
	check.NotEqual(t, "", keyAttestation.PCRs.ApplicationHash)
	check.NotEqual(t, "", keyAttestation.PCRs.IAMRoleHash)
	check.NotEqual(t, "", keyAttestation.PCRs.InstanceIDHash)

	// Verify attestation metadata
	check.NotEqual(t, "", keyAttestation.Certificate)
	check.NotEqual(t, []string{}, keyAttestation.CABundle)
	check.NotEqual(t, "", keyAttestation.PublicKey)
	check.NotEqual(t, "", keyAttestation.Nonce)
}

func TestHandleKeyRequest(t *testing.T) {
	// Test with nil attester (error case)
	keyManager, err := NewKeyManager()
	check.NoError(t, err)

	tokenManager := NewTokenManager()

	keyResponse, err := HandleKeyRequest(nil, keyManager, tokenManager)

	// Should fail with nil attester
	check.Error(t, err)
	check.Nil(t, keyResponse)
	check.True(t, strings.Contains(err.Error(), "failed to generate key attestation"))
}

func TestHandleKeyRequestWithMock(t *testing.T) {
	// Create a real key manager
	keyManager, err := NewKeyManager()
	check.NoError(t, err)

	tokenManager := NewTokenManager()

	// Create a mock enclave that returns properly formatted CBOR
	mockEnclave := CreateMockEnclave(t)

	// Test successful key request handling with mock
	keyResponse, err := HandleKeyRequest(mockEnclave, keyManager, tokenManager)

	// Should succeed
	check.NoError(t, err)
	check.NotNil(t, keyResponse)

	// Verify response structure
	check.Equal(t, "key_response", keyResponse.Type)
	check.NotEqual(t, "", keyResponse.PublicKey)
	check.NotNil(t, keyResponse.KeyAttestation)

	// Verify auction token in attestation user_data
	check.NotEqual(t, "", keyResponse.KeyAttestation.UserData.AuctionToken)

	// Verify auction token is a valid UUID v4
	parsedToken, err := uuid.Parse(keyResponse.KeyAttestation.UserData.AuctionToken)
	check.NoError(t, err)
	check.Equal(t, uuid.Version(4), parsedToken.Version())

	// Verify public key is in proper PEM format
	check.True(t, strings.HasPrefix(keyResponse.PublicKey, "-----BEGIN PUBLIC KEY-----"))
	check.True(t, strings.HasSuffix(strings.TrimSpace(keyResponse.PublicKey), "-----END PUBLIC KEY-----"))

	// Verify we can parse the PEM back
	block, _ := pem.Decode([]byte(keyResponse.PublicKey))
	check.NotNil(t, block)
	check.Equal(t, "PUBLIC KEY", block.Type)

	// Verify we can parse the public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	check.NoError(t, err)
	check.NotNil(t, parsedKey)

	// Verify key attestation is properly structured
	keyAttestation := keyResponse.KeyAttestation
	check.Equal(t, "test-enclave-12345", keyAttestation.ModuleID)
	check.Equal(t, "SHA384", keyAttestation.DigestAlgorithm)
	check.NotNil(t, keyAttestation.UserData)
	check.Equal(t, "RSA-2048", keyAttestation.UserData.KeyAlgorithm)
	// Verify user data includes the public key
	check.NotEqual(t, "", keyAttestation.UserData.PublicKey)
	check.True(t, strings.Contains(keyAttestation.UserData.PublicKey, "-----BEGIN PUBLIC KEY-----"))
}

func TestHandleKeyRequest_PEMRoundTrip(t *testing.T) {
	// Create key manager
	keyManager, err := NewKeyManager()
	check.NoError(t, err)

	tokenManager := NewTokenManager()

	// Create mock enclave
	mockEnclave := CreateMockEnclave(t)

	// Handle key request
	keyResponse, err := HandleKeyRequest(mockEnclave, keyManager, tokenManager)
	check.NoError(t, err)

	// Parse the returned PEM
	block, _ := pem.Decode([]byte(keyResponse.PublicKey))
	check.NotNil(t, block)

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	check.NoError(t, err)

	// Cast to RSA public key
	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	check.True(t, ok)

	// Verify the parsed key matches the original
	check.Equal(t, 0, rsaKey.N.Cmp(keyManager.PublicKey.N))
	check.Equal(t, rsaKey.E, keyManager.PublicKey.E)
}

func TestGenerateAttestationWithMixedBidTypes(t *testing.T) {
	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_mixed_scenario",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			// Unencrypted bid 1 - Lower price, should lose
			{CoreBid: core.CoreBid{ID: "unencrypted_bid_1", Bidder: "plaintext_bidder_a", Price: 2.25, Currency: "USD"}},

			// Encrypted bid 1 - Winner after decryption
			{
				CoreBid: core.CoreBid{ID: "encrypted_bid_1", Bidder: "encrypted_bidder_b", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  "ZW5jcnlwdGVkX3dpbm5lcl9hZXNfa2V5", // Mock RSA-encrypted AES key
					EncryptedPayload: "ZW5jcnlwdGVkX3dpbm5lcl9wcmljZQ==", // Mock {"price": 4.50}
					Nonce:            "d2lubmVyX25vbmNlXzEyYg==",         // Mock 12-byte nonce
				},
			},

			// Unencrypted bid 2 - Higher than unencrypted_bid_1, but still loses to encrypted winner
			{CoreBid: core.CoreBid{ID: "unencrypted_bid_2", Bidder: "plaintext_bidder_c", Price: 3.80, Currency: "USD"}},

			// Encrypted bid 2 - Runner-up after decryption
			{
				CoreBid: core.CoreBid{ID: "encrypted_bid_2", Bidder: "encrypted_bidder_d", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  "cnVubmVyX3VwX2VuY3J5cHRlZF9rZXk=",
					EncryptedPayload: "cnVubmVyX3VwX2VuY3J5cHRlZF9wcmljZQ==", // Mock {"price": 4.00}
					Nonce:            "cnVubmVyX3VwX25vbmNlXzEyYg==",
				},
			},

			// Unencrypted bid 3 - Middle price
			{CoreBid: core.CoreBid{ID: "unencrypted_bid_3", Bidder: "plaintext_bidder_e", Price: 3.25, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{
			"plaintext_bidder_a": 1.0,
			"encrypted_bidder_b": 1.0,
			"plaintext_bidder_c": 0.95, // Adjustment factor affects final ranking
			"encrypted_bidder_d": 1.0,
			"plaintext_bidder_e": 1.05,
		},
	}

	// Expected results after E2EE decryption and adjustment factors applied:
	// encrypted_bidder_b: 4.50 * 1.0 = 4.50 (WINNER - encrypted)
	// encrypted_bidder_d: 4.00 * 1.0 = 4.00 (RUNNER-UP - encrypted)
	// plaintext_bidder_c: 3.80 * 0.95 = 3.61 (3rd place - unencrypted)
	// plaintext_bidder_e: 3.25 * 1.05 = 3.41 (4th place - unencrypted)
	// plaintext_bidder_a: 2.25 * 1.0 = 2.25 (5th place - unencrypted)

	winner := &core.CoreBid{ID: "encrypted_bid_1", Bidder: "encrypted_bidder_b", Price: 4.50, Currency: "USD"}   // Encrypted winner
	runnerUp := &core.CoreBid{ID: "encrypted_bid_2", Bidder: "encrypted_bidder_d", Price: 4.00, Currency: "USD"} // Encrypted runner-up

	// Create mock enclave
	mockEnclave := CreateMockEnclave(t)

	// Generate nonce for bid hashing
	bidHashNonce := "mixed_bid_nonce_12345"

	// Calculate bid hashes from decrypted prices for all bids
	hashU1 := generateBidHash("unencrypted_bid_1", 2.25, bidHashNonce)
	hashE1 := generateBidHash("encrypted_bid_1", 4.50, bidHashNonce) // Decrypted price
	hashU2 := generateBidHash("unencrypted_bid_2", 3.80, bidHashNonce)
	hashE2 := generateBidHash("encrypted_bid_2", 4.00, bidHashNonce) // Decrypted price
	hashU3 := generateBidHash("unencrypted_bid_3", 3.25, bidHashNonce)

	// Build list of bid hashes
	bidHashes := []string{hashU1, hashE1, hashU2, hashE2, hashU3}

	// Generate attestation for mixed bid scenario
	attestationDoc, err := GenerateAttestation(mockEnclave, req, bidHashes, "mixed_request_hash", "mixed_adj_hash",
		bidHashNonce, "mixed_req_nonce", "mixed_adj_nonce", winner, runnerUp)

	// Verify successful attestation generation
	check.NoError(t, err)
	check.NotNil(t, attestationDoc)
	check.Equal(t, "test-enclave-12345", attestationDoc.ModuleID)

	// Verify user data reflects the mixed bid scenario
	userData := attestationDoc.UserData
	check.NotNil(t, userData)
	check.Equal(t, "test_auction_mixed_scenario", userData.AuctionID)
	check.Equal(t, 1, userData.RoundID)

	// Critical test: Winner and runner-up are both from encrypted bids
	check.NotNil(t, userData.Winner)
	check.NotNil(t, userData.RunnerUp)
	check.Equal(t, winner.ID, userData.Winner.ID)     // Encrypted bid won
	check.Equal(t, 4.50, userData.Winner.Price)       // Decrypted price
	check.Equal(t, runnerUp.ID, userData.RunnerUp.ID) // Encrypted bid runner-up
	check.Equal(t, 4.00, userData.RunnerUp.Price)     // Decrypted price

	// Verify bid hashes computed from decrypted prices for all bid types
	check.Equal(t, 5, len(userData.BidHashes))
	check.True(t, slices.Contains(userData.BidHashes, hashU1))
	check.True(t, slices.Contains(userData.BidHashes, hashE1))
	check.True(t, slices.Contains(userData.BidHashes, hashU2))
	check.True(t, slices.Contains(userData.BidHashes, hashE2))
	check.True(t, slices.Contains(userData.BidHashes, hashU3))

	// Verify hashes and nonces are properly generated for mixed scenario
	check.NotEqual(t, "", userData.RequestHash)
	check.NotEqual(t, "", userData.AdjustmentFactorsHash) // Important: adjustment factors applied to both types
	check.NotEqual(t, "", userData.BidHashNonce)
	check.NotEqual(t, "", userData.RequestNonce)
	check.NotEqual(t, "", userData.AdjustmentFactorsNonce)

	// Verify attestation structural integrity
	check.NotNil(t, attestationDoc.PCRs)
	check.NotEqual(t, "", attestationDoc.Certificate)
	check.NotEqual(t, "", attestationDoc.PublicKey)
	check.NotEqual(t, "", attestationDoc.Nonce)
}
