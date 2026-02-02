package main

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/peterldowns/testy/assert"
	"github.com/peterldowns/testy/check"

	"github.com/cloudx-io/openauction/core"
	"github.com/cloudx-io/openauction/enclaveapi"
)

// parseAttestationFromResponse is a test helper that parses the COSE attestation from a response
func parseAttestationFromResponse(t *testing.T, response enclaveapi.EnclaveAuctionResponse) *enclaveapi.AuctionAttestationDoc {
	t.Helper()

	// Return nil for responses without attestation (e.g., validation failures)
	if response.AttestationCOSEBase64 == "" {
		return nil
	}

	coseBytes, err := response.AttestationCOSEBase64.Decode()
	assert.Nil(t, err)

	return parseAuctionAttestationFromCOSE(t, coseBytes)
}

func TestProcessAuction_ZeroBids(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_zero_bids",
		RoundIDString: "test_auction_zero_bids-1",
		Bids:          []enclaveapi.EncryptedCoreBid{}, // No bids
		Timestamp:     time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response and attestation structure
	attestationDoc := validateSuccessfulResponse(t, response, req, 0)

	// Verify attestation document contains no winner/runner-up
	check.Nil(t, attestationDoc.UserData.Winner)
	check.Nil(t, attestationDoc.UserData.RunnerUp)

	// Verify empty bid hashes
	check.Equal(t, []string{}, attestationDoc.UserData.BidHashes)
}

func TestProcessAuction_OneBid(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_one_bid",
		RoundIDString: "test_auction_one_bid-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.50, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{},
		Timestamp:         time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response and attestation structure
	attestationDoc := validateSuccessfulResponse(t, response, req, 1)

	// Verify attestation document contains winner but no runner-up
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Nil(t, attestationDoc.UserData.RunnerUp)

	// Verify winner details
	check.Equal(t, "bid1", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 2.50, attestationDoc.UserData.Winner.Price)

	// Verify bid hashes contains single bid
	nonce := attestationDoc.UserData.BidHashNonce
	expectedHash := core.ComputeBidHash("bid1", 2.50, nonce)

	check.Equal(t, 1, len(attestationDoc.UserData.BidHashes))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, expectedHash))
}

func TestProcessAuction_TwoBids(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_two_bids",
		RoundIDString: "test_auction_two_bids-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.50, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 3.00, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{
			"bidder_a": 1.0, // 2.50 * 1.0 = 2.50
			"bidder_b": 1.0, // 3.00 * 1.0 = 3.00
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response and attestation structure
	attestationDoc := validateSuccessfulResponse(t, response, req, 2)

	// Verify attestation document contains winner and runner-up
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.NotNil(t, attestationDoc.UserData.RunnerUp)

	// Verify winner is the highest bid (bidder_b at 3.00)
	check.Equal(t, "bid2", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 3.00, attestationDoc.UserData.Winner.Price)

	// Verify runner-up is the second highest bid (bidder_a at 2.50)
	check.Equal(t, "bid1", attestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 2.50, attestationDoc.UserData.RunnerUp.Price)

	// Verify bid hashes contains both bids
	nonce := attestationDoc.UserData.BidHashNonce
	hash1 := core.ComputeBidHash("bid1", 2.50, nonce)
	hash2 := core.ComputeBidHash("bid2", 3.00, nonce)

	check.Equal(t, 2, len(attestationDoc.UserData.BidHashes))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, hash1))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, hash2))
}

func TestProcessAuction_ThreeBids(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_three_bids",
		RoundIDString: "test_auction_three_bids-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.50, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 3.00, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder_c", Price: 2.25, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{
			"bidder_a": 1.0, // 2.50 * 1.0 = 2.50
			"bidder_b": 0.9, // 3.00 * 0.9 = 2.70
			"bidder_c": 1.1, // 2.25 * 1.1 = 2.475
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response and attestation structure
	attestationDoc := validateSuccessfulResponse(t, response, req, 3)

	// Verify attestation document contains winner and runner-up
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.NotNil(t, attestationDoc.UserData.RunnerUp)

	// After adjustment factors, the ranking should be:
	// 1. bidder_b: 2.70 (winner) - 3.00 * 0.9 = 2.70
	// 2. bidder_a: 2.50 (runner-up) - 2.50 * 1.0 = 2.50
	// 3. bidder_c: 2.475 - 2.25 * 1.1 = 2.475
	check.Equal(t, "bid2", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 2.70, attestationDoc.UserData.Winner.Price)

	check.Equal(t, "bid1", attestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 2.50, attestationDoc.UserData.RunnerUp.Price)

	// Verify bid hashes contains all three bids
	nonce := attestationDoc.UserData.BidHashNonce
	hash1 := core.ComputeBidHash("bid1", 2.50, nonce)
	hash2 := core.ComputeBidHash("bid2", 3.00, nonce)
	hash3 := core.ComputeBidHash("bid3", 2.25, nonce)

	check.Equal(t, 3, len(attestationDoc.UserData.BidHashes))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, hash1))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, hash2))
	check.True(t, slices.Contains(attestationDoc.UserData.BidHashes, hash3))
}

func TestGetBidderName(t *testing.T) {
	bid := &core.CoreBid{
		ID:     "test_bid",
		Bidder: "test_bidder",
		Price:  1.50,
	}

	check.Equal(t, "test_bidder", getBidderName(bid))
	check.Equal(t, "none", getBidderName(nil))
}

func TestGetBidPrice(t *testing.T) {
	bid := &core.CoreBid{
		ID:     "test_bid",
		Bidder: "test_bidder",
		Price:  2.75,
	}

	check.Equal(t, 2.75, getBidPrice(bid))
	check.Equal(t, 0.0, getBidPrice(nil))
}

// validateSuccessfulResponse validates common fields of successful auction responses and attestation docs
func validateSuccessfulResponse(t *testing.T, response enclaveapi.EnclaveAuctionResponse, req enclaveapi.EnclaveAuctionRequest, expectedBidCount int) *enclaveapi.AuctionAttestationDoc {
	t.Helper()

	// Basic response validation
	check.Equal(t, "auction_response", response.Type)
	check.True(t, response.Success)
	check.Equal(t, fmt.Sprintf("Processed %d bids in enclave", expectedBidCount), response.Message)
	check.NotEqual(t, "", response.AttestationCOSEBase64)
	check.GreaterThanOrEqual(t, response.ProcessingTime, int64(0))

	// Parse attestation from COSE format
	attestationDoc := parseAttestationFromResponse(t, response)
	check.NotNil(t, attestationDoc)

	// Attestation document structure validation
	check.Equal(t, "test-enclave-12345", attestationDoc.ModuleID)
	check.Equal(t, "SHA384", attestationDoc.DigestAlgorithm)
	check.NotEqual(t, "", attestationDoc.Certificate)
	check.NotEqual(t, []string{}, attestationDoc.CABundle)
	check.NotEqual(t, "", attestationDoc.PublicKey)
	check.NotEqual(t, "", attestationDoc.Nonce)
	check.NotEqual(t, time.Time{}, attestationDoc.Timestamp)

	// User data core fields validation
	check.Equal(t, attestationDoc.UserData.AuctionID, req.AuctionID)
	check.Equal(t, attestationDoc.UserData.RoundID, req.RoundID)
	check.Equal(t, attestationDoc.UserData.RoundIDString, req.RoundIDString)

	// User data hashes and nonces validation
	check.NotEqual(t, "", attestationDoc.UserData.RequestHash)
	check.NotEqual(t, "", attestationDoc.UserData.AdjustmentFactorsHash)
	check.NotEqual(t, "", attestationDoc.UserData.BidHashNonce)
	check.NotEqual(t, "", attestationDoc.UserData.RequestNonce)
	check.NotEqual(t, "", attestationDoc.UserData.AdjustmentFactorsNonce)

	return attestationDoc
}

// Bid floor enforcement tests

// TestProcessAuction_BidFloorEnforcement tests that bids below floor are rejected
func TestProcessAuction_BidFloorEnforcement(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_floor_enforcement",
		RoundIDString: "test_auction_floor_enforcement-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}}, // Above floor
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 2.50, Currency: "USD"}}, // At floor
			{CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder_c", Price: 2.00, Currency: "USD"}}, // Below floor
		},
		AdjustmentFactors: map[string]float64{},
		BidFloor:          2.50,
		Timestamp:         time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	attestationDoc := parseAttestationFromResponse(t, response)
	assert.NotNil(t, attestationDoc)
	assert.NotNil(t, attestationDoc.UserData)

	// Verify per-bidder floors are included in attestation
	check.Equal(t, 2.50, attestationDoc.UserData.BidFloor)

	// Verify ALL bids are in attestation (including floor-rejected bid3)
	// This allows bidders rejected by floor to verify the auction and see the floor
	check.Equal(t, 3, len(attestationDoc.UserData.BidHashes))

	// Verify winner is highest bid above floor
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Equal(t, "bid1", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 3.00, attestationDoc.UserData.Winner.Price)

	// Verify runner-up is bid at floor
	check.NotNil(t, attestationDoc.UserData.RunnerUp)
	check.Equal(t, "bid2", attestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 2.50, attestationDoc.UserData.RunnerUp.Price)
}

// TestProcessAuction_BidFloorAllRejected tests when all bids are below floor
func TestProcessAuction_BidFloorAllRejected(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_floor_all_rejected",
		RoundIDString: "test_auction_floor_all_rejected-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.00, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 1.50, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{},
		BidFloor:          2.50,
		Timestamp:         time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	attestationDoc := parseAttestationFromResponse(t, response)
	assert.NotNil(t, attestationDoc)

	// Verify floors are included in attestation
	check.Equal(t, 2.50, attestationDoc.UserData.BidFloor)

	// Verify ALL bids are still in attestation (even though rejected by floor)
	// This allows bidders to verify the auction and see the floor that rejected them
	check.Equal(t, 2, len(attestationDoc.UserData.BidHashes))

	// Verify no winner or runner-up (because all bids were below floor)
	check.Nil(t, attestationDoc.UserData.Winner)
	check.Nil(t, attestationDoc.UserData.RunnerUp)
}

// Token validation tests

func TestAuctionTokenValidation_WithValidToken(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Generate a token
	token := tokenManager.GenerateToken()
	check.True(t, tokenManager.ValidateToken(token))

	// Create encrypted bid with valid token
	payload := fmt.Sprintf(`{"price": 5.50, "auction_token": "%s"}`, token)
	result, err := EncryptHybridWithHash([]byte(payload), keyManager.PublicKey, HashAlgorithmSHA256)
	check.NoError(t, err)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_valid_token",
		RoundIDString: "test_auction_valid_token-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result.EncryptedAESKey,
					EncryptedPayload: result.EncryptedPayload,
					Nonce:            result.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Should succeed
	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)

	// Token should be consumed
	check.False(t, tokenManager.ValidateToken(token))
}

func TestAuctionTokenValidation_WithInvalidToken(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Use a token that was never generated
	fakeToken := "00000000-0000-0000-0000-000000000000"
	check.False(t, tokenManager.ValidateToken(fakeToken))

	// Create encrypted bid with invalid token
	payload := fmt.Sprintf(`{"price": 5.50, "auction_token": "%s"}`, fakeToken)
	result, err := EncryptHybridWithHash([]byte(payload), keyManager.PublicKey, HashAlgorithmSHA256)
	check.NoError(t, err)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_invalid_token",
		RoundIDString: "test_auction_invalid_token-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result.EncryptedAESKey,
					EncryptedPayload: result.EncryptedPayload,
					Nonce:            result.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Should succeed but exclude the bid
	check.True(t, response.Success)
	check.Equal(t, 1, len(response.ExcludedBids))
	check.Equal(t, "bid1", response.ExcludedBids[0].BidID)
	check.Equal(t, "invalid_or_consumed_auction_token", response.ExcludedBids[0].Reason)
}

func TestAuctionTokenValidation_WithConsumedToken(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Generate and consume a token
	token := tokenManager.GenerateToken()
	tokenManager.ConsumeToken(token)
	check.False(t, tokenManager.ValidateToken(token))

	// Try to use the consumed token
	payload := fmt.Sprintf(`{"price": 5.50, "auction_token": "%s"}`, token)
	result, err := EncryptHybridWithHash([]byte(payload), keyManager.PublicKey, HashAlgorithmSHA256)
	check.NoError(t, err)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_consumed_token",
		RoundIDString: "test_auction_consumed_token-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result.EncryptedAESKey,
					EncryptedPayload: result.EncryptedPayload,
					Nonce:            result.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Should succeed but exclude the bid
	check.True(t, response.Success)
	check.Equal(t, 1, len(response.ExcludedBids))
	check.Equal(t, "bid1", response.ExcludedBids[0].BidID)
	check.Equal(t, "invalid_or_consumed_auction_token", response.ExcludedBids[0].Reason)
}

func TestAuctionTokenValidation_WithoutToken(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Create encrypted bid WITHOUT token (backward compatible)
	payload := `{"price": 5.50}`
	result, err := EncryptHybridWithHash([]byte(payload), keyManager.PublicKey, HashAlgorithmSHA256)
	check.NoError(t, err)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_no_token",
		RoundIDString: "test_auction_no_token-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result.EncryptedAESKey,
					EncryptedPayload: result.EncryptedPayload,
					Nonce:            result.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Should succeed (backward compatible)
	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)
}

func TestAuctionTokenValidation_MultipleBidsWithTokens(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Generate three tokens
	token1 := tokenManager.GenerateToken()
	token2 := tokenManager.GenerateToken()
	token3 := tokenManager.GenerateToken()

	// Create three bids with different tokens
	payload1 := fmt.Sprintf(`{"price": 3.00, "auction_token": "%s"}`, token1)
	result1, _ := EncryptHybridWithHash([]byte(payload1), keyManager.PublicKey, HashAlgorithmSHA256)

	payload2 := fmt.Sprintf(`{"price": 4.50, "auction_token": "%s"}`, token2)
	result2, _ := EncryptHybridWithHash([]byte(payload2), keyManager.PublicKey, HashAlgorithmSHA256)

	payload3 := fmt.Sprintf(`{"price": 2.75, "auction_token": "%s"}`, token3)
	result3, _ := EncryptHybridWithHash([]byte(payload3), keyManager.PublicKey, HashAlgorithmSHA256)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_multiple_tokens",
		RoundIDString: "test_auction_multiple_tokens-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result1.EncryptedAESKey,
					EncryptedPayload: result1.EncryptedPayload,
					Nonce:            result1.Nonce,
				},
			},
			{
				CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder2", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result2.EncryptedAESKey,
					EncryptedPayload: result2.EncryptedPayload,
					Nonce:            result2.Nonce,
				},
			},
			{
				CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder3", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result3.EncryptedAESKey,
					EncryptedPayload: result3.EncryptedPayload,
					Nonce:            result3.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Should succeed
	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)

	// All tokens should be consumed
	check.False(t, tokenManager.ValidateToken(token1))
	check.False(t, tokenManager.ValidateToken(token2))
	check.False(t, tokenManager.ValidateToken(token3))

	attestationDoc := parseAttestationFromResponse(t, response)

	// Winner should be bid2 (highest price)
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Equal(t, "bid2", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 4.50, attestationDoc.UserData.Winner.Price)
}

func TestAuctionTokenValidation_MixedValidInvalidTokens(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Generate one valid token
	validToken := tokenManager.GenerateToken()
	invalidToken := "11111111-1111-1111-1111-111111111111"

	// Bid 1: valid token
	payload1 := fmt.Sprintf(`{"price": 3.00, "auction_token": "%s"}`, validToken)
	result1, _ := EncryptHybridWithHash([]byte(payload1), keyManager.PublicKey, HashAlgorithmSHA256)

	// Bid 2: invalid token (should be excluded)
	payload2 := fmt.Sprintf(`{"price": 4.50, "auction_token": "%s"}`, invalidToken)
	result2, _ := EncryptHybridWithHash([]byte(payload2), keyManager.PublicKey, HashAlgorithmSHA256)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_mixed_tokens",
		RoundIDString: "test_auction_mixed_tokens-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result1.EncryptedAESKey,
					EncryptedPayload: result1.EncryptedPayload,
					Nonce:            result1.Nonce,
				},
			},
			{
				CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder2", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result2.EncryptedAESKey,
					EncryptedPayload: result2.EncryptedPayload,
					Nonce:            result2.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Should succeed
	check.True(t, response.Success)

	// bid2 should be excluded
	check.Equal(t, 1, len(response.ExcludedBids))
	check.Equal(t, "bid2", response.ExcludedBids[0].BidID)
	check.Equal(t, "invalid_or_consumed_auction_token", response.ExcludedBids[0].Reason)

	// Valid token should be consumed
	check.False(t, tokenManager.ValidateToken(validToken))

	attestationDoc := parseAttestationFromResponse(t, response)

	// Winner should be bid1
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Equal(t, "bid1", attestationDoc.UserData.Winner.ID)
}

// End-to-end token flow test
func TestEndToEndTokenFlow(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Request key and auction token
	keyResp, err := HandleKeyRequest(mockAttester, keyManager, tokenManager)
	check.NoError(t, err)
	check.NotEqual(t, "", keyResp.PublicKey)
	check.NotEqual(t, "", keyResp.AuctionToken)
	token := keyResp.AuctionToken

	// Token should be valid
	check.True(t, tokenManager.ValidateToken(token))

	// Create encrypted bid with token
	payload := fmt.Sprintf(`{"price": 6.75, "auction_token": "%s"}`, token)
	result, err := EncryptHybridWithHash([]byte(payload), keyManager.PublicKey, HashAlgorithmSHA256)
	check.NoError(t, err)

	// Run auction
	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_end_to_end",
		RoundIDString: "test_end_to_end-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result.EncryptedAESKey,
					EncryptedPayload: result.EncryptedPayload,
					Nonce:            result.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Auction should succeed
	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)

	// Token should be consumed
	check.False(t, tokenManager.ValidateToken(token))

	// Step 4: Try to replay same bid in second auction (should fail)
	req2 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_replay_attack",
		RoundIDString: "test_replay_attack-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result.EncryptedAESKey,
					EncryptedPayload: result.EncryptedPayload,
					Nonce:            result.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response2 := ProcessAuction(mockAttester, req2, keyManager, tokenManager)

	// Auction should succeed but exclude the replayed bid
	check.True(t, response2.Success)
	check.Equal(t, 1, len(response2.ExcludedBids))
	check.Equal(t, "bid1", response2.ExcludedBids[0].BidID)
	check.Equal(t, "invalid_or_consumed_auction_token", response2.ExcludedBids[0].Reason)
}

func TestAuctionTokenValidation_MultipleBidsSameToken(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Generate ONE token for the entire auction
	sharedToken := tokenManager.GenerateToken()

	// Create THREE bids all using the SAME token (realistic scenario)
	payload1 := fmt.Sprintf(`{"price": 3.00, "auction_token": "%s"}`, sharedToken)
	result1, _ := EncryptHybridWithHash([]byte(payload1), keyManager.PublicKey, HashAlgorithmSHA256)

	payload2 := fmt.Sprintf(`{"price": 4.50, "auction_token": "%s"}`, sharedToken)
	result2, _ := EncryptHybridWithHash([]byte(payload2), keyManager.PublicKey, HashAlgorithmSHA256)

	payload3 := fmt.Sprintf(`{"price": 2.75, "auction_token": "%s"}`, sharedToken)
	result3, _ := EncryptHybridWithHash([]byte(payload3), keyManager.PublicKey, HashAlgorithmSHA256)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_shared_token",
		RoundIDString: "test_auction_shared_token-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result1.EncryptedAESKey,
					EncryptedPayload: result1.EncryptedPayload,
					Nonce:            result1.Nonce,
				},
			},
			{
				CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder2", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result2.EncryptedAESKey,
					EncryptedPayload: result2.EncryptedPayload,
					Nonce:            result2.Nonce,
				},
			},
			{
				CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder3", Price: 0.0, Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  result3.EncryptedAESKey,
					EncryptedPayload: result3.EncryptedPayload,
					Nonce:            result3.Nonce,
				},
			},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager, tokenManager)

	// Should succeed - all three bids with same token are valid
	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)

	// Shared token should be consumed (only once)
	check.False(t, tokenManager.ValidateToken(sharedToken))

	attestationDoc := parseAttestationFromResponse(t, response)

	// Winner should be bid2 (highest price)
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Equal(t, "bid2", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 4.50, attestationDoc.UserData.Winner.Price)
}

// TestProcessAuction_BidFloorZero tests that zero floor means no enforcement
func TestProcessAuction_BidFloorZero(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_floor_zero",
		RoundIDString: "test_auction_floor_zero-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 0.50, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{}, // No floors
		BidFloor:          0.00,
		Timestamp:         time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	attestationDoc := parseAttestationFromResponse(t, response)
	assert.NotNil(t, attestationDoc)

	// Verify empty floor in attestation
	check.Equal(t, 0.00, attestationDoc.UserData.BidFloor)

	// Verify all bids pass (no floor enforcement)
	check.Equal(t, 2, len(attestationDoc.UserData.BidHashes))
}

// TestProcessAuction_BidFloorWithAdjustments tests floor enforcement happens after adjustments
func TestProcessAuction_BidFloorWithAdjustments(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_floor_with_adjustments",
		RoundIDString: "test_auction_floor_with_adjustments-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 2.00, Currency: "USD"}}, // Below floor before adjustment
		},
		AdjustmentFactors: map[string]float64{
			"bidder_b": 2.0, // This makes bid2 = $4.00 after adjustment
		},
		BidFloor:  2.50,
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	attestationDoc := parseAttestationFromResponse(t, response)
	assert.NotNil(t, attestationDoc)

	// Verify floors are included in attestation
	check.Equal(t, 2.50, attestationDoc.UserData.BidFloor)

	// Verify both bids are in attestation
	check.Equal(t, 2, len(attestationDoc.UserData.BidHashes))

	// Verify bidder_b won (after 2.0x adjustment: $2.00 × 2.0 = $4.00 > $2.50 floor)
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Equal(t, "bid2", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 4.00, attestationDoc.UserData.Winner.Price)

	// Verify bidder_a is runner-up
	check.NotNil(t, attestationDoc.UserData.RunnerUp)
	check.Equal(t, "bid1", attestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 3.00, attestationDoc.UserData.RunnerUp.Price)
}

// TestProcessAuction_NegativeFloorRejected tests that TEE rejects negative floor prices
func TestProcessAuction_NegativeFloorRejected(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_negative_floor",
		RoundIDString: "test_auction_negative_floor-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{},
		BidFloor:          -2.50, // Negative floor - invalid!
		Timestamp:         time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Verify TEE rejected the request
	check.False(t, response.Success)
	check.Equal(t, "Invalid negative floor price -2.5000", response.Message)
	attestationDoc := parseAttestationFromResponse(t, response)
	check.Nil(t, attestationDoc)
}

// TestProcessAuction_LegacyRoundID tests backward compatibility (RoundID as int only)
func TestProcessAuction_LegacyRoundID(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_legacy_round_id",
		RoundID:   123, // Set int only, no String ID
		// RoundIDString omitted
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 1.00, Currency: "USD"}},
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	attestationDoc := parseAttestationFromResponse(t, response)
	assert.NotNil(t, attestationDoc)

	// Verify RoundID is present
	check.Equal(t, 123, attestationDoc.UserData.RoundID)
	// RoundIDString should be empty
	check.Equal(t, "", attestationDoc.UserData.RoundIDString)
	// Hashes should still be valid (will use "123" for calculation)
	check.NotEqual(t, "", attestationDoc.UserData.RequestHash)
}

// TestProcessAuction_StringRoundID tests new functionality (RoundIDString only)
func TestProcessAuction_StringRoundID(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_string_round_id",
		RoundID:       0, // Zero value for int
		RoundIDString: "unique-round-id-xyz",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 1.00, Currency: "USD"}},
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	attestationDoc := parseAttestationFromResponse(t, response)
	assert.NotNil(t, attestationDoc)

	// Verify RoundIDString is present
	check.Equal(t, "unique-round-id-xyz", attestationDoc.UserData.RoundIDString)
	check.Equal(t, 0, attestationDoc.UserData.RoundID)
	// Hashes should still be valid (will use "unique-round-id-xyz" for calculation)
	check.NotEqual(t, "", attestationDoc.UserData.RequestHash)
}
