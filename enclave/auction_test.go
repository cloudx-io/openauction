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

func TestProcessAuction_ZeroBids(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_zero_bids",
		RoundID:   1,
		Bids:      []enclaveapi.EncryptedCoreBid{}, // No bids
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response and attestation structure
	validateSuccessfulResponse(t, response, req, 0)

	// Verify attestation document contains no winner/runner-up
	check.Nil(t, response.AttestationDoc.UserData.Winner)
	check.Nil(t, response.AttestationDoc.UserData.RunnerUp)

	// Verify empty bid hashes
	check.Equal(t, []string{}, response.AttestationDoc.UserData.BidHashes)
}

func TestProcessAuction_OneBid(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_one_bid",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.50, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{},
		Timestamp:         time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response and attestation structure
	validateSuccessfulResponse(t, response, req, 1)

	// Verify attestation document contains winner but no runner-up
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.Nil(t, response.AttestationDoc.UserData.RunnerUp)

	// Verify winner details
	check.Equal(t, "bid1", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.Winner.Price)

	// Verify bid hashes contains single bid
	nonce := response.AttestationDoc.UserData.BidHashNonce
	expectedHash := generateBidHash("bid1", 2.50, nonce)

	check.Equal(t, 1, len(response.AttestationDoc.UserData.BidHashes))
	check.True(t, slices.Contains(response.AttestationDoc.UserData.BidHashes, expectedHash))
}

func TestProcessAuction_TwoBids(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_two_bids",
		RoundID:   1,
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
	validateSuccessfulResponse(t, response, req, 2)

	// Verify attestation document contains winner and runner-up
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.NotNil(t, response.AttestationDoc.UserData.RunnerUp)

	// Verify winner is the highest bid (bidder_b at 3.00)
	check.Equal(t, "bid2", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 3.00, response.AttestationDoc.UserData.Winner.Price)

	// Verify runner-up is the second highest bid (bidder_a at 2.50)
	check.Equal(t, "bid1", response.AttestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.RunnerUp.Price)

	// Verify bid hashes contains both bids
	nonce := response.AttestationDoc.UserData.BidHashNonce
	hash1 := generateBidHash("bid1", 2.50, nonce)
	hash2 := generateBidHash("bid2", 3.00, nonce)

	check.Equal(t, 2, len(response.AttestationDoc.UserData.BidHashes))
	check.True(t, slices.Contains(response.AttestationDoc.UserData.BidHashes, hash1))
	check.True(t, slices.Contains(response.AttestationDoc.UserData.BidHashes, hash2))
}

func TestProcessAuction_ThreeBids(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_three_bids",
		RoundID:   1,
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
	validateSuccessfulResponse(t, response, req, 3)

	// Verify attestation document contains winner and runner-up
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.NotNil(t, response.AttestationDoc.UserData.RunnerUp)

	// After adjustment factors, the ranking should be:
	// 1. bidder_b: 2.70 (winner) - 3.00 * 0.9 = 2.70
	// 2. bidder_a: 2.50 (runner-up) - 2.50 * 1.0 = 2.50
	// 3. bidder_c: 2.475 - 2.25 * 1.1 = 2.475
	check.Equal(t, "bid2", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 2.70, response.AttestationDoc.UserData.Winner.Price)

	check.Equal(t, "bid1", response.AttestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.RunnerUp.Price)

	// Verify bid hashes contains all three bids
	nonce := response.AttestationDoc.UserData.BidHashNonce
	hash1 := generateBidHash("bid1", 2.50, nonce)
	hash2 := generateBidHash("bid2", 3.00, nonce)
	hash3 := generateBidHash("bid3", 2.25, nonce)

	check.Equal(t, 3, len(response.AttestationDoc.UserData.BidHashes))
	check.True(t, slices.Contains(response.AttestationDoc.UserData.BidHashes, hash1))
	check.True(t, slices.Contains(response.AttestationDoc.UserData.BidHashes, hash2))
	check.True(t, slices.Contains(response.AttestationDoc.UserData.BidHashes, hash3))
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
func validateSuccessfulResponse(t *testing.T, response enclaveapi.EnclaveAuctionResponse, req enclaveapi.EnclaveAuctionRequest, expectedBidCount int) {
	t.Helper()

	// Basic response validation
	check.Equal(t, "auction_response", response.Type)
	check.True(t, response.Success)
	check.Equal(t, fmt.Sprintf("Processed %d bids in enclave", expectedBidCount), response.Message)
	check.NotNil(t, response.AttestationDoc)
	check.GreaterThanOrEqual(t, response.ProcessingTime, int64(0))

	// Attestation document structure validation
	check.Equal(t, "test-enclave-12345", response.AttestationDoc.ModuleID)
	check.Equal(t, "SHA384", response.AttestationDoc.DigestAlgorithm)
	check.NotEqual(t, "", response.AttestationDoc.Certificate)
	check.NotEqual(t, []string{}, response.AttestationDoc.CABundle)
	check.NotEqual(t, "", response.AttestationDoc.PublicKey)
	check.NotEqual(t, "", response.AttestationDoc.Nonce)
	check.NotEqual(t, time.Time{}, response.AttestationDoc.Timestamp)

	// User data core fields validation
	check.Equal(t, response.AttestationDoc.UserData.AuctionID, req.AuctionID)
	check.Equal(t, response.AttestationDoc.UserData.RoundID, req.RoundID)

	// User data hashes and nonces validation
	check.NotEqual(t, "", response.AttestationDoc.UserData.RequestHash)
	check.NotEqual(t, "", response.AttestationDoc.UserData.AdjustmentFactorsHash)
	check.NotEqual(t, "", response.AttestationDoc.UserData.BidHashNonce)
	check.NotEqual(t, "", response.AttestationDoc.UserData.RequestNonce)
	check.NotEqual(t, "", response.AttestationDoc.UserData.AdjustmentFactorsNonce)
}

// Bid floor enforcement tests

// TestProcessAuction_BidFloorEnforcement tests that bids below floor are rejected
func TestProcessAuction_BidFloorEnforcement(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_floor_enforcement",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}}, // Above floor
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 2.50, Currency: "USD"}}, // At floor
			{CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder_c", Price: 2.00, Currency: "USD"}}, // Below floor
		},
		AdjustmentFactors: map[string]float64{},
		BidFloors: map[string]float64{
			"bidder_a": 2.50,
			"bidder_b": 2.50,
			"bidder_c": 2.50,
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	assert.NotNil(t, response.AttestationDoc)
	assert.NotNil(t, response.AttestationDoc.UserData)

	// Verify per-bidder floors are included in attestation
	assert.NotNil(t, response.AttestationDoc.UserData.BidFloors)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_a"])
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_b"])
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_c"])

	// Verify ALL bids are in attestation (including floor-rejected bid3)
	// This allows bidders rejected by floor to verify the auction and see the floor
	check.Equal(t, 3, len(response.AttestationDoc.UserData.BidHashes))

	// Verify winner is highest bid above floor
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.Equal(t, "bid1", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 3.00, response.AttestationDoc.UserData.Winner.Price)

	// Verify runner-up is bid at floor
	check.NotNil(t, response.AttestationDoc.UserData.RunnerUp)
	check.Equal(t, "bid2", response.AttestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.RunnerUp.Price)
}

// TestProcessAuction_BidFloorAllRejected tests when all bids are below floor
func TestProcessAuction_BidFloorAllRejected(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_floor_all_rejected",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.00, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 1.50, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{},
		BidFloors: map[string]float64{
			"bidder_a": 2.50,
			"bidder_b": 2.50,
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	assert.NotNil(t, response.AttestationDoc)

	// Verify floors are included in attestation
	assert.NotNil(t, response.AttestationDoc.UserData.BidFloors)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_a"])
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_b"])

	// Verify ALL bids are still in attestation (even though rejected by floor)
	// This allows bidders to verify the auction and see the floor that rejected them
	check.Equal(t, 2, len(response.AttestationDoc.UserData.BidHashes))

	// Verify no winner or runner-up (because all bids were below floor)
	check.Nil(t, response.AttestationDoc.UserData.Winner)
	check.Nil(t, response.AttestationDoc.UserData.RunnerUp)
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
		Type:      "auction_request",
		AuctionID: "test_auction_valid_token",
		RoundID:   1,
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
	check.Equal(t, []enclaveapi.ExcludedBid{}, response.ExcludedBids)

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
		Type:      "auction_request",
		AuctionID: "test_auction_invalid_token",
		RoundID:   1,
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
		Type:      "auction_request",
		AuctionID: "test_auction_consumed_token",
		RoundID:   1,
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
		Type:      "auction_request",
		AuctionID: "test_auction_no_token",
		RoundID:   1,
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
	check.Equal(t, []enclaveapi.ExcludedBid{}, response.ExcludedBids)
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
		Type:      "auction_request",
		AuctionID: "test_auction_multiple_tokens",
		RoundID:   1,
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
	check.Equal(t, []enclaveapi.ExcludedBid{}, response.ExcludedBids)

	// All tokens should be consumed
	check.False(t, tokenManager.ValidateToken(token1))
	check.False(t, tokenManager.ValidateToken(token2))
	check.False(t, tokenManager.ValidateToken(token3))

	// Winner should be bid2 (highest price)
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.Equal(t, "bid2", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 4.50, response.AttestationDoc.UserData.Winner.Price)
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
		Type:      "auction_request",
		AuctionID: "test_auction_mixed_tokens",
		RoundID:   1,
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

	// Winner should be bid1
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.Equal(t, "bid1", response.AttestationDoc.UserData.Winner.ID)
}

// End-to-end token flow test
func TestEndToEndTokenFlow(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager, _ := NewKeyManager()
	tokenManager := NewTokenManager()

	// Request key and get token from attestation user_data
	keyResp, err := HandleKeyRequest(mockAttester, keyManager, tokenManager)
	check.NoError(t, err)
	check.NotEqual(t, "", keyResp.PublicKey)
	check.NotNil(t, keyResp.KeyAttestation)
	check.NotEqual(t, "", keyResp.KeyAttestation.UserData.AuctionToken)
	token := keyResp.KeyAttestation.UserData.AuctionToken

	// Token should be valid
	check.True(t, tokenManager.ValidateToken(token))

	// Create encrypted bid with token
	payload := fmt.Sprintf(`{"price": 6.75, "auction_token": "%s"}`, token)
	result, err := EncryptHybridWithHash([]byte(payload), keyManager.PublicKey, HashAlgorithmSHA256)
	check.NoError(t, err)

	// Run auction
	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_end_to_end",
		RoundID:   1,
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
	check.Equal(t, []enclaveapi.ExcludedBid{}, response.ExcludedBids)

	// Token should be consumed
	check.False(t, tokenManager.ValidateToken(token))

	// Step 4: Try to replay same bid in second auction (should fail)
	req2 := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_replay_attack",
		RoundID:   1,
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
		Type:      "auction_request",
		AuctionID: "test_auction_shared_token",
		RoundID:   1,
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
	check.Equal(t, []enclaveapi.ExcludedBid{}, response.ExcludedBids)

	// Shared token should be consumed (only once)
	check.False(t, tokenManager.ValidateToken(sharedToken))

	// Winner should be bid2 (highest price)
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.Equal(t, "bid2", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 4.50, response.AttestationDoc.UserData.Winner.Price)
}

// TestProcessAuction_BidFloorZero tests that zero floor means no enforcement
func TestProcessAuction_BidFloorZero(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_floor_zero",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 0.50, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{},
		BidFloors:         map[string]float64{}, // No floors
		Timestamp:         time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	assert.NotNil(t, response.AttestationDoc)

	// Verify empty floors map in attestation
	check.Equal(t, map[string]float64{}, response.AttestationDoc.UserData.BidFloors)

	// Verify all bids pass (no floor enforcement)
	check.Equal(t, 2, len(response.AttestationDoc.UserData.BidHashes))
}

// TestProcessAuction_BidFloorWithAdjustments tests floor enforcement happens after adjustments
func TestProcessAuction_BidFloorWithAdjustments(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_floor_with_adjustments",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 2.00, Currency: "USD"}}, // Below floor before adjustment
		},
		AdjustmentFactors: map[string]float64{
			"bidder_b": 2.0, // This makes bid2 = $4.00 after adjustment
		},
		BidFloors: map[string]float64{
			"bidder_a": 2.50,
			"bidder_b": 2.50,
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	assert.NotNil(t, response.AttestationDoc)

	// Verify floors are included in attestation
	assert.NotNil(t, response.AttestationDoc.UserData.BidFloors)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_a"])
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_b"])

	// Verify both bids are in attestation
	check.Equal(t, 2, len(response.AttestationDoc.UserData.BidHashes))

	// Verify bidder_b won (after 2.0x adjustment: $2.00 × 2.0 = $4.00 > $2.50 floor)
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.Equal(t, "bid2", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 4.00, response.AttestationDoc.UserData.Winner.Price)

	// Verify bidder_a is runner-up
	check.NotNil(t, response.AttestationDoc.UserData.RunnerUp)
	check.Equal(t, "bid1", response.AttestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 3.00, response.AttestationDoc.UserData.RunnerUp.Price)
}

// TestProcessAuction_PerBidderFloors tests that different bidders can have different floors
func TestProcessAuction_PerBidderFloors(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_per_bidder_floors",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 2.75, Currency: "USD"}}, // Above bidder_a floor (2.50)
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder_b", Price: 2.75, Currency: "USD"}}, // Below bidder_b floor (3.00)
			{CoreBid: core.CoreBid{ID: "bid3", Bidder: "bidder_c", Price: 1.50, Currency: "USD"}}, // Above bidder_c floor (1.00)
		},
		AdjustmentFactors: map[string]float64{},
		BidFloors: map[string]float64{
			"bidder_a": 2.50, // Lowest floor
			"bidder_b": 3.00, // Highest floor
			"bidder_c": 1.00, // Medium floor
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Validate successful response
	assert.True(t, response.Success)
	assert.NotNil(t, response.AttestationDoc)

	// Verify per-bidder floors are in attestation
	assert.NotNil(t, response.AttestationDoc.UserData.BidFloors)
	check.Equal(t, 2.50, response.AttestationDoc.UserData.BidFloors["bidder_a"])
	check.Equal(t, 3.00, response.AttestationDoc.UserData.BidFloors["bidder_b"])
	check.Equal(t, 1.00, response.AttestationDoc.UserData.BidFloors["bidder_c"])

	// Verify all bids are in attestation
	check.Equal(t, 3, len(response.AttestationDoc.UserData.BidHashes))

	// Only bidder_a and bidder_c should pass (bidder_b rejected: $2.75 < $3.00)
	// bidder_a wins with $2.75 (highest among eligible)
	check.NotNil(t, response.AttestationDoc.UserData.Winner)
	check.Equal(t, "bid1", response.AttestationDoc.UserData.Winner.ID)
	check.Equal(t, 2.75, response.AttestationDoc.UserData.Winner.Price)

	// bidder_c is runner-up with $1.50
	check.NotNil(t, response.AttestationDoc.UserData.RunnerUp)
	check.Equal(t, "bid3", response.AttestationDoc.UserData.RunnerUp.ID)
	check.Equal(t, 1.50, response.AttestationDoc.UserData.RunnerUp.Price)
}

// TestProcessAuction_NegativeFloorRejected tests that TEE rejects negative floor prices
func TestProcessAuction_NegativeFloorRejected(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:      "auction_request",
		AuctionID: "test_auction_negative_floor",
		RoundID:   1,
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 3.00, Currency: "USD"}},
		},
		AdjustmentFactors: map[string]float64{},
		BidFloors: map[string]float64{
			"bidder_a": -2.50, // Negative floor - invalid!
		},
		Timestamp: time.Now(),
	}

	tokenManager := NewTokenManager()
	response := ProcessAuction(mockAttester, req, nil, tokenManager)

	// Verify TEE rejected the request
	check.False(t, response.Success)
	check.Equal(t, "Invalid negative floor price -2.5000 for bidder bidder_a", response.Message)
	check.Nil(t, response.AttestationDoc)
}
