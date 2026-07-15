package main

import (
	"encoding/base64"
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

// newTestKeyManager builds a KeyManager backed by the mock attester for tests
// that exercise encryption/decryption and dedup.
func newTestKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	km, err := NewKeyManager(CreateMockEnclave(t))
	assert.NoError(t, err)
	return km
}

// encryptPriceBid encrypts a price payload to the key manager's current epoch and
// returns a bid carrying the resulting ciphertext.
func encryptPriceBid(t *testing.T, km *KeyManager, id, bidder, payload string) enclaveapi.EncryptedCoreBid {
	t.Helper()
	result, err := EncryptHybridWithHash([]byte(payload), km.currentEpoch().PublicKey, HashAlgorithmSHA256)
	assert.NoError(t, err)
	return enclaveapi.EncryptedCoreBid{
		CoreBid:        core.CoreBid{ID: id, Bidder: bidder, Price: 0.0, Currency: "USD"},
		EncryptedPrice: encryptedPriceFromResult(result),
	}
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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

// Ciphertext dedup replay-protection tests

// TestCiphertextDedup_FirstSubmissionAccepted verifies a fresh encrypted bid is
// accepted (not treated as a replay).
func TestCiphertextDedup_FirstSubmissionAccepted(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	bid := encryptPriceBid(t, keyManager, "bid1", "bidder1", `{"price": 5.50}`)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_first",
		RoundIDString: "test_dedup_first-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager)

	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)
}

// TestCiphertextDedup_ByteIdenticalReplayExcluded verifies that resubmitting the
// exact same ciphertext in a later auction is excluded as duplicate_ciphertext.
func TestCiphertextDedup_ByteIdenticalReplayExcluded(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	bid := encryptPriceBid(t, keyManager, "bid1", "bidder1", `{"price": 6.75}`)

	req1 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_replay_1",
		RoundIDString: "test_dedup_replay_1-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response1 := ProcessAuction(mockAttester, req1, keyManager)
	check.True(t, response1.Success)
	check.Equal(t, []core.ExcludedBid{}, response1.ExcludedBids)

	// Replay the exact same ciphertext in a second auction.
	req2 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_replay_2",
		RoundIDString: "test_dedup_replay_2-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response2 := ProcessAuction(mockAttester, req2, keyManager)

	check.True(t, response2.Success)
	check.Equal(t, 1, len(response2.ExcludedBids))
	check.Equal(t, "bid1", response2.ExcludedBids[0].BidID)
	check.Equal(t, "duplicate_ciphertext", response2.ExcludedBids[0].Reason)
}

// TestCiphertextDedup_DuplicateWithinSameAuctionExcluded verifies dedup applies
// within a single auction as well: two copies of the same ciphertext keep one.
func TestCiphertextDedup_DuplicateWithinSameAuctionExcluded(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	bidA := encryptPriceBid(t, keyManager, "bid1", "bidder1", `{"price": 4.00}`)
	// bid2 carries the identical ciphertext bytes as bid1.
	bidB := bidA
	bidB.ID = "bid2"

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_same_auction",
		RoundIDString: "test_dedup_same_auction-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bidA, bidB},
		Timestamp:     time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager)

	check.True(t, response.Success)
	check.Equal(t, 1, len(response.ExcludedBids))
	check.Equal(t, "bid2", response.ExcludedBids[0].BidID)
	check.Equal(t, "duplicate_ciphertext", response.ExcludedBids[0].Reason)
}

// TestCiphertextDedup_ReEncryptedNotExcluded verifies that the same price
// re-encrypted with fresh randomness produces a different ciphertext and is NOT
// treated as a replay.
func TestCiphertextDedup_ReEncryptedNotExcluded(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	// Two independent encryptions of the identical plaintext price.
	bid1 := encryptPriceBid(t, keyManager, "bid1", "bidder1", `{"price": 5.00}`)
	bid2 := encryptPriceBid(t, keyManager, "bid2", "bidder2", `{"price": 5.00}`)

	// Sanity: fresh randomness => different ciphertext bytes.
	check.NotEqual(t, bid1.EncryptedPrice.EncryptedPayload, bid2.EncryptedPrice.EncryptedPayload)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_reencrypt",
		RoundIDString: "test_dedup_reencrypt-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid1, bid2},
		Timestamp:     time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager)

	// Both bids are accepted; neither is treated as a replay.
	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)

	attestationDoc := parseAttestationFromResponse(t, response)
	check.Equal(t, 2, len(attestationDoc.UserData.BidHashes))
}

// TestCiphertextDedup_ReEncodedBase64StillExcluded verifies the fingerprint is
// keyed on the decoded ciphertext bytes rather than the exact base64 string
// object: a replay whose base64 fields are re-encoded (decode then re-encode to
// identical bytes, the form the enclave accepts) still collides and is excluded.
func TestCiphertextDedup_ReEncodedBase64StillExcluded(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	bid := encryptPriceBid(t, keyManager, "bid1", "bidder1", `{"price": 7.25}`)

	// A re-encode that preserves the decoded bytes yields the identical
	// fingerprint, confirming dedup keys on content, not the string object.
	reencoded := roundTripStdEncodedPrice(t, bid.EncryptedPrice)
	fpOriginal, err := ciphertextFingerprint(bid.EncryptedPrice)
	check.NoError(t, err)
	fpReencoded, err := ciphertextFingerprint(reencoded)
	check.NoError(t, err)
	check.Equal(t, fpOriginal, fpReencoded)

	req1 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_reencode_1",
		RoundIDString: "test_dedup_reencode_1-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response1 := ProcessAuction(mockAttester, req1, keyManager)
	check.True(t, response1.Success)
	check.Equal(t, []core.ExcludedBid{}, response1.ExcludedBids)

	// Replay carrying the re-encoded (but byte-identical) ciphertext.
	replay := enclaveapi.EncryptedCoreBid{
		CoreBid:        core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 0.0, Currency: "USD"},
		EncryptedPrice: reencoded,
	}
	req2 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_reencode_2",
		RoundIDString: "test_dedup_reencode_2-1",
		Bids:          []enclaveapi.EncryptedCoreBid{replay},
		Timestamp:     time.Now(),
	}
	response2 := ProcessAuction(mockAttester, req2, keyManager)

	check.True(t, response2.Success)
	check.Equal(t, 1, len(response2.ExcludedBids))
	check.Equal(t, "bid1", response2.ExcludedBids[0].BidID)
	check.Equal(t, "duplicate_ciphertext", response2.ExcludedBids[0].Reason)
}

// TestCiphertextDedup_PriorEpochReplayExcluded verifies that a bid sealed to a
// prior epoch still decrypts after rotation and is deduped under that prior
// epoch's set.
func TestCiphertextDedup_PriorEpochReplayExcluded(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	// Seal a bid to the current (soon-to-be-prior) epoch.
	bid := encryptPriceBid(t, keyManager, "bid1", "bidder1", `{"price": 3.33}`)

	req1 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_prior_epoch_1",
		RoundIDString: "test_dedup_prior_epoch_1-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response1 := ProcessAuction(mockAttester, req1, keyManager)
	check.True(t, response1.Success)
	check.Equal(t, []core.ExcludedBid{}, response1.ExcludedBids)

	// Rotate to a new current epoch; the prior epoch remains live.
	_, err := keyManager.addEpoch(mockAttester)
	check.NoError(t, err)
	check.Equal(t, 2, keyManager.epochCount())

	// Replay the prior-epoch bid: it still decrypts (under the prior epoch) and
	// its fingerprint is recognized as a duplicate for that epoch.
	req2 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_prior_epoch_2",
		RoundIDString: "test_dedup_prior_epoch_2-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response2 := ProcessAuction(mockAttester, req2, keyManager)

	check.True(t, response2.Success)
	check.Equal(t, 1, len(response2.ExcludedBids))
	check.Equal(t, "bid1", response2.ExcludedBids[0].BidID)
	check.Equal(t, "duplicate_ciphertext", response2.ExcludedBids[0].Reason)
}

// TestCiphertextDedup_PriorEpochBidStillWins verifies a bid sealed to a prior
// epoch still decrypts and participates in the auction after rotation.
func TestCiphertextDedup_PriorEpochBidStillWins(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	// Seal a bid to the current epoch, then rotate before running the auction.
	bid := encryptPriceBid(t, keyManager, "bid1", "bidder1", `{"price": 8.88}`)
	_, err := keyManager.addEpoch(mockAttester)
	check.NoError(t, err)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_prior_epoch_win",
		RoundIDString: "test_dedup_prior_epoch_win-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response := ProcessAuction(mockAttester, req, keyManager)

	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)

	attestationDoc := parseAttestationFromResponse(t, response)
	check.NotNil(t, attestationDoc.UserData.Winner)
	check.Equal(t, "bid1", attestationDoc.UserData.Winner.ID)
	check.Equal(t, 8.88, attestationDoc.UserData.Winner.Price)
}

// TestCiphertextDedup_LegacyTokenIgnored verifies that a payload carrying a
// legacy auction_token is accepted (token ignored) and still deduped by
// ciphertext on replay.
func TestCiphertextDedup_LegacyTokenIgnored(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	// Payload includes a legacy token field; it must be ignored, not validated.
	payload := `{"price": 5.50, "auction_token": "550e8400-e29b-41d4-a716-446655440000"}`
	bid := encryptPriceBid(t, keyManager, "bid1", "bidder1", payload)

	req1 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_legacy_token_1",
		RoundIDString: "test_dedup_legacy_token_1-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response1 := ProcessAuction(mockAttester, req1, keyManager)

	// Accepted despite carrying a token.
	check.True(t, response1.Success)
	check.Equal(t, []core.ExcludedBid{}, response1.ExcludedBids)

	// Byte-identical replay of the token-carrying bid is still deduped.
	req2 := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_dedup_legacy_token_2",
		RoundIDString: "test_dedup_legacy_token_2-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Timestamp:     time.Now(),
	}
	response2 := ProcessAuction(mockAttester, req2, keyManager)

	check.True(t, response2.Success)
	check.Equal(t, 1, len(response2.ExcludedBids))
	check.Equal(t, "bid1", response2.ExcludedBids[0].BidID)
	check.Equal(t, "duplicate_ciphertext", response2.ExcludedBids[0].Reason)
}

// TestProcessAuction_UnencryptedNotDeduped verifies plaintext bids are never
// subject to ciphertext dedup (no encrypted price to fingerprint).
func TestProcessAuction_UnencryptedNotDeduped(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_unencrypted_no_dedup",
		RoundIDString: "test_unencrypted_no_dedup-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 2.50, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "bid2", Bidder: "bidder2", Price: 2.50, Currency: "USD"}},
		},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager)

	check.True(t, response.Success)
	check.Equal(t, []core.ExcludedBid{}, response.ExcludedBids)
}

// roundTripStdEncodedPrice decodes each field and re-encodes it with standard
// base64, yielding a fresh string that still decodes to identical bytes and
// remains decryptable by the enclave. Test-only helper.
func roundTripStdEncodedPrice(t *testing.T, enc *enclaveapi.EncryptedBidPrice) *enclaveapi.EncryptedBidPrice {
	t.Helper()
	roundTrip := func(std string) string {
		raw, err := base64.StdEncoding.DecodeString(std)
		assert.NoError(t, err)
		return base64.StdEncoding.EncodeToString(raw)
	}
	return &enclaveapi.EncryptedBidPrice{
		AESKeyEncrypted:  roundTrip(enc.AESKeyEncrypted),
		EncryptedPayload: roundTrip(enc.EncryptedPayload),
		Nonce:            roundTrip(enc.Nonce),
		HashAlgorithm:    enc.HashAlgorithm,
	}
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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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

	response := ProcessAuction(mockAttester, req, nil)

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
