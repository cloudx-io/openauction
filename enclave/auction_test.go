package main

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
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

	// No winner/runner-up means no bidder identity to echo
	check.Equal(t, "", response.WinnerBidder)
	check.Equal(t, "", response.RunnerUpBidder)

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

	// Winner identity is echoed on the response envelope; no runner-up to echo
	check.Equal(t, "bidder_a", response.WinnerBidder)
	check.Equal(t, "", response.RunnerUpBidder)

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

	// Both identities are echoed on the response envelope
	check.Equal(t, "bidder_b", response.WinnerBidder)
	check.Equal(t, "bidder_a", response.RunnerUpBidder)

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

	// Echoed identities follow the adjusted ranking
	check.Equal(t, "bidder_b", response.WinnerBidder)
	check.Equal(t, "bidder_a", response.RunnerUpBidder)

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

func TestBidderOf(t *testing.T) {
	bid := &core.CoreBid{
		ID:     "test_bid",
		Bidder: "test_bidder",
		Price:  1.50,
	}

	check.Equal(t, "test_bidder", bidderOf(bid))
	check.Equal(t, "", bidderOf(nil))
}

// TestProcessAuction_RejectionsQualifiedByBidder: two bidders share a bid ID and
// only one is below floor. The response must name the rejected bidder, because
// the ID alone also belongs to the winner.
func TestProcessAuction_RejectionsQualifiedByBidder(t *testing.T) {
	const sharedBidID = "1"

	mockAttester := CreateMockEnclave(t)
	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_qualified_rejections",
		RoundIDString: "test_auction_qualified_rejections-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: sharedBidID, Bidder: "aaa_bidder", Price: 2.26, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: sharedBidID, Bidder: "zzz_bidder", Price: 0.10, Currency: "USD"}},
			{CoreBid: core.CoreBid{ID: "2", Bidder: "mmm_bidder", Price: 0.0, Currency: "USD"}},
		},
		BidFloor:  1.00,
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, nil)
	assert.True(t, response.Success)

	check.Equal(t, "aaa_bidder", response.WinnerBidder)
	check.Equal(t, []core.BidRef{{BidID: sharedBidID, Bidder: "zzz_bidder"}}, response.FloorRejected)
	check.Equal(t, []core.BidRef{{BidID: "2", Bidder: "mmm_bidder"}}, response.PriceRejected)

	// The deprecated ID-only field still ships for older hosts, and on its own
	// reports the floor rejection under the winner's bid ID.
	//nolint:staticcheck // asserts the deprecated field still ships for older hosts
	check.Equal(t, []string{sharedBidID}, response.FloorRejectedBidIDs)
}

// TestProcessAuction_ExcludedBidCarriesBidder: an excluded bid names its bidder,
// so a host never has to guess which seat lost a bid to exclusion.
func TestProcessAuction_ExcludedBidCarriesBidder(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	bid := encryptPriceBid(t, keyManager, "1", "zzz_bidder", `{"price": 3.00}`)
	newReq := func(id string) enclaveapi.EnclaveAuctionRequest {
		return enclaveapi.EnclaveAuctionRequest{
			Type:          "auction_request",
			AuctionID:     id,
			RoundIDString: id + "-1",
			// A plaintext bid from another bidder reuses the encrypted bid's ID,
			// so attributing the exclusion by ID alone would be ambiguous.
			Bids: []enclaveapi.EncryptedCoreBid{
				bid,
				{CoreBid: core.CoreBid{ID: "1", Bidder: "aaa_bidder", Price: 1.00, Currency: "USD"}},
			},
			Timestamp: time.Now(),
		}
	}

	assert.True(t, ProcessAuction(mockAttester, newReq("test_excluded_bidder_1"), keyManager).Success)

	// Replaying the identical ciphertext excludes it as a duplicate.
	response := ProcessAuction(mockAttester, newReq("test_excluded_bidder_2"), keyManager)

	assert.True(t, response.Success)
	assert.Equal(t, 1, len(response.ExcludedBids))
	check.Equal(t, core.ExcludedBid{
		BidID:  "1",
		Bidder: "zzz_bidder",
		Reason: reasonDuplicateCiphertext,
	}, response.ExcludedBids[0])
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

// TestDedupAndBuildBids_DecryptedButEpochlessExcluded verifies fail-closed
// behavior: a bid that carries an EncryptedPrice (so it was decrypted) but
// resolves to no epoch is excluded rather than passed through un-fingerprinted,
// which would silently drop replay protection. It is reported as
// fingerprint_failed since decryption itself succeeded.
func TestDedupAndBuildBids_DecryptedButEpochlessExcluded(t *testing.T) {
	// A decrypted bid (non-nil payload, non-nil EncryptedPrice) with no epoch.
	decrypted := []decryptedBidData{
		{
			encBid: enclaveapi.EncryptedCoreBid{
				CoreBid:        core.CoreBid{ID: "bid1", Bidder: "bidder1", Currency: "USD"},
				EncryptedPrice: encPrice([]byte("aeskey"), []byte("payload"), []byte("nonce123")),
			},
			payload: &decryptedBidPayload{Price: new(5.50)},
			epoch:   nil,
		},
	}

	unencrypted, excluded := dedupAndBuildBids(decrypted)

	check.Equal(t, 0, len(unencrypted))
	check.Equal(t, 1, len(excluded))
	check.Equal(t, "bid1", excluded[0].BidID)
	check.Equal(t, "fingerprint_failed", excluded[0].Reason)
}

// TestDedupAndBuildBids_FingerprintFailureExcluded verifies that when a
// decrypted bid's ciphertext cannot be fingerprinted (invalid base64 in the
// encrypted fields), it is excluded with the distinct fingerprint_failed reason
// rather than decryption_failed — decryption had already succeeded.
func TestDedupAndBuildBids_FingerprintFailureExcluded(t *testing.T) {
	decrypted := []decryptedBidData{
		{
			encBid: enclaveapi.EncryptedCoreBid{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Currency: "USD"},
				EncryptedPrice: &enclaveapi.EncryptedBidPrice{
					AESKeyEncrypted:  "not valid base64 !!!",
					EncryptedPayload: "dGVzdA==",
					Nonce:            "dGVzdA==",
				},
			},
			payload: &decryptedBidPayload{Price: new(5.50)},
			epoch:   &keyEpoch{},
		},
	}

	unencrypted, excluded := dedupAndBuildBids(decrypted)

	check.Equal(t, 0, len(unencrypted))
	check.Equal(t, 1, len(excluded))
	check.Equal(t, "bid1", excluded[0].BidID)
	check.Equal(t, "fingerprint_failed", excluded[0].Reason)
}

// TestDedupAndBuildBids_PlaintextEpochlessPassesThrough verifies the fail-closed
// change does not affect genuine plaintext bids: a bid with no EncryptedPrice
// (and thus no epoch) is still passed through un-fingerprinted.
func TestDedupAndBuildBids_PlaintextEpochlessPassesThrough(t *testing.T) {
	decrypted := []decryptedBidData{
		{
			encBid: enclaveapi.EncryptedCoreBid{
				CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder1", Price: 2.50, Currency: "USD"},
				// No EncryptedPrice: a real plaintext bid.
			},
			payload: nil,
			epoch:   nil,
		},
	}

	unencrypted, excluded := dedupAndBuildBids(decrypted)

	check.Equal(t, 0, len(excluded))
	check.Equal(t, 1, len(unencrypted))
	check.Equal(t, "bid1", unencrypted[0].ID)
	check.Equal(t, 2.50, unencrypted[0].Price)
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

// TestProcessAuction_ZeroBidOnListedDeal: a zero bid naming a listed deal wins,
// and the attestation records the round's deals verbatim.
func TestProcessAuction_ZeroBidOnListedDeal(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	deals := []core.Deal{{ID: "deal-1", BidFloor: 0}, {ID: "deal-2", BidFloor: 1.50}}

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_zero_deal_bid",
		RoundIDString: "test_auction_zero_deal_bid-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 0, Currency: "USD", DealID: "deal-1"}},
		},
		BidFloor:  0.50,
		Deals:     deals,
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, nil)

	attestationDoc := validateSuccessfulResponse(t, response, req, 1)
	check.Equal(t, deals, attestationDoc.UserData.Deals)
	if check.NotNil(t, attestationDoc.UserData.Winner) {
		check.Equal(t, "bid1", attestationDoc.UserData.Winner.ID)
		check.Equal(t, 0.0, attestationDoc.UserData.Winner.Price)
		check.Equal(t, "deal-1", attestationDoc.UserData.Winner.DealID)
	}
	check.Equal(t, "bidder_a", response.WinnerBidder)
	check.Equal(t, 0, len(response.PriceRejected))
}

// TestProcessAuction_ZeroBidWithoutDeals: the same bid in a round that lists no
// deals is a price reject, and the attestation carries no deals field.
func TestProcessAuction_ZeroBidWithoutDeals(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_zero_bid_no_deals",
		RoundIDString: "test_auction_zero_bid_no_deals-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 0, Currency: "USD", DealID: "deal-1"}},
		},
		BidFloor:  0.50,
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, nil)

	attestationDoc := validateSuccessfulResponse(t, response, req, 1)
	check.Nil(t, attestationDoc.UserData.Winner)
	check.Equal(t, []core.BidRef{{BidID: "bid1", Bidder: "bidder_a"}}, response.PriceRejected)

	coseBytes, err := response.AttestationCOSEBase64.Decode()
	assert.NoError(t, err)
	_, userData, err := coseBytes.ParseAttestationDoc()
	assert.NoError(t, err)
	check.False(t, strings.Contains(string(userData), `"deals"`))
}

// TestProcessAuction_EncryptedZeroBidOnListedDeal: the price rule applies to
// the decrypted price, so an encrypted bid that decrypts to zero on a listed
// deal wins.
func TestProcessAuction_EncryptedZeroBidOnListedDeal(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)

	bid := encryptPriceBid(t, keyManager, "bid1", "bidder_a", `{"price": 0}`)
	bid.DealID = "deal-1"

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_encrypted_zero_deal_bid",
		RoundIDString: "test_auction_encrypted_zero_deal_bid-1",
		Bids:          []enclaveapi.EncryptedCoreBid{bid},
		Deals:         []core.Deal{{ID: "deal-1", BidFloor: 0}},
		Timestamp:     time.Now(),
	}

	response := ProcessAuction(mockAttester, req, keyManager)

	attestationDoc := validateSuccessfulResponse(t, response, req, 1)
	if check.NotNil(t, attestationDoc.UserData.Winner) {
		check.Equal(t, "bid1", attestationDoc.UserData.Winner.ID)
		check.Equal(t, 0.0, attestationDoc.UserData.Winner.Price)
	}
	check.Equal(t, 0, len(response.ExcludedBids))
	check.Equal(t, 0, len(response.PriceRejected))
}

// TestProcessAuction_EncryptedPayloadWithoutPrice: a sealed payload with a
// missing or null price is excluded as malformed, not read as a zero bid, even
// when the bid names a listed zero-floor deal. An explicit zero still counts.
func TestProcessAuction_EncryptedPayloadWithoutPrice(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		excluded bool
	}{
		{name: "empty object", payload: `{}`, excluded: true},
		{name: "null payload", payload: `null`, excluded: true},
		{name: "null price", payload: `{"price":null}`, excluded: true},
		{name: "explicit zero price", payload: `{"price":0}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyManager := newTestKeyManager(t)
			bid := encryptPriceBid(t, keyManager, "bid1", "bidder_a", tt.payload)
			bid.DealID = "deal-1"

			req := enclaveapi.EnclaveAuctionRequest{
				Type:          "auction_request",
				AuctionID:     "test_auction_payload_without_price",
				RoundIDString: "test_auction_payload_without_price-1",
				Bids:          []enclaveapi.EncryptedCoreBid{bid},
				Deals:         []core.Deal{{ID: "deal-1", BidFloor: 0}},
				Timestamp:     time.Now(),
			}

			response := ProcessAuction(CreateMockEnclave(t), req, keyManager)

			attestationDoc := validateSuccessfulResponse(t, response, req, 1)
			check.Equal(t, 0, len(response.PriceRejected))
			if tt.excluded {
				check.Nil(t, attestationDoc.UserData.Winner)
				check.Equal(t, []core.ExcludedBid{{BidID: "bid1", Bidder: "bidder_a", Reason: reasonInvalidPayloadFormat}}, response.ExcludedBids)
			} else if check.NotNil(t, attestationDoc.UserData.Winner) {
				check.Equal(t, "bid1", attestationDoc.UserData.Winner.ID)
				check.Equal(t, 0, len(response.ExcludedBids))
			}
		})
	}
}

// TestProcessAuction_InvalidDealsRejected: a deal list the auction cannot apply
// unambiguously fails the request, like a negative round floor.
func TestProcessAuction_InvalidDealsRejected(t *testing.T) {
	tests := []struct {
		name    string
		deals   []core.Deal
		message string
	}{
		{name: "empty ID", deals: []core.Deal{{ID: ""}}, message: "Invalid deals: deal 0 has an empty id"},
		{name: "negative floor", deals: []core.Deal{{ID: "deal-1", BidFloor: -1}}, message: `Invalid deals: deal "deal-1" has negative floor -1.0000`},
		{name: "repeated ID", deals: []core.Deal{{ID: "deal-1"}, {ID: "deal-1"}}, message: `Invalid deals: deal "deal-1" is listed twice`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := enclaveapi.EnclaveAuctionRequest{
				Type:          "auction_request",
				AuctionID:     "test_auction_invalid_deals",
				RoundIDString: "test_auction_invalid_deals-1",
				Bids: []enclaveapi.EncryptedCoreBid{
					{CoreBid: core.CoreBid{ID: "bid1", Bidder: "bidder_a", Price: 1.00, Currency: "USD", DealID: "deal-1"}},
				},
				Deals:     tt.deals,
				Timestamp: time.Now(),
			}

			response := ProcessAuction(CreateMockEnclave(t), req, nil)

			check.False(t, response.Success)
			check.Equal(t, tt.message, response.Message)
			check.Nil(t, parseAttestationFromResponse(t, response))
		})
	}
}

// TestProcessAuction_DealBidHashForm: a bid naming a listed deal is attested in
// the deal form, which binds its deal ID; every other bid keeps the open form.
func TestProcessAuction_DealBidHashForm(t *testing.T) {
	mockAttester := CreateMockEnclave(t)

	req := enclaveapi.EnclaveAuctionRequest{
		Type:          "auction_request",
		AuctionID:     "test_auction_deal_hash_form",
		RoundIDString: "test_auction_deal_hash_form-1",
		Bids: []enclaveapi.EncryptedCoreBid{
			{CoreBid: core.CoreBid{ID: "listed", Bidder: "bidder_a", Price: 0, Currency: "USD", DealID: "deal-1"}},
			{CoreBid: core.CoreBid{ID: "unlisted", Bidder: "bidder_b", Price: 2.00, Currency: "USD", DealID: "deal-9"}},
			{CoreBid: core.CoreBid{ID: "open", Bidder: "bidder_c", Price: 1.50, Currency: "USD"}},
		},
		Deals:     []core.Deal{{ID: "deal-1", BidFloor: 0}},
		Timestamp: time.Now(),
	}

	response := ProcessAuction(mockAttester, req, nil)

	attestationDoc := validateSuccessfulResponse(t, response, req, 3)
	hashes := attestationDoc.UserData.BidHashes
	nonce := attestationDoc.UserData.BidHashNonce
	check.True(t, slices.Contains(hashes, core.ComputeDealBidHash("listed", 0, "deal-1", nonce)))
	check.False(t, slices.Contains(hashes, core.ComputeBidHash("listed", 0, nonce)))
	check.True(t, slices.Contains(hashes, core.ComputeBidHash("unlisted", 2.00, nonce)))
	check.True(t, slices.Contains(hashes, core.ComputeBidHash("open", 1.50, nonce)))
}

// TestProcessAuction_InvalidDealsLeaveCiphertextUnrecorded: a request rejected
// for its deal list is rejected before decryption, so resubmitting the same
// sealed bid in a valid request is not a replay.
func TestProcessAuction_InvalidDealsLeaveCiphertextUnrecorded(t *testing.T) {
	mockAttester := CreateMockEnclave(t)
	keyManager := newTestKeyManager(t)
	bid := encryptPriceBid(t, keyManager, "bid1", "bidder_a", `{"price": 2.00}`)

	newReq := func(id string, deals []core.Deal) enclaveapi.EnclaveAuctionRequest {
		return enclaveapi.EnclaveAuctionRequest{
			Type:          "auction_request",
			AuctionID:     id,
			RoundIDString: id + "-1",
			Bids:          []enclaveapi.EncryptedCoreBid{bid},
			Deals:         deals,
			Timestamp:     time.Now(),
		}
	}

	rejected := ProcessAuction(mockAttester, newReq("test_invalid_deals_first", []core.Deal{{ID: ""}}), keyManager)
	check.False(t, rejected.Success)

	response := ProcessAuction(mockAttester, newReq("test_invalid_deals_retry", nil), keyManager)
	assert.True(t, response.Success)
	check.Equal(t, 0, len(response.ExcludedBids))
	check.Equal(t, "bidder_a", response.WinnerBidder)
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
