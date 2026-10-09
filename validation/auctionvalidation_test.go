package validation

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/peterldowns/testy/check"

	"github.com/cloudx-io/openauction/core"
	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
)

func TestValidateDeals(t *testing.T) {
	tests := []struct {
		name      string
		requested []core.Deal
		dealID    string // the deal the bid names
		attested  []core.Deal
		valid     bool
		detail    string // one detail the check must report
	}{
		{
			name:   "no deals on either side",
			valid:  true,
			detail: "Deals validation passed: no deals in the bid request",
		},
		{
			name:      "every requested deal attested with its floor, in any order",
			requested: []core.Deal{{ID: "deal-1", BidFloor: 0}, {ID: "deal-2", BidFloor: 1.50}},
			attested:  []core.Deal{{ID: "deal-2", BidFloor: 1.50}, {ID: "deal-1", BidFloor: 0}},
			valid:     true,
			detail:    `Deal "deal-2" validation passed: floor 1.500000`,
		},
		{
			name:      "floor mismatch",
			requested: []core.Deal{{ID: "deal-1", BidFloor: 0}},
			attested:  []core.Deal{{ID: "deal-1", BidFloor: 0.50}},
			valid:     false,
			detail:    `Deal "deal-1" floor mismatch: expected 0.000000, attestation has 0.500000`,
		},
		{
			name:      "requested deal missing from an attestation without deals",
			requested: []core.Deal{{ID: "deal-1", BidFloor: 0}},
			valid:     false,
			detail:    `Deal "deal-1" NOT found in attestation`,
		},
		{
			name:      "attested deal the bidder was not sent is reported, not failed",
			requested: []core.Deal{{ID: "deal-1", BidFloor: 0}},
			attested:  []core.Deal{{ID: "deal-1", BidFloor: 0}, {ID: "deal-2", BidFloor: 2}},
			valid:     true,
			detail:    `Attestation lists deal "deal-2" (floor 2.000000), which is not in the bid request`,
		},
		{
			name:     "bid names an attested deal its request did not list",
			dealID:   "deal-1",
			attested: []core.Deal{{ID: "deal-1", BidFloor: 5.00}},
			valid:    false,
			detail:   `Bid names deal "deal-1", which the bid request did not list, but the attestation holds it to floor 5.000000`,
		},
		{
			name:   "bid names a deal neither sent nor attested",
			dealID: "deal-9",
			valid:  true,
			detail: "Deals validation passed: no deals in the bid request",
		},
		{
			name:     "attested deals with none in the bid request",
			attested: []core.Deal{{ID: "deal-1", BidFloor: 0}},
			valid:    true,
			detail:   `Attestation lists deal "deal-1" (floor 0.000000), which is not in the bid request`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &AuctionValidationInput{Deals: tt.requested, DealID: tt.dealID}
			attestation := &enclaveapi.AuctionAttestationDoc{
				UserData: &enclaveapi.AuctionAttestationUserData{Deals: tt.attested},
			}
			result := &AuctionValidationResult{}

			check.Equal(t, tt.valid, validateDeals(input, attestation, result))
			check.In(t, tt.detail, result.ValidationDetails)
		})
	}
}

func TestAuctionValidationResult_IsValidRequiresDeals(t *testing.T) {
	result := AuctionValidationResult{
		BaseValidationResult: BaseValidationResult{PCRsValid: true, CertificateValid: true, SignatureValid: true},
		BidHashValid:         true,
		ClearingPriceValid:   true,
		BidFloorValid:        true,
		AdjustmentHashValid:  true,
		WinnerValid:          true,
	}
	check.False(t, result.IsValid())

	result.DealsValid = true
	check.True(t, result.IsValid())
}

// TestValidateBidHash_DealForms: the bid hash binds the deal label the enclave
// applied, so a host that adds, strips or swaps a listed deal on a bid leaves
// that bid's hash missing, and the details name the form that was found.
func TestValidateBidHash_DealForms(t *testing.T) {
	const nonce = "nonce-1"
	listed := []core.Deal{{ID: "deal-1", BidFloor: 0}, {ID: "deal-2", BidFloor: 0}}

	tests := []struct {
		name         string
		sentDealID   string // bid.dealid in the bidder's response
		attestedHash string // what the enclave hashed
		deals        []core.Deal
		valid        bool
		detail       string
	}{
		{
			name:         "open bid, open form",
			attestedHash: core.ComputeBidHash("bid-1", 0.50, nonce),
			deals:        listed,
			valid:        true,
		},
		{
			name:         "listed deal bid, deal form",
			sentDealID:   "deal-1",
			attestedHash: core.ComputeDealBidHash("bid-1", 0.50, "deal-1", nonce),
			deals:        listed,
			valid:        true,
		},
		{
			name:         "unlisted deal bid, open form",
			sentDealID:   "deal-9",
			attestedHash: core.ComputeBidHash("bid-1", 0.50, nonce),
			deals:        listed,
			valid:        true,
		},
		{
			name:         "host attached a listed deal to an open bid",
			attestedHash: core.ComputeDealBidHash("bid-1", 0.50, "deal-1", nonce),
			deals:        listed,
			valid:        false,
			detail:       `Bid hash found in deal form for "deal-1": enclave applied a deal this bid did not name`,
		},
		{
			name:         "host stripped the listed deal from a deal bid",
			sentDealID:   "deal-1",
			attestedHash: core.ComputeBidHash("bid-1", 0.50, nonce),
			deals:        listed,
			valid:        false,
			detail:       `Bid hash found in open form: enclave did not honour deal "deal-1"`,
		},
		{
			name:         "host swapped one listed deal for another",
			sentDealID:   "deal-1",
			attestedHash: core.ComputeDealBidHash("bid-1", 0.50, "deal-2", nonce),
			deals:        listed,
			valid:        false,
			detail:       `Bid hash found in deal form for "deal-2": enclave applied a deal this bid did not name`,
		},
		{
			// The bid hash matches; the deals check is what catches this.
			name:         "host de-listed the deal the bid named",
			sentDealID:   "deal-1",
			attestedHash: core.ComputeBidHash("bid-1", 0.50, nonce),
			valid:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &AuctionValidationInput{BidID: "bid-1", BidPrice: 0.50, DealID: tt.sentDealID}
			attestation := &enclaveapi.AuctionAttestationDoc{UserData: &enclaveapi.AuctionAttestationUserData{
				BidHashNonce: nonce,
				BidHashes:    []string{core.ComputeBidHash("other-bid", 1.00, nonce), tt.attestedHash},
				Deals:        tt.deals,
			}}
			result := &AuctionValidationResult{}

			check.Equal(t, tt.valid, validateBidHash(input, attestation, result))
			if tt.detail != "" {
				check.In(t, tt.detail, result.ValidationDetails)
			}
		})
	}
}

// TestValidateAuctionUserData: every auction check is recorded on the result,
// including the deals check, and missing user data fails them all.
func TestValidateAuctionUserData(t *testing.T) {
	const bidNonce, factorsNonce = "bid-nonce", "factors-nonce"
	clearingPrice := 0.0
	factors := map[string]float64{"bidder_a": 1.0}
	deals := []core.Deal{{ID: "deal-1", BidFloor: 0}}

	input := &AuctionValidationInput{
		BidID:             "bid-1",
		BidPrice:          0,
		DealID:            "deal-1",
		BidFloor:          0.50,
		Deals:             deals,
		ClearingPrice:     &clearingPrice,
		AdjustmentFactors: factors,
		IsWinner:          true,
	}
	userData := func(deals []core.Deal) *enclaveapi.AuctionAttestationUserData {
		return &enclaveapi.AuctionAttestationUserData{
			BidHashNonce:           bidNonce,
			BidHashes:              []string{core.ComputeAttestedBidHash("bid-1", 0, "deal-1", deals, bidNonce)},
			BidFloor:               0.50,
			Deals:                  deals,
			AdjustmentFactorsNonce: factorsNonce,
			AdjustmentFactorsHash:  core.ComputeAdjustmentFactorsHash(factors, factorsNonce),
			Winner:                 &enclaveapi.CoreBidWithoutBidder{ID: "bid-1", Price: 0, DealID: "deal-1"},
		}
	}

	t.Run("zero deal bid that won", func(t *testing.T) {
		result := &AuctionValidationResult{}
		validateAuctionUserData(input, &enclaveapi.AuctionAttestationDoc{UserData: userData(deals)}, result)

		check.True(t, result.BidHashValid)
		check.True(t, result.ClearingPriceValid)
		check.True(t, result.BidFloorValid)
		check.True(t, result.DealsValid)
		check.True(t, result.AdjustmentHashValid)
		check.True(t, result.WinnerValid)
	})

	t.Run("attestation without the deal the bid request listed", func(t *testing.T) {
		result := &AuctionValidationResult{}
		validateAuctionUserData(input, &enclaveapi.AuctionAttestationDoc{UserData: userData(nil)}, result)

		check.True(t, result.BidHashValid)
		check.False(t, result.DealsValid)
	})

	t.Run("missing user data", func(t *testing.T) {
		result := &AuctionValidationResult{DealsValid: true}
		validateAuctionUserData(input, &enclaveapi.AuctionAttestationDoc{}, result)

		check.False(t, result.BidHashValid)
		check.False(t, result.DealsValid)
		check.In(t, "Attestation user data missing", result.ValidationDetails)
	})
}

func TestValidateWinnerAndRunnerUp_WinnerDealID(t *testing.T) {
	tests := []struct {
		name         string
		sentDealID   string
		winnerDealID string
		valid        bool
	}{
		{name: "open bid won open", valid: true},
		{name: "deal bid won with its deal", sentDealID: "deal-1", winnerDealID: "deal-1", valid: true},
		{name: "host added a deal to the winner", winnerDealID: "deal-1", valid: false},
		{name: "host changed the winner's deal", sentDealID: "deal-1", winnerDealID: "deal-2", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &AuctionValidationInput{BidID: "bid-1", DealID: tt.sentDealID, IsWinner: true}
			attestation := &enclaveapi.AuctionAttestationDoc{UserData: &enclaveapi.AuctionAttestationUserData{
				Winner: &enclaveapi.CoreBidWithoutBidder{ID: "bid-1", DealID: tt.winnerDealID},
			}}
			result := &AuctionValidationResult{}

			check.Equal(t, tt.valid, validateWinnerAndRunnerUp(input, attestation, result))
		})
	}
}

// TestValidateDeals_BidDealNotInRequest: a host that lists, at a high floor, a
// deal ID the bid names but was never sent can floor-reject the bid while its
// hash and floor still validate; the deals check is what catches it.
func TestValidateDeals_BidDealNotInRequest(t *testing.T) {
	const nonce = "abcd"
	hostDeals := []core.Deal{{ID: "X", BidFloor: 5.00}}
	bids := []core.CoreBid{{ID: "bid-1", Bidder: "b", Price: 1.00, DealID: "X"}}
	res := core.RunAuction(bids, nil, 0.50, hostDeals...)
	check.Nil(t, res.Winner)
	check.Equal(t, 1, len(res.FloorRejected))

	att := &enclaveapi.AuctionAttestationDoc{UserData: &enclaveapi.AuctionAttestationUserData{
		BidFloor:     0.50,
		Deals:        hostDeals,
		BidHashNonce: nonce,
		BidHashes:    []string{core.ComputeAttestedBidHash("bid-1", 1.00, "X", hostDeals, nonce)},
	}}
	input := &AuctionValidationInput{BidID: "bid-1", BidPrice: 1.00, DealID: "X", BidFloor: 0.50}
	result := &AuctionValidationResult{}

	check.True(t, validateBidHash(input, att, result))
	check.True(t, validateBidFloor(input, att, result))
	check.False(t, validateDeals(input, att, result))
}

// fakeAttestationCOSE wraps userData in the Nitro COSE_Sign1 layout that
// ParseAttestationDoc reads; userData nil omits the field.
func fakeAttestationCOSE(t *testing.T, userData []byte) enclaveapi.AttestationCOSEBase64 {
	t.Helper()
	doc := map[string]any{"module_id": "test-enclave"}
	if userData != nil {
		doc["user_data"] = userData
	}
	nested, err := cbor.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	coseBytes, err := cbor.Marshal([]any{[]byte{}, map[string]any{}, nested, []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	return enclaveapi.AttestationCOSE(coseBytes).EncodeBase64()
}

// TestParseAuctionAttestationFromCOSE_UserData: an attestation without user
// data parses with nil UserData, so validation reports it as missing.
func TestParseAuctionAttestationFromCOSE_UserData(t *testing.T) {
	for name, userData := range map[string][]byte{"absent": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			att, err := parseAuctionAttestationFromCOSE(fakeAttestationCOSE(t, userData))
			if !check.NoError(t, err) {
				return
			}
			check.Nil(t, att.UserData)

			result := &AuctionValidationResult{}
			validateAuctionUserData(&AuctionValidationInput{}, att, result)
			check.In(t, "Attestation user data missing", result.ValidationDetails)
		})
	}

	t.Run("present", func(t *testing.T) {
		att, err := parseAuctionAttestationFromCOSE(fakeAttestationCOSE(t, []byte(`{"bid_hash_nonce":"n"}`)))
		if !check.NoError(t, err) || !check.NotNil(t, att.UserData) {
			return
		}
		check.Equal(t, "n", att.UserData.BidHashNonce)
	})

	t.Run("malformed document", func(t *testing.T) {
		_, err := parseAuctionAttestationFromCOSE(enclaveapi.AttestationCOSE{0xff}.EncodeBase64())
		if check.Error(t, err) {
			check.True(t, strings.HasPrefix(err.Error(), "parse attestation document: "))
		}
	})
}
