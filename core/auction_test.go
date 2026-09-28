package core

import (
	"math"
	"testing"

	"github.com/peterldowns/testy/check"
)

func TestRunAuction_BasicFlow(t *testing.T) {
	// Test the complete auction flow with adjustment, floor enforcement, and ranking
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 1.5},
		{ID: "bid3", Bidder: "bidder_c", Price: 1.0},
	}

	adjustmentFactors := map[string]float64{
		"bidder_a": 1.0,
		"bidder_b": 1.2, // Boost bidder_b by 20%
		"bidder_c": 1.0,
	}

	bidFloor := 1.5 // bidder_c bid should fail floor

	result := RunAuction(bids, adjustmentFactors, bidFloor)

	// After adjustment: bidder_a=2.0, bidder_b=1.8, bidder_c=1.0
	// After floor enforcement: bidder_a=2.0, bidder_b=1.8 (bidder_c rejected)
	// Ranking: 1=bidder_a, 2=bidder_b

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)
	check.NotNil(t, result.RunnerUp)

	// Verify winner (highest bid after adjustment)
	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Equal(t, 2.0, result.Winner.Price)

	// Verify runner-up
	check.Equal(t, "bidder_b", result.RunnerUp.Bidder)
	check.Equal(t, 1.8, result.RunnerUp.Price)

	// Verify eligible bids (only bidder_a and bidder_b passed floor)
	check.Equal(t, 2, len(result.EligibleBids))

	// Verify rejected bids (bidder_c failed floor)
	check.Equal(t, 1, len(result.FloorRejectedBidIDs))
	check.Equal(t, "bid3", result.FloorRejectedBidIDs[0])
}

func TestRunAuction_NoBids(t *testing.T) {
	result := RunAuction([]CoreBid{}, nil, 0.0)

	check.NotNil(t, result)
	check.Nil(t, result.Winner)
	check.Nil(t, result.RunnerUp)
	check.Equal(t, 0, len(result.EligibleBids))
	check.Equal(t, 0, len(result.FloorRejectedBidIDs))
}

// TestRunAuction_RejectionsQualifiedByBidder: when two bidders share a bid ID
// and only one of them is rejected, the bare ID cannot say which. The
// bidder-qualified rejections can, and the winner keeps the shared ID.
func TestRunAuction_RejectionsQualifiedByBidder(t *testing.T) {
	const sharedBidID = "1"

	bids := []CoreBid{
		{ID: sharedBidID, Bidder: "aaa_bidder", Price: 2.26},
		{ID: sharedBidID, Bidder: "zzz_bidder", Price: 0.10},
		{ID: "2", Bidder: "mmm_bidder", Price: -1.0},
	}

	result := RunAuction(bids, nil, 1.00)

	check.NotNil(t, result.Winner)
	check.Equal(t, "aaa_bidder", result.Winner.Bidder)
	check.Equal(t, sharedBidID, result.Winner.ID)

	// Only zzz_bidder was below floor, even though the winner shares its bid ID.
	check.Equal(t, []BidRef{{BidID: sharedBidID, Bidder: "zzz_bidder"}}, result.FloorRejected)
	check.Equal(t, []BidRef{{BidID: "2", Bidder: "mmm_bidder"}}, result.PriceRejected)

	// The deprecated ID-only views stay populated for existing callers, and show
	// exactly the ambiguity that motivated the qualified fields: the floor
	// rejection is reported under an ID the winner also holds.
	check.Equal(t, []string{sharedBidID}, result.FloorRejectedBidIDs)
	check.Equal(t, []string{"2"}, result.PriceRejectedBidIDs)
}

func TestRunAuction_SingleBid(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
	}

	result := RunAuction(bids, nil, 0.0)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)
	check.Nil(t, result.RunnerUp) // Only one bid, no runner-up

	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Equal(t, 2.0, result.Winner.Price)
}

func TestRunAuction_AllBidsRejectedByFloor(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 1.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 0.5},
	}

	bidFloor := 2.0 // Both bids below floor

	result := RunAuction(bids, nil, bidFloor)

	check.NotNil(t, result)
	check.Nil(t, result.Winner)
	check.Nil(t, result.RunnerUp)
	check.Equal(t, 0, len(result.EligibleBids))
	check.Equal(t, 2, len(result.FloorRejectedBidIDs))
}

func TestRunAuction_NoAdjustmentFactors(t *testing.T) {
	// Test that auction works without adjustment factors
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 1.5},
	}

	result := RunAuction(bids, nil, 0.0)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)

	// Without adjustments, original ranking is preserved
	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Equal(t, 2.0, result.Winner.Price)

	// Verify runner-up
	check.NotNil(t, result.RunnerUp)
	check.Equal(t, "bidder_b", result.RunnerUp.Bidder)
	check.Equal(t, 1.5, result.RunnerUp.Price)
}

func TestRunAuction_NoFloors(t *testing.T) {
	// Test that auction works without floor enforcement
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 0.01}, // Very low bid
	}

	result := RunAuction(bids, nil, 0.0)

	check.NotNil(t, result)

	// Without floors, all bids are eligible
	check.Equal(t, 2, len(result.EligibleBids))
	check.Equal(t, 0, len(result.FloorRejectedBidIDs))
}

func TestRunAuction_AdjustmentChangesWinner(t *testing.T) {
	// Test that adjustment factors can change the auction winner
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 1.5},
	}

	adjustmentFactors := map[string]float64{
		"bidder_a": 1.0,
		"bidder_b": 1.5, // Boost bidder_b to 2.25
	}

	result := RunAuction(bids, adjustmentFactors, 0.0)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)

	// After adjustment, bidder_b should win (1.5 * 1.5 = 2.25 > 2.0)
	check.Equal(t, "bidder_b", result.Winner.Bidder)
	check.True(t, result.Winner.Price > 2.24 && result.Winner.Price < 2.26)

	check.Equal(t, "bidder_a", result.RunnerUp.Bidder)
	check.Equal(t, 2.0, result.RunnerUp.Price)
}

func TestRunAuction_PreservesOriginalBids(t *testing.T) {
	// Test that original bid slice is not modified
	originalBids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
	}

	adjustmentFactors := map[string]float64{
		"bidder_a": 2.0,
	}

	result := RunAuction(originalBids, adjustmentFactors, 0.0)

	check.NotNil(t, result)

	// Original bid should be unchanged
	check.Equal(t, 2.0, originalBids[0].Price)

	// Result should have adjusted price
	check.Equal(t, 4.0, result.Winner.Price)
}

func TestRunAuction_RejectsNegativePrices(t *testing.T) {
	// Test that negative prices are rejected during price validation
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: -1.5},
	}

	result := RunAuction(bids, nil, 0.0)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)

	// Check eligible bids
	eligibleIDs := make(map[string]bool)
	for _, bid := range result.EligibleBids {
		eligibleIDs[bid.ID] = true
	}
	check.True(t, eligibleIDs["bid1"])
	check.False(t, eligibleIDs["bid2"])

	// Check rejected bids
	check.Equal(t, "bid2", result.PriceRejectedBidIDs[0])

	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Nil(t, result.RunnerUp)
}

func TestRunAuction_RejectsZeroPrices(t *testing.T) {
	// Test that zero prices are rejected
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 0.0},
	}

	result := RunAuction(bids, nil, 0.0)

	check.NotNil(t, result)

	// Check eligible bids
	eligibleIDs := map[string]bool{}
	for _, bid := range result.EligibleBids {
		eligibleIDs[bid.ID] = true
	}
	check.True(t, eligibleIDs["bid1"])
	check.False(t, eligibleIDs["bid2"])

	// Check rejected bids
	check.Equal(t, "bid2", result.PriceRejectedBidIDs[0])

	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Nil(t, result.RunnerUp)
}

func TestRunAuction_MixedPriceValidation(t *testing.T) {
	// Test combination of valid, negative, and zero price bids
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: -0.5},
		{ID: "bid3", Bidder: "bidder_c", Price: 0.0},
		{ID: "bid4", Bidder: "bidder_d", Price: 0.0},
		{ID: "bid5", Bidder: "bidder_e", Price: 1.5},
	}

	result := RunAuction(bids, nil, 0.0)

	check.NotNil(t, result)

	// Check eligible bids
	eligibleIDs := map[string]bool{}
	for _, bid := range result.EligibleBids {
		eligibleIDs[bid.ID] = true
	}
	check.True(t, eligibleIDs["bid1"])
	check.True(t, eligibleIDs["bid5"])
	check.False(t, eligibleIDs["bid2"])
	check.False(t, eligibleIDs["bid3"])
	check.False(t, eligibleIDs["bid4"])

	// Check rejected bids
	rejectedIDs := map[string]bool{}
	for _, id := range result.PriceRejectedBidIDs {
		rejectedIDs[id] = true
	}
	check.True(t, rejectedIDs["bid2"])
	check.True(t, rejectedIDs["bid3"])
	check.True(t, rejectedIDs["bid4"])
}

func TestRunAuction_Deals(t *testing.T) {
	tests := []struct {
		name          string
		bids          []CoreBid
		factors       map[string]float64
		bidFloor      float64
		deals         []Deal
		winner        string // bid ID; empty when no bid wins
		winnerPrice   float64
		winnerDealID  string
		runnerUp      string // bid ID; empty when there is no runner-up
		priceRejected []BidRef
		floorRejected []BidRef
	}{
		{
			name:          "zero without a deal ID is a price reject",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 0}},
			deals:         []Deal{{ID: "d1"}},
			priceRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name:          "zero naming a deal is a price reject when the round lists none",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 0, DealID: "d1"}},
			priceRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name:          "zero naming an unlisted deal is a price reject",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 0, DealID: "d2"}},
			deals:         []Deal{{ID: "d1"}},
			priceRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name:          "negative naming a listed deal is a price reject",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: -1, DealID: "d1"}},
			deals:         []Deal{{ID: "d1"}},
			priceRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name:         "zero naming a listed deal at floor 0 wins alone",
			bids:         []CoreBid{{ID: "b1", Bidder: "a", Price: 0, DealID: "d1"}},
			bidFloor:     0.50,
			deals:        []Deal{{ID: "d1", BidFloor: 0}},
			winner:       "b1",
			winnerPrice:  0,
			winnerDealID: "d1",
		},
		{
			name:          "zero naming a listed deal at floor 1 is a floor reject",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 0, DealID: "d1"}},
			deals:         []Deal{{ID: "d1", BidFloor: 1.00}},
			floorRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name:         "a deal floor below the round floor admits a bid under the round floor",
			bids:         []CoreBid{{ID: "b1", Bidder: "a", Price: 0.50, DealID: "d1"}},
			bidFloor:     1.00,
			deals:        []Deal{{ID: "d1", BidFloor: 0.10}},
			winner:       "b1",
			winnerPrice:  0.50,
			winnerDealID: "d1",
		},
		{
			name:          "a deal floor above the round floor rejects a bid over the round floor",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 1.50, DealID: "d1"}},
			bidFloor:      1.00,
			deals:         []Deal{{ID: "d1", BidFloor: 2.00}},
			floorRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name:          "a bid naming an unlisted deal is held to the round floor",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 0.50, DealID: "d2"}},
			bidFloor:      1.00,
			deals:         []Deal{{ID: "d1", BidFloor: 0}},
			floorRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name: "a positive open bid outranks a zero deal bid",
			bids: []CoreBid{
				{ID: "b1", Bidder: "a", Price: 0, DealID: "d1"},
				{ID: "b2", Bidder: "b", Price: 1.20},
			},
			bidFloor:    1.00,
			deals:       []Deal{{ID: "d1", BidFloor: 0}},
			winner:      "b2",
			winnerPrice: 1.20,
			runnerUp:    "b1",
		},
		{
			name:         "an adjustment factor keeps a zero deal bid at zero",
			bids:         []CoreBid{{ID: "b1", Bidder: "a", Price: 0, DealID: "d1"}},
			factors:      map[string]float64{"a": 1.3},
			deals:        []Deal{{ID: "d1", BidFloor: 0}},
			winner:       "b1",
			winnerPrice:  0,
			winnerDealID: "d1",
		},
		{
			name:          "the deal floor applies to the adjusted price",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 1.00, DealID: "d1"}},
			factors:       map[string]float64{"a": 0.5},
			deals:         []Deal{{ID: "d1", BidFloor: 0.75}},
			floorRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name: "a bidder's zero deal bid ranks when its open bid misses the round floor",
			bids: []CoreBid{
				{ID: "b1", Bidder: "a", Price: 0, DealID: "d1"},
				{ID: "b2", Bidder: "a", Price: 0.40},
			},
			bidFloor:      0.50,
			deals:         []Deal{{ID: "d1", BidFloor: 0}},
			winner:        "b1",
			winnerPrice:   0,
			winnerDealID:  "d1",
			floorRejected: []BidRef{{BidID: "b2", Bidder: "a"}},
		},
		{
			name:          "deal IDs match exactly",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 0, DealID: "D1"}},
			deals:         []Deal{{ID: "d1", BidFloor: 0}},
			priceRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
		{
			name:          "an empty deal ID names no deal, even one listed with an empty ID",
			bids:          []CoreBid{{ID: "b1", Bidder: "a", Price: 0}},
			deals:         []Deal{{ID: "", BidFloor: 0}},
			priceRejected: []BidRef{{BidID: "b1", Bidder: "a"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RunAuction(tt.bids, tt.factors, tt.bidFloor, tt.deals...)

			if tt.winner == "" {
				check.Nil(t, result.Winner)
			} else if check.NotNil(t, result.Winner) {
				check.Equal(t, tt.winner, result.Winner.ID)
				check.Equal(t, tt.winnerPrice, result.Winner.Price)
				check.Equal(t, tt.winnerDealID, result.Winner.DealID)
			}
			if tt.runnerUp == "" {
				check.Nil(t, result.RunnerUp)
			} else if check.NotNil(t, result.RunnerUp) {
				check.Equal(t, tt.runnerUp, result.RunnerUp.ID)
			}

			check.Equal(t, orEmpty(tt.priceRejected), result.PriceRejected)
			check.Equal(t, orEmpty(tt.floorRejected), result.FloorRejected)
		})
	}
}

// TestRunAuction_ZeroDealBidsTie: two zero bids on listed deals are both
// eligible and tie; ranking orders them at random.
func TestRunAuction_ZeroDealBidsTie(t *testing.T) {
	bids := []CoreBid{
		{ID: "b1", Bidder: "a", Price: 0, DealID: "d1"},
		{ID: "b2", Bidder: "b", Price: 0, DealID: "d2"},
	}
	deals := []Deal{{ID: "d1"}, {ID: "d2"}}

	result := RunAuction(bids, nil, 0, deals...)

	check.Equal(t, 2, len(result.EligibleBids))
	check.Equal(t, []BidRef{}, result.PriceRejected)
	if check.NotNil(t, result.Winner) && check.NotNil(t, result.RunnerUp) {
		check.In(t, result.Winner.ID, []string{"b1", "b2"})
		check.NotEqual(t, result.Winner.ID, result.RunnerUp.ID)
	}
}

// orEmpty maps a nil expectation to the empty, non-nil slice RunAuction returns.
func orEmpty(refs []BidRef) []BidRef {
	if refs == nil {
		return []BidRef{}
	}
	return refs
}

// TestRunAuction_NegativeZeroDealBid: a bidder's -0 is priced as 0, so the
// winner never carries a negative zero into the attestation.
func TestRunAuction_NegativeZeroDealBid(t *testing.T) {
	bids := []CoreBid{{ID: "b1", Bidder: "a", Price: math.Copysign(0, -1), DealID: "d1"}}

	result := RunAuction(bids, nil, 0, Deal{ID: "d1"})

	if check.NotNil(t, result.Winner) {
		check.Equal(t, "b1", result.Winner.ID)
		check.False(t, math.Signbit(result.Winner.Price))
	}
}
