package core

import (
	"testing"

	"github.com/peterldowns/testy/check"
)

func TestBidMeetsFloor(t *testing.T) {
	tests := []struct {
		name       string
		bidPrice   float64
		floorPrice float64
		expected   bool
	}{
		{"bid above floor", 3.0, 2.5, true},
		{"bid at floor", 2.5, 2.5, true},
		{"bid below floor", 2.0, 2.5, false},
		{"zero floor - always passes", 1.0, 0.0, true},
		{"zero floor with zero bid", 0.0, 0.0, true},
		{"zero floor with positive bid", 2.5, 0.0, true},
		{"negative bid below floor", -1.0, 2.5, false},
		{"negative bid with zero floor", -1.0, 0.0, false},
		{"decimal precision edge case - passes", 2.499999999, 2.5, true},
		{"decimal precision edge case - fails", 2.4999, 2.5, false},
		{"very small difference - passes", 2.5001, 2.5, true},
		{"very small difference - fails", 2.4999, 2.5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BidMeetsFloor(tt.bidPrice, tt.floorPrice)
			check.Equal(t, tt.expected, result)
		})
	}
}

func TestEnforceBidFloors(t *testing.T) {
	tests := []struct {
		name     string
		bids     []CoreBid
		floors   map[string]float64
		expected []CoreBid
	}{
		{
			name: "no floors - all bids pass",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 1.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 2.0},
				{ID: "bid3", Bidder: "bidder_3", Price: 0.5},
			},
			floors: map[string]float64{},
			expected: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 1.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 2.0},
				{ID: "bid3", Bidder: "bidder_3", Price: 0.5},
			},
		},
		{
			name: "same floor for all bidders - some rejected",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 3.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 2.5},
				{ID: "bid3", Bidder: "bidder_3", Price: 2.0},
			},
			floors: map[string]float64{
				"bidder_1": 2.5,
				"bidder_2": 2.5,
				"bidder_3": 2.5,
			},
			expected: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 3.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 2.5},
			},
		},
		{
			name: "per-bidder floors - different floors per bidder",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 2.75},
				{ID: "bid2", Bidder: "bidder_2", Price: 2.75},
				{ID: "bid3", Bidder: "bidder_3", Price: 1.50},
			},
			floors: map[string]float64{
				"bidder_1": 2.50, // bidder_1 passes (2.75 >= 2.50)
				"bidder_2": 3.00, // bidder_2 fails (2.75 < 3.00)
				"bidder_3": 1.00, // bidder_3 passes (1.50 >= 1.00)
			},
			expected: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 2.75},
				{ID: "bid3", Bidder: "bidder_3", Price: 1.50},
			},
		},
		{
			name: "bidder with no floor - passes",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 3.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 1.0}, // No floor for bidder_2
			},
			floors: map[string]float64{
				"bidder_1": 2.5,
				// bidder_2 not in map - should pass
			},
			expected: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 3.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 1.0},
			},
		},
		{
			name: "bidder with zero floor - passes",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 3.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 1.0},
			},
			floors: map[string]float64{
				"bidder_1": 2.5,
				"bidder_2": 0.0, // Zero floor - should pass
			},
			expected: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 3.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 1.0},
			},
		},
		{
			name: "all bids below their floors - all rejected",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_1", Price: 1.0},
				{ID: "bid2", Bidder: "bidder_2", Price: 1.5},
			},
			floors: map[string]float64{
				"bidder_1": 2.5,
				"bidder_2": 2.5,
			},
			expected: []CoreBid{},
		},
		{
			name:     "empty bids array",
			bids:     []CoreBid{},
			floors:   map[string]float64{"bidder_1": 2.5},
			expected: []CoreBid{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eligible, rejected := EnforceBidFloors(tt.bids, tt.floors)
			check.Equal(t, tt.expected, eligible)

			// Verify rejected count
			expectedRejected := len(tt.bids) - len(tt.expected)
			check.Equal(t, expectedRejected, len(rejected))
		})
	}
}

func TestEnforceBidFloors_PreservesOtherFields(t *testing.T) {
	bids := []CoreBid{
		{
			ID:       "bid1",
			Bidder:   "bidder_1",
			Price:    3.0,
			Currency: "USD",
			DealID:   "deal123",
			BidType:  "banner",
		},
		{
			ID:       "bid2",
			Bidder:   "bidder_2",
			Price:    2.0,
			Currency: "USD",
			DealID:   "",
			BidType:  "video",
		},
	}

	floors := map[string]float64{
		"bidder_1": 2.5,
		"bidder_2": 2.5,
	}

	eligible, rejected := EnforceBidFloors(bids, floors)

	check.Equal(t, 1, len(eligible))
	check.Equal(t, 1, len(rejected))

	// Verify eligible bid preserves all fields
	result := eligible
	check.Equal(t, "bid1", result[0].ID)
	check.Equal(t, "bidder_1", result[0].Bidder)
	check.Equal(t, 3.0, result[0].Price)
	check.Equal(t, "USD", result[0].Currency)
	check.Equal(t, "deal123", result[0].DealID)
	check.Equal(t, "banner", result[0].BidType)

	// Verify rejected bid ID is returned
	check.Equal(t, 1, len(rejected))
	check.Equal(t, "bid2", rejected[0])
}

func TestEnforceBidFloors_MonetaryPrecisionConsistency(t *testing.T) {
	// Test that the MonetaryPrecision constant is used correctly
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_1", Price: 2.123456},
	}

	floors := map[string]float64{
		"bidder_1": 2.1234,
	}

	eligible, rejected := EnforceBidFloors(bids, floors)

	check.Equal(t, bids, eligible)
	check.Equal(t, []string{}, rejected)
}
