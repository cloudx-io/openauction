package core

import (
	"testing"

	"github.com/peterldowns/testy/assert"
	"github.com/peterldowns/testy/check"
)

func TestApplyBidAdjustmentFactors(t *testing.T) {
	tests := []struct {
		name              string
		bids              []CoreBid
		adjustmentFactors map[string]float64
		expectedPrices    map[string]float64
	}{
		{
			name: "Basic adjustment factors",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_a", Price: 2.00, Currency: "USD"},
				{ID: "bid2", Bidder: "bidder_b", Price: 1.50, Currency: "USD"},
				{ID: "bid3", Bidder: "bidder_c", Price: 3.00, Currency: "USD"},
			},
			adjustmentFactors: map[string]float64{
				"bidder_a": 1.0,
				"bidder_b": 0.9,
				"bidder_c": 1.1,
			},
			expectedPrices: map[string]float64{
				"bidder_a": 2.00, // 2.00 (no adjustment)
				"bidder_b": 1.35, // 1.50 * 0.9
				"bidder_c": 3.30, // 3.00 * 1.1
			},
		},
		{
			name: "Case-insensitive bidder matching",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "Bidder_A", Price: 2.00, Currency: "USD"},
				{ID: "bid2", Bidder: "BIDDER_B", Price: 1.50, Currency: "USD"},
			},
			adjustmentFactors: map[string]float64{
				"bidder_a": 1.2,
				"bidder_b": 0.8,
			},
			expectedPrices: map[string]float64{
				"Bidder_A": 2.40, // 2.00 * 1.2
				"BIDDER_B": 1.20, // 1.50 * 0.8
			},
		},
		{
			name: "No adjustment factors",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_a", Price: 2.00, Currency: "USD"},
			},
			adjustmentFactors: map[string]float64{},
			expectedPrices: map[string]float64{
				"bidder_a": 2.00, // 2.00 (no adjustment)
			},
		},
		{
			name: "Mixed bidders with and without adjustments",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_a", Price: 2.00, Currency: "USD"},
				{ID: "bid2", Bidder: "bidder_b", Price: 1.50, Currency: "USD"},
				{ID: "bid3", Bidder: "bidder_c", Price: 3.00, Currency: "USD"},
			},
			adjustmentFactors: map[string]float64{
				"bidder_a": 1.2,
				// bidder_b has no adjustment
				"bidder_c": 0.9,
			},
			expectedPrices: map[string]float64{
				"bidder_a": 2.40, // 2.00 * 1.2
				"bidder_b": 1.50, // 1.50 (no adjustment)
				"bidder_c": 2.70, // 3.00 * 0.9
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adjustedBids := ApplyBidAdjustmentFactors(tt.bids, tt.adjustmentFactors)

			assert.Equal(t, len(adjustedBids), len(tt.bids))

			for i, adjustedBid := range adjustedBids {
				expectedPrice := tt.expectedPrices[adjustedBid.Bidder]
				check.Equal(t, expectedPrice, adjustedBid.Price)

				check.Equal(t, tt.bids[i].ID, adjustedBid.ID)
				check.Equal(t, tt.bids[i].Bidder, adjustedBid.Bidder)
				check.Equal(t, tt.bids[i].Currency, adjustedBid.Currency)
			}
		})
	}
}

func TestApplyBidAdjustmentFactorsDecimalPrecision(t *testing.T) {
	// Test with values that typically cause floating point precision issues
	tests := []struct {
		name              string
		bids              []CoreBid
		adjustmentFactors map[string]float64
		expectedPrices    map[string]float64
	}{
		{
			name: "Decimal precision test - values that cause floating point errors",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_a", Price: 2.1, Currency: "USD"},
				{ID: "bid2", Bidder: "bidder_b", Price: 3.3, Currency: "USD"},
				{ID: "bid3", Bidder: "bidder_c", Price: 1.7, Currency: "USD"},
			},
			adjustmentFactors: map[string]float64{
				"bidder_a": 1.1,  // 2.1 * 1.1 = 2.31
				"bidder_b": 0.33, // 3.3 * 0.33 = 1.089
				"bidder_c": 1.5,  // 1.7 * 1.5 = 2.55
			},
			expectedPrices: map[string]float64{
				"bidder_a": 2.31,  // Should be exact
				"bidder_b": 1.089, // Should be exact
				"bidder_c": 2.55,  // Should be exact
			},
		},
		{
			name: "Complex decimal calculations",
			bids: []CoreBid{
				{ID: "bid1", Bidder: "bidder_x", Price: 12.34, Currency: "USD"},
				{ID: "bid2", Bidder: "bidder_y", Price: 5.67, Currency: "USD"},
			},
			adjustmentFactors: map[string]float64{
				"bidder_x": 0.789, // 12.34 * 0.789 = 9.73626
				"bidder_y": 1.234, // 5.67 * 1.234 = 6.99678
			},
			expectedPrices: map[string]float64{
				"bidder_x": 9.73626, // 12.34 * 0.789
				"bidder_y": 6.99678, // 5.67 * 1.234
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adjustedBids := ApplyBidAdjustmentFactors(tt.bids, tt.adjustmentFactors)

			assert.Equal(t, len(adjustedBids), len(tt.bids))

			for _, adjustedBid := range adjustedBids {
				expectedPrice := tt.expectedPrices[adjustedBid.Bidder]
				// With decimal arithmetic, we should get exact results
				check.Equal(t, expectedPrice, adjustedBid.Price)
			}
		})
	}
}
