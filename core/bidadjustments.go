package core

import (
	"strings"

	"github.com/shopspring/decimal"
)

func ApplyBidAdjustmentFactors(bids []CoreBid, adjustmentFactors map[string]float64) []CoreBid {
	result := make([]CoreBid, len(bids))

	for i, bid := range bids {
		result[i] = bid

		adjustmentFactor := 1.0
		if len(adjustmentFactors) > 0 {
			if factor, exists := adjustmentFactors[strings.ToLower(bid.Bidder)]; exists && factor > 0 {
				adjustmentFactor = factor
			}
		}

		// Use decimal arithmetic for precise calculation
		bidPriceDecimal := decimal.NewFromFloat(bid.Price)
		adjustmentFactorDecimal := decimal.NewFromFloat(adjustmentFactor)

		finalPriceDecimal := bidPriceDecimal.Mul(adjustmentFactorDecimal)

		// Convert back to float64
		result[i].Price, _ = finalPriceDecimal.Float64()
	}

	return result
}
