package core

import (
	"strings"

	"github.com/shopspring/decimal"
)

func ApplyBidAdjustmentFactors(bids []CoreBid, adjustmentFactors map[string]float64, conversionRate float64) []CoreBid {
	if conversionRate <= 0 {
		return bids
	}

	result := make([]CoreBid, len(bids))

	conversionRateDecimal := decimal.NewFromFloat(conversionRate)

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

		finalPriceDecimal := bidPriceDecimal.Mul(adjustmentFactorDecimal).Mul(conversionRateDecimal)

		// Convert back to float64
		result[i].Price, _ = finalPriceDecimal.Float64()
	}

	return result
}

func ApplySingleBidAdjustmentFactor(bidPrice float64, bidderName string, fallbackBidderName string, adjustmentFactors map[string]float64, conversionRate float64) float64 {
	if conversionRate <= 0 {
		return bidPrice
	}

	adjustmentFactor := 1.0
	if len(adjustmentFactors) > 0 {
		if givenAdjustment, ok := adjustmentFactors[strings.ToLower(bidderName)]; ok {
			adjustmentFactor = givenAdjustment
		} else if givenAdjustment, ok := adjustmentFactors[strings.ToLower(fallbackBidderName)]; ok {
			adjustmentFactor = givenAdjustment
		}
	}

	// Use decimal arithmetic for precise calculation
	bidPriceDecimal := decimal.NewFromFloat(bidPrice)
	adjustmentFactorDecimal := decimal.NewFromFloat(adjustmentFactor)
	conversionRateDecimal := decimal.NewFromFloat(conversionRate)

	finalPriceDecimal := bidPriceDecimal.Mul(adjustmentFactorDecimal).Mul(conversionRateDecimal)

	// Convert back to float64
	result, _ := finalPriceDecimal.Float64()
	return result
}
