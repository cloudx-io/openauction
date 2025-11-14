package core

import (
	"fmt"

	"github.com/shopspring/decimal"
)

const MonetaryPrecision int32 = 4 // 4 decimal places for CPM values (0.0001 precision)

// RejectedBid represents a bid that was rejected during floor enforcement.
type RejectedBid struct {
	Bid        CoreBid
	FloorPrice float64
	Reason     string // Human-readable rejection reason
}

// BidMeetsFloor returns true if the bid price meets or exceeds the floor price.
// Uses decimal arithmetic with MonetaryPrecision to avoid floating-point errors.
func BidMeetsFloor(bidPrice, floorPrice float64) bool {
	bidPriceDecimal := decimal.NewFromFloat(bidPrice).Round(MonetaryPrecision)
	floorDecimal := decimal.NewFromFloat(floorPrice).Round(MonetaryPrecision)

	return bidPriceDecimal.GreaterThanOrEqual(floorDecimal)
}

// EnforceBidFloors filters bids based floor prices.
// Returns eligible bids and rejected bids with rejection details.
// If a bidder has no floor in the map, their bids pass without enforcement.
func EnforceBidFloors(bids []CoreBid, floor float64) (eligible []CoreBid, rejected []RejectedBid) {
	eligibleBids := make([]CoreBid, 0, len(bids))
	rejectedBids := make([]RejectedBid, 0)

	for _, bid := range bids {
		// Check if bid meets bidder-specific floor
		if BidMeetsFloor(bid.Price, floor) {
			eligibleBids = append(eligibleBids, bid)
		} else {
			// Track rejected bids with detailed rejection info
			rejectedBids = append(rejectedBids, RejectedBid{
				Bid:        bid,
				FloorPrice: floor,
				Reason:     fmt.Sprintf("Below floor: %.4f < %.4f", bid.Price, floor),
			})
		}
	}

	return eligibleBids, rejectedBids
}
