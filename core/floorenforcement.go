package core

import (
	"github.com/shopspring/decimal"
)

const monetaryPrecision int32 = 4 // 4 decimal places for CPM values (0.0001 precision)

// BidMeetsFloor returns true if the bid price meets or exceeds the floor price.
// Uses decimal arithmetic with monetaryPrecision to avoid floating-point errors.
func BidMeetsFloor(bidPrice, floorPrice float64) bool {
	bidPriceDecimal := decimal.NewFromFloat(bidPrice).Round(monetaryPrecision)
	floorDecimal := decimal.NewFromFloat(floorPrice).Round(monetaryPrecision)

	return bidPriceDecimal.GreaterThanOrEqual(floorDecimal)
}

// EnforceBidFloors filters bids based on floor price.
// Returns eligible bids and bidder-qualified references to the rejected bids.
// If a bidder has no floor in the map, their bids pass without enforcement.
func EnforceBidFloor(bids []CoreBid, floor float64) (eligible []CoreBid, rejected []BidRef) {
	eligibleBids := make([]CoreBid, 0, len(bids))
	rejectedBids := make([]BidRef, 0)

	for _, bid := range bids {
		if BidMeetsFloor(bid.Price, floor) {
			eligibleBids = append(eligibleBids, bid)
		} else {
			rejectedBids = append(rejectedBids, BidRef{BidID: bid.ID, Bidder: bid.Bidder})
		}
	}

	return eligibleBids, rejectedBids
}
