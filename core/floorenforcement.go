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

// EnforceBidFloors filters bids based on per-bidder floor prices.
// Returns eligible bids and IDs of rejected bids.
// If a bidder has no floor in the map, their bids pass without enforcement.
func EnforceBidFloors(bids []CoreBid, floors map[string]float64) (eligible []CoreBid, rejectedBidIDs []string) {
	eligibleBids := make([]CoreBid, 0, len(bids))
	rejectedIDs := make([]string, 0)

	for _, bid := range bids {
		floor, hasFloor := floors[bid.Bidder]

		// If no floor for this bidder, bid passes
		if !hasFloor {
			eligibleBids = append(eligibleBids, bid)
			continue
		}

		if BidMeetsFloor(bid.Price, floor) {
			eligibleBids = append(eligibleBids, bid)
		} else {
			rejectedIDs = append(rejectedIDs, bid.ID)
		}
	}

	return eligibleBids, rejectedIDs
}
