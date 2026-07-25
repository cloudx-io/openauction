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

// EnforceBidFloor filters bids based on floor price.
// Returns eligible bids and IDs of rejected bids.
func EnforceBidFloor(bids []CoreBid, floor float64) (eligible []CoreBid, rejectedBidIDs []string) {
	eligibleBids, rejectedBids := partitionBidsByFloor(bids, floor)
	rejectedIDs := make([]string, 0, len(rejectedBids))
	for _, bid := range rejectedBids {
		rejectedIDs = append(rejectedIDs, bid.ID)
	}

	return eligibleBids, rejectedIDs
}

func partitionBidsByFloor(bids []CoreBid, floor float64) (eligible, rejected []CoreBid) {
	eligibleBids := make([]CoreBid, 0, len(bids))
	rejectedBids := make([]CoreBid, 0)

	for _, bid := range bids {
		if BidMeetsFloor(bid.Price, floor) {
			eligibleBids = append(eligibleBids, bid)
		} else {
			rejectedBids = append(rejectedBids, bid)
		}
	}

	return eligibleBids, rejectedBids
}
