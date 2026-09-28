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

// EnforceBidFloor filters bids based on floor price: a bid that names a listed
// deal must meet that deal's floor, and every other bid the round floor.
// Returns eligible bids and bidder-qualified references to the rejected bids.
func EnforceBidFloor(bids []CoreBid, floor float64, deals ...Deal) (eligible []CoreBid, rejected []BidRef) {
	eligibleBids := make([]CoreBid, 0, len(bids))
	rejectedBids := make([]BidRef, 0)

	for _, bid := range bids {
		bidFloor := floor
		if deal, ok := findDeal(deals, bid.DealID); ok {
			bidFloor = deal.BidFloor
		}
		if BidMeetsFloor(bid.Price, bidFloor) {
			eligibleBids = append(eligibleBids, bid)
		} else {
			rejectedBids = append(rejectedBids, BidRef{BidID: bid.ID, Bidder: bid.Bidder})
		}
	}

	return eligibleBids, rejectedBids
}
