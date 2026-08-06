package core

// validateBidPrices filters bids with invalid (non-positive) prices.
// Returns valid bids and bidder-qualified references to the rejected bids.
func validateBidPrices(bids []CoreBid) (valid []CoreBid, rejected []BidRef) {
	validBids := make([]CoreBid, 0, len(bids))
	rejectedBids := make([]BidRef, 0)

	for _, bid := range bids {
		if bid.Price > 0.0 {
			validBids = append(validBids, bid)
		} else {
			rejectedBids = append(rejectedBids, BidRef{BidID: bid.ID, Bidder: bid.Bidder})
		}
	}

	return validBids, rejectedBids
}

// RunAuction executes the core auction logic: price validation → adjustment → floor enforcement → ranking.
// This function provides a unified auction implementation used by both TEE and local processing.
//
// Parameters:
//   - bids: Input bids (should already be decrypted if from TEE)
//   - adjustmentFactors: Per-bidder adjustment multipliers
//   - bidFloors: Per-bidder floor prices
//
// Returns:
//   - AuctionResult containing winner, runner-up, eligible bids, rejected bids, and full ranking
//
// Processing flow:
//  1. Validate bid prices (reject non-positive prices)
//  2. Apply bid adjustment factors (multipliers per bidder)
//  3. Enforce floor price
//  4. Rank eligible bids by price with random tie-breaking
//  5. Extract winner and runner-up from ranking
func RunAuction(
	bids []CoreBid,
	adjustmentFactors map[string]float64,
	bidFloor float64,
) *AuctionResult {
	// Step 1: Validate bid prices
	validBids, priceRejected := validateBidPrices(bids)

	// Step 2: Apply bid adjustment factors
	adjustedBids := validBids
	if len(adjustmentFactors) > 0 {
		adjustedBids = ApplyBidAdjustmentFactors(validBids, adjustmentFactors)
	}

	// Step 3: Enforce floor price
	eligibleBids, floorRejected := EnforceBidFloor(adjustedBids, bidFloor)

	// Step 4: Rank eligible bids by price with random tie-breaking
	ranking := RankCoreBids(eligibleBids, defaultRandSource)

	// Step 5: Extract winner and runner-up from ranking
	var winner, runnerUp *CoreBid
	if len(ranking.SortedBidders) > 0 {
		winner = ranking.HighestBids[ranking.SortedBidders[0]]
	}
	if len(ranking.SortedBidders) > 1 {
		runnerUp = ranking.HighestBids[ranking.SortedBidders[1]]
	}

	return &AuctionResult{
		Winner:              winner,
		RunnerUp:            runnerUp,
		EligibleBids:        eligibleBids,
		PriceRejected:       priceRejected,
		FloorRejected:       floorRejected,
		PriceRejectedBidIDs: bidRefIDs(priceRejected),
		FloorRejectedBidIDs: bidRefIDs(floorRejected),
	}
}
