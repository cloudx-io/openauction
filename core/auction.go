package core

// validateBidPrices filters bids with invalid prices: negative prices, and zero
// prices unless the bid names a listed deal.
// Returns valid bids and bidder-qualified references to the rejected bids.
func validateBidPrices(bids []CoreBid, deals []Deal) (valid []CoreBid, rejected []BidRef) {
	validBids := make([]CoreBid, 0, len(bids))
	rejectedBids := make([]BidRef, 0)

	for _, bid := range bids {
		bid.Price = positiveZero(bid.Price)
		_, listed := findDeal(deals, bid.DealID)
		if bid.Price > 0.0 || (bid.Price == 0.0 && listed) {
			validBids = append(validBids, bid)
		} else {
			rejectedBids = append(rejectedBids, BidRef{BidID: bid.ID, Bidder: bid.Bidder})
		}
	}

	return validBids, rejectedBids
}

// positiveZero maps -0 to +0, so a bidder's -0 is ranked and hashed as 0
// ("%.6f" formats -0 as "-0.000000").
func positiveZero(price float64) float64 {
	if price == 0 {
		return 0
	}
	return price
}

// RunAuction executes the core auction logic: price validation → adjustment → floor enforcement → ranking.
// This function provides a unified auction implementation used by both TEE and local processing.
//
// Parameters:
//   - bids: Input bids (should already be decrypted if from TEE)
//   - adjustmentFactors: Per-bidder adjustment multipliers
//   - bidFloor: The round floor
//   - deals: The deals listed on the round's impression (see Deal); none for an open auction.
//     RunAuction assumes the list passes ValidateDeals and does not check it; a
//     non-finite deal floor panics in floor enforcement.
//
// Returns:
//   - AuctionResult containing winner, runner-up, eligible bids, and rejected bids
//
// Processing flow:
//  1. Validate bid prices (reject negative prices, and zero prices unless the bid names a listed deal)
//  2. Apply bid adjustment factors (multipliers per bidder)
//  3. Enforce floors (a listed deal's floor for bids that name it, the round floor otherwise)
//  4. Rank eligible bids by price with random tie-breaking
//  5. Extract winner and runner-up from ranking
func RunAuction(
	bids []CoreBid,
	adjustmentFactors map[string]float64,
	bidFloor float64,
	deals ...Deal,
) *AuctionResult {
	// Step 1: Validate bid prices
	validBids, priceRejected := validateBidPrices(bids, deals)

	// Step 2: Apply bid adjustment factors
	adjustedBids := validBids
	if len(adjustmentFactors) > 0 {
		adjustedBids = ApplyBidAdjustmentFactors(validBids, adjustmentFactors)
	}

	// Step 3: Enforce floors
	eligibleBids, floorRejected := EnforceBidFloor(adjustedBids, bidFloor, deals...)

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
