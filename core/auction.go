package core

// RunAuction executes the core auction logic: adjustment → floor enforcement → ranking.
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
//  1. Apply bid adjustment factors (multipliers per bidder)
//  2. Enforce per-bidder floor prices
//  3. Rank eligible bids by price
//  4. Extract winner and runner-up from ranking
func RunAuction(
	bids []CoreBid,
	adjustmentFactors map[string]float64,
	bidFloors map[string]float64,
) *AuctionResult {
	// Step 1: Apply bid adjustment factors
	// Use conversion rate of 1.0 (no currency conversion in unified logic)
	adjustedBids := bids
	if len(adjustmentFactors) > 0 {
		adjustedBids = ApplyBidAdjustmentFactors(bids, adjustmentFactors, 1.0)
	}

	// Step 2: Enforce per-bidder floor prices
	eligibleBids, rejectedBids := EnforceBidFloors(adjustedBids, bidFloors)

	// Step 3: Rank eligible bids
	ranking := RankCoreBids(eligibleBids)

	// Step 4: Extract winner and runner-up from ranking
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
		FloorRejectedBidIDs: rejectedBids,
	}
}

// RunAuction executes the core auction logic: adjustment → floor enforcement → ranking.
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
//  1. Apply bid adjustment factors (multipliers per bidder)
//  2. Enforce floor price
//  3. Rank eligible bids by price
//  4. Extract winner and runner-up from ranking
func RunAuctionSingleBidFloor(
	bids []CoreBid,
	adjustmentFactors map[string]float64,
	bidFloor float64,
) *AuctionResult {
	// Step 1: Apply bid adjustment factors
	// Use conversion rate of 1.0 (no currency conversion in unified logic)
	adjustedBids := bids
	if len(adjustmentFactors) > 0 {
		adjustedBids = ApplyBidAdjustmentFactors(bids, adjustmentFactors, 1.0)
	}

	// Step 2: Enforce per-bidder floor prices
	eligibleBids, rejectedBids := EnforceBidFloor(adjustedBids, bidFloor)

	// Step 3: Rank eligible bids
	ranking := RankCoreBids(eligibleBids)

	// Step 4: Extract winner and runner-up from ranking
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
		FloorRejectedBidIDs: rejectedBids,
	}
}
