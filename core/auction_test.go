package core

import (
	"testing"

	"github.com/peterldowns/testy/check"
)

func TestRunAuction_BasicFlow(t *testing.T) {
	// Test the complete auction flow with floor enforcement and ranking
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 1.5},
		{ID: "bid3", Bidder: "bidder_c", Price: 1.0},
	}

	bidFloor := 1.5 // bidder_c bid should fail floor

	result := RunAuction(bids, bidFloor)

	// After floor enforcement: bidder_a=2.0, bidder_b=1.5 (bidder_c rejected)
	// Ranking: 1=bidder_a, 2=bidder_b

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)
	check.NotNil(t, result.RunnerUp)

	// Verify winner
	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Equal(t, 2.0, result.Winner.Price)

	// Verify runner-up
	check.Equal(t, "bidder_b", result.RunnerUp.Bidder)
	check.Equal(t, 1.5, result.RunnerUp.Price)

	// Verify eligible bids (only bidder_a and bidder_b passed floor)
	check.Equal(t, 2, len(result.EligibleBids))

	// Verify rejected bids (bidder_c failed floor)
	check.Equal(t, 1, len(result.FloorRejectedBidIDs))
	check.Equal(t, "bid3", result.FloorRejectedBidIDs[0])
}

func TestRunAuction_NoBids(t *testing.T) {
	result := RunAuction([]CoreBid{}, 0.0)

	check.NotNil(t, result)
	check.Nil(t, result.Winner)
	check.Nil(t, result.RunnerUp)
	check.Equal(t, 0, len(result.EligibleBids))
	check.Equal(t, 0, len(result.FloorRejectedBidIDs))
}

func TestRunAuction_SingleBid(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
	}

	result := RunAuction(bids, 0.0)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)
	check.Nil(t, result.RunnerUp) // Only one bid, no runner-up

	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Equal(t, 2.0, result.Winner.Price)
}

func TestRunAuction_AllBidsRejectedByFloor(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 1.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 0.5},
	}

	bidFloor := 2.0 // Both bids below floor

	result := RunAuction(bids, bidFloor)

	check.NotNil(t, result)
	check.Nil(t, result.Winner)
	check.Nil(t, result.RunnerUp)
	check.Equal(t, 0, len(result.EligibleBids))
	check.Equal(t, 2, len(result.FloorRejectedBidIDs))
}

func TestRunAuction_NoFloors(t *testing.T) {
	// Test that auction works without floor enforcement
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 0.01}, // Very low bid
	}

	result := RunAuction(bids, 0.0)

	check.NotNil(t, result)

	// Without floors, all bids are eligible
	check.Equal(t, 2, len(result.EligibleBids))
	check.Equal(t, 0, len(result.FloorRejectedBidIDs))
}

func TestRunAuction_RejectsNegativePrices(t *testing.T) {
	// Test that negative prices are rejected during price validation
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: -1.5},
	}

	result := RunAuction(bids, 0.0)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)

	// Check eligible bids
	eligibleIDs := make(map[string]bool)
	for _, bid := range result.EligibleBids {
		eligibleIDs[bid.ID] = true
	}
	check.True(t, eligibleIDs["bid1"])
	check.False(t, eligibleIDs["bid2"])

	// Check rejected bids
	check.Equal(t, "bid2", result.PriceRejectedBidIDs[0])

	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Nil(t, result.RunnerUp)
}

func TestRunAuction_RejectsZeroPrices(t *testing.T) {
	// Test that zero prices are rejected
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 0.0},
	}

	result := RunAuction(bids, 0.0)

	check.NotNil(t, result)

	// Check eligible bids
	eligibleIDs := map[string]bool{}
	for _, bid := range result.EligibleBids {
		eligibleIDs[bid.ID] = true
	}
	check.True(t, eligibleIDs["bid1"])
	check.False(t, eligibleIDs["bid2"])

	// Check rejected bids
	check.Equal(t, "bid2", result.PriceRejectedBidIDs[0])

	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Nil(t, result.RunnerUp)
}

func TestRunAuction_MixedPriceValidation(t *testing.T) {
	// Test combination of valid, negative, and zero price bids
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: -0.5},
		{ID: "bid3", Bidder: "bidder_c", Price: 0.0},
		{ID: "bid4", Bidder: "bidder_d", Price: 0.0},
		{ID: "bid5", Bidder: "bidder_e", Price: 1.5},
	}

	result := RunAuction(bids, 0.0)

	check.NotNil(t, result)

	// Check eligible bids
	eligibleIDs := map[string]bool{}
	for _, bid := range result.EligibleBids {
		eligibleIDs[bid.ID] = true
	}
	check.True(t, eligibleIDs["bid1"])
	check.True(t, eligibleIDs["bid5"])
	check.False(t, eligibleIDs["bid2"])
	check.False(t, eligibleIDs["bid3"])
	check.False(t, eligibleIDs["bid4"])

	// Check rejected bids
	rejectedIDs := map[string]bool{}
	for _, id := range result.PriceRejectedBidIDs {
		rejectedIDs[id] = true
	}
	check.True(t, rejectedIDs["bid2"])
	check.True(t, rejectedIDs["bid3"])
	check.True(t, rejectedIDs["bid4"])
}
