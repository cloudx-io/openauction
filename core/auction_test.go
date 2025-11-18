package core

import (
	"testing"

	"github.com/peterldowns/testy/check"
)

func TestRunAuction_BasicFlow(t *testing.T) {
	// Test the complete auction flow with adjustment, floor enforcement, and ranking
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 1.5},
		{ID: "bid3", Bidder: "bidder_c", Price: 1.0},
	}

	adjustmentFactors := map[string]float64{
		"bidder_a": 1.0,
		"bidder_b": 1.2, // Boost bidder_b by 20%
		"bidder_c": 1.0,
	}

	bidFloors := map[string]float64{
		"bidder_a": 1.0,
		"bidder_b": 1.0,
		"bidder_c": 1.5, // bidder_c bid should fail floor
	}

	result := RunAuction(bids, adjustmentFactors, bidFloors)

	// After adjustment: bidder_a=2.0, bidder_b=1.8, bidder_c=1.0
	// After floor enforcement: bidder_a=2.0, bidder_b=1.8 (bidder_c rejected)
	// Ranking: 1=bidder_a, 2=bidder_b

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)
	check.NotNil(t, result.RunnerUp)

	// Verify winner (highest bid after adjustment)
	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Equal(t, 2.0, result.Winner.Price)

	// Verify runner-up
	check.Equal(t, "bidder_b", result.RunnerUp.Bidder)
	check.Equal(t, 1.8, result.RunnerUp.Price)

	// Verify eligible bids (only bidder_a and bidder_b passed floor)
	check.Equal(t, 2, len(result.EligibleBids))

	// Verify rejected bids (bidder_c failed floor)
	check.Equal(t, 1, len(result.RejectedBids))
	check.Equal(t, "bidder_c", result.RejectedBids[0].Bid.Bidder)
}

func TestRunAuction_NoBids(t *testing.T) {
	result := RunAuction([]CoreBid{}, nil, nil)

	check.NotNil(t, result)
	check.Nil(t, result.Winner)
	check.Nil(t, result.RunnerUp)
	check.Equal(t, 0, len(result.EligibleBids))
	check.Equal(t, 0, len(result.RejectedBids))
}

func TestRunAuction_SingleBid(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
	}

	result := RunAuction(bids, nil, nil)

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

	bidFloors := map[string]float64{
		"bidder_a": 2.0, // Both bids below floor
		"bidder_b": 2.0,
	}

	result := RunAuction(bids, nil, bidFloors)

	check.NotNil(t, result)
	check.Nil(t, result.Winner)
	check.Nil(t, result.RunnerUp)
	check.Equal(t, 0, len(result.EligibleBids))
	check.Equal(t, 2, len(result.RejectedBids))
}

func TestRunAuction_NoAdjustmentFactors(t *testing.T) {
	// Test that auction works without adjustment factors
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 1.5},
	}

	result := RunAuction(bids, nil, nil)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)

	// Without adjustments, original ranking is preserved
	check.Equal(t, "bidder_a", result.Winner.Bidder)
	check.Equal(t, 2.0, result.Winner.Price)

	// Verify runner-up
	check.NotNil(t, result.RunnerUp)
	check.Equal(t, "bidder_b", result.RunnerUp.Bidder)
	check.Equal(t, 1.5, result.RunnerUp.Price)
}

func TestRunAuction_NoFloors(t *testing.T) {
	// Test that auction works without floor enforcement
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 0.01}, // Very low bid
	}

	result := RunAuction(bids, nil, nil)

	check.NotNil(t, result)

	// Without floors, all bids are eligible
	check.Equal(t, 2, len(result.EligibleBids))
	check.Equal(t, 0, len(result.RejectedBids))
}

func TestRunAuction_AdjustmentChangesWinner(t *testing.T) {
	// Test that adjustment factors can change the auction winner
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
		{ID: "bid2", Bidder: "bidder_b", Price: 1.5},
	}

	adjustmentFactors := map[string]float64{
		"bidder_a": 1.0,
		"bidder_b": 1.5, // Boost bidder_b to 2.25
	}

	result := RunAuction(bids, adjustmentFactors, nil)

	check.NotNil(t, result)
	check.NotNil(t, result.Winner)

	// After adjustment, bidder_b should win (1.5 * 1.5 = 2.25 > 2.0)
	check.Equal(t, "bidder_b", result.Winner.Bidder)
	check.True(t, result.Winner.Price > 2.24 && result.Winner.Price < 2.26)

	check.Equal(t, "bidder_a", result.RunnerUp.Bidder)
	check.Equal(t, 2.0, result.RunnerUp.Price)
}

func TestRunAuction_PreservesOriginalBids(t *testing.T) {
	// Test that original bid slice is not modified
	originalBids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.0},
	}

	adjustmentFactors := map[string]float64{
		"bidder_a": 2.0,
	}

	result := RunAuction(originalBids, adjustmentFactors, nil)

	check.NotNil(t, result)

	// Original bid should be unchanged
	check.Equal(t, 2.0, originalBids[0].Price)

	// Result should have adjusted price
	check.Equal(t, 4.0, result.Winner.Price)
}
