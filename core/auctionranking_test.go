package core

import (
	"testing"

	"github.com/peterldowns/testy/check"
)

// mockRandSource provides a deterministic random source for testing
type mockRandSource struct {
	sequence []int
	index    int
}

func (m *mockRandSource) Intn(n int) int {
	if m.index >= len(m.sequence) {
		return 0
	}
	val := m.sequence[m.index] % n
	m.index++
	return val
}

func TestRankCoreBids_Integration(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid_a_001", Bidder: "bidder_a", Price: 2.50},
		{ID: "bid_b_001", Bidder: "bidder_b", Price: 2.25},
		{ID: "bid_c_001", Bidder: "bidder_c", Price: 2.75},
	}

	rankingResult := RankCoreBids(bids, nil)

	check.Equal(t, 3, len(rankingResult.SortedBidders))
	check.Equal(t, "bidder_c", rankingResult.SortedBidders[0]) // Highest (2.75)
	check.Equal(t, "bidder_a", rankingResult.SortedBidders[1]) // Middle (2.50)
	check.Equal(t, "bidder_b", rankingResult.SortedBidders[2]) // Lowest (2.25)

	check.Equal(t, 2.75, rankingResult.HighestBids["bidder_c"].Price)
	check.Equal(t, 2.50, rankingResult.HighestBids["bidder_a"].Price)
	check.Equal(t, 2.25, rankingResult.HighestBids["bidder_b"].Price)
}

func TestRankCoreBids_SingleBid(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.00},
	}

	result := RankCoreBids(bids, nil)

	check.Equal(t, 1, len(result.SortedBidders))
	check.Equal(t, "bidder_a", result.SortedBidders[0])
	check.Equal(t, 2.00, result.HighestBids["bidder_a"].Price)
}

func TestRankCoreBids_EmptyBids(t *testing.T) {
	result := RankCoreBids([]CoreBid{}, nil)

	check.NotNil(t, result)
	check.Equal(t, 0, len(result.SortedBidders))
	check.Equal(t, 0, len(result.HighestBids))
	check.Equal(t, 0, len(result.Ranks))
}

func TestRankCoreBids_TwoWayTie_Winner(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.50},
		{ID: "bid2", Bidder: "bidder_b", Price: 2.50},
		{ID: "bid3", Bidder: "bidder_c", Price: 1.00},
	}

	mock1 := &mockRandSource{sequence: []int{0}}
	result1 := RankCoreBids(bids, mock1)

	check.Equal(t, 3, len(result1.SortedBidders))
	check.Equal(t, "bidder_b", result1.SortedBidders[0]) // Swapped to first
	check.Equal(t, "bidder_a", result1.SortedBidders[1]) // Swapped to second
	check.Equal(t, "bidder_c", result1.SortedBidders[2])
	check.Equal(t, 2.50, result1.HighestBids["bidder_b"].Price)
	check.Equal(t, 2.50, result1.HighestBids["bidder_a"].Price)
	check.Equal(t, 1.00, result1.HighestBids["bidder_c"].Price)

	mock2 := &mockRandSource{sequence: []int{1}}
	result2 := RankCoreBids(bids, mock2)

	check.Equal(t, 3, len(result2.SortedBidders))
	check.Equal(t, "bidder_a", result2.SortedBidders[0]) // Stayed first
	check.Equal(t, "bidder_b", result2.SortedBidders[1]) // Stayed second
	check.Equal(t, "bidder_c", result2.SortedBidders[2])
	check.Equal(t, 2.50, result2.HighestBids["bidder_a"].Price)
	check.Equal(t, 2.50, result2.HighestBids["bidder_b"].Price)
}

func TestRankCoreBids_ThreeWayTie_AllPositions(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 2.00},
		{ID: "bid2", Bidder: "bidder_b", Price: 2.00},
		{ID: "bid3", Bidder: "bidder_c", Price: 2.00},
	}

	mock1 := &mockRandSource{sequence: []int{0, 1}}
	result1 := RankCoreBids(bids, mock1)

	check.Equal(t, 3, len(result1.SortedBidders))
	check.Equal(t, "bidder_c", result1.SortedBidders[0])
	check.Equal(t, "bidder_b", result1.SortedBidders[1])
	check.Equal(t, "bidder_a", result1.SortedBidders[2])
	check.Equal(t, 2.00, result1.HighestBids["bidder_a"].Price)
	check.Equal(t, 2.00, result1.HighestBids["bidder_b"].Price)
	check.Equal(t, 2.00, result1.HighestBids["bidder_c"].Price)

	mock2 := &mockRandSource{sequence: []int{2, 0}}
	result2 := RankCoreBids(bids, mock2)

	check.Equal(t, 3, len(result2.SortedBidders))
	check.Equal(t, "bidder_b", result2.SortedBidders[0])
	check.Equal(t, "bidder_a", result2.SortedBidders[1])
	check.Equal(t, "bidder_c", result2.SortedBidders[2])
	check.Equal(t, 2.00, result2.HighestBids["bidder_a"].Price)
	check.Equal(t, 2.00, result2.HighestBids["bidder_b"].Price)
	check.Equal(t, 2.00, result2.HighestBids["bidder_c"].Price)
}

func TestRankCoreBids_MultipleTieLevels(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 3.00},
		{ID: "bid2", Bidder: "bidder_b", Price: 3.00},
		{ID: "bid3", Bidder: "bidder_c", Price: 2.00},
		{ID: "bid4", Bidder: "bidder_d", Price: 2.00},
		{ID: "bid5", Bidder: "bidder_e", Price: 1.00},
	}

	mock1 := &mockRandSource{sequence: []int{0, 1}}
	result1 := RankCoreBids(bids, mock1)

	check.Equal(t, 5, len(result1.SortedBidders))
	check.Equal(t, "bidder_b", result1.SortedBidders[0])
	check.Equal(t, "bidder_a", result1.SortedBidders[1])
	check.Equal(t, "bidder_c", result1.SortedBidders[2])
	check.Equal(t, "bidder_d", result1.SortedBidders[3])
	check.Equal(t, "bidder_e", result1.SortedBidders[4])

	mock2 := &mockRandSource{sequence: []int{1, 0}}
	result2 := RankCoreBids(bids, mock2)

	check.Equal(t, 5, len(result2.SortedBidders))
	check.Equal(t, "bidder_a", result2.SortedBidders[0])
	check.Equal(t, "bidder_b", result2.SortedBidders[1])
	check.Equal(t, "bidder_d", result2.SortedBidders[2])
	check.Equal(t, "bidder_c", result2.SortedBidders[3])
	check.Equal(t, "bidder_e", result2.SortedBidders[4])
}

func TestRankCoreBids_FourWayTie_WinnerRunnerUp(t *testing.T) {
	bids := []CoreBid{
		{ID: "bid1", Bidder: "bidder_a", Price: 5.00},
		{ID: "bid2", Bidder: "bidder_b", Price: 5.00},
		{ID: "bid3", Bidder: "bidder_c", Price: 5.00},
		{ID: "bid4", Bidder: "bidder_d", Price: 5.00},
	}

	mock1 := &mockRandSource{sequence: []int{2, 1, 0}}
	result1 := RankCoreBids(bids, mock1)

	check.Equal(t, 4, len(result1.SortedBidders))
	check.Equal(t, "bidder_d", result1.SortedBidders[0])
	check.Equal(t, "bidder_a", result1.SortedBidders[1])
	check.Equal(t, "bidder_b", result1.SortedBidders[2])
	check.Equal(t, "bidder_c", result1.SortedBidders[3])
	check.Equal(t, 5.00, result1.HighestBids["bidder_a"].Price)
	check.Equal(t, 5.00, result1.HighestBids["bidder_b"].Price)
	check.Equal(t, 5.00, result1.HighestBids["bidder_c"].Price)
	check.Equal(t, 5.00, result1.HighestBids["bidder_d"].Price)

	mock2 := &mockRandSource{sequence: []int{0, 2, 1}}
	result2 := RankCoreBids(bids, mock2)

	check.Equal(t, 4, len(result2.SortedBidders))
	check.Equal(t, "bidder_d", result2.SortedBidders[0])
	check.Equal(t, "bidder_b", result2.SortedBidders[1])
	check.Equal(t, "bidder_c", result2.SortedBidders[2])
	check.Equal(t, "bidder_a", result2.SortedBidders[3])
	check.Equal(t, 5.00, result2.HighestBids["bidder_a"].Price)
	check.Equal(t, 5.00, result2.HighestBids["bidder_b"].Price)
	check.Equal(t, 5.00, result2.HighestBids["bidder_c"].Price)
	check.Equal(t, 5.00, result2.HighestBids["bidder_d"].Price)
}
