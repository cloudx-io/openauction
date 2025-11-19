package core

// CoreBid represents a single bid in the auction system.
type CoreBid struct {
	ID       string  `json:"id"`
	Bidder   string  `json:"bidder"`
	Price    float64 `json:"price"`
	Currency string  `json:"currency"`
	DealID   string  `json:"deal_id,omitempty"`
	BidType  string  `json:"bid_type,omitempty"`
}

// CoreRankingResult contains the ranked bidders and their highest bids.
type CoreRankingResult struct {
	Ranks         map[string]int      `json:"ranks"`
	HighestBids   map[string]*CoreBid `json:"highest_bids"`
	SortedBidders []string            `json:"sorted_bidders"`
}

// AuctionResult contains the complete results of running an auction.
// This unified result format is used by both TEE and local processing paths.
type AuctionResult struct {
	// Winner is the highest-ranked bid (nil if no valid bids)
	Winner *CoreBid

	// RunnerUp is the second-highest-ranked bid (nil if less than 2 valid bids)
	RunnerUp *CoreBid

	// EligibleBids contains all bids that passed floor enforcement and were included in ranking
	EligibleBids []CoreBid

	// FloorRejectedBidIDs contains IDs of bids that failed floor enforcement
	FloorRejectedBidIDs []string
}

// ExcludedBid represents a bid that was excluded from the auction (floor rejection, decryption failure, etc.)
type ExcludedBid struct {
	BidID  string `json:"bid_id"`
	Reason string `json:"reason"`
}
