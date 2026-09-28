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

// Deal is one private-marketplace deal on the round's impression: the ID and
// floor the bidder received in imp.pmp.deals (OpenRTB 2.6 Deal.id and
// Deal.bidfloor). A bid names a deal with its DealID.
//
// A bid that names a deal the round lists must meet that deal's floor instead
// of the round floor, and may be priced at zero. A bid that names any other
// deal ID is an open-auction bid. The auction is first price and does not read
// Deal.at: a deal bid clears at its own price, like any other. Deals carry no
// seats; which bidders may bid on a deal is the host's check.
type Deal struct {
	ID string `json:"id"`
	// BidFloor is a CPM in the currency of the round floor.
	BidFloor float64 `json:"bid_floor"`
}

// CoreRankingResult contains the ranked bidders and their highest bids.
type CoreRankingResult struct {
	Ranks         map[string]int      `json:"ranks"`
	HighestBids   map[string]*CoreBid `json:"highest_bids"`
	SortedBidders []string            `json:"sorted_bidders"`
}

// BidRef identifies a bid by the bidder that submitted it.
//
// Bid IDs are only unique per bidder — many DSPs number their bids "1", "2" —
// so a bare ID cannot be attributed back to a seat when two bidders in the same
// round share one. Every bid reference that crosses a package or process
// boundary carries the bidder alongside the ID for that reason.
type BidRef struct {
	BidID  string `json:"bid_id"`
	Bidder string `json:"bidder,omitempty"`
}

// bidRefIDs projects refs down to bare bid IDs.
func bidRefIDs(refs []BidRef) []string {
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		ids = append(ids, ref.BidID)
	}
	return ids
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

	// PriceRejected identifies the bids rejected for invalid prices, by bidder.
	PriceRejected []BidRef

	// FloorRejected identifies the bids that failed floor enforcement, by bidder.
	FloorRejected []BidRef

	// Deprecated: use PriceRejected. A bare bid ID cannot be attributed to a
	// bidder when two bidders in the round share it.
	PriceRejectedBidIDs []string

	// Deprecated: use FloorRejected. A bare bid ID cannot be attributed to a
	// bidder when two bidders in the round share it.
	FloorRejectedBidIDs []string
}

// ExcludedBid represents a bid that was excluded from the auction (floor rejection, decryption failure, etc.)
type ExcludedBid struct {
	BidID string `json:"bid_id"`
	// Bidder that submitted the bid. Empty from enclaves predating
	// bidder-qualified exclusions, in which case callers must fall back to
	// their own attribution.
	Bidder string `json:"bidder,omitempty"`
	Reason string `json:"reason"`
}
