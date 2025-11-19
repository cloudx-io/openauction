package core

import (
	"sort"
)

func RankCoreBids(bids []CoreBid) *CoreRankingResult {
	if len(bids) == 0 {
		return &CoreRankingResult{
			Ranks:         make(map[string]int),
			HighestBids:   make(map[string]*CoreBid),
			SortedBidders: make([]string, 0),
		}
	}

	type BidEntry struct {
		bidder string
		bid    *CoreBid
	}

	bidderMap := make(map[string]*CoreBid)
	for i := range bids {
		bid := &bids[i]
		existing, exists := bidderMap[bid.Bidder]
		if !exists || bid.Price > existing.Price {
			bidderMap[bid.Bidder] = bid
		}
	}

	entries := make([]BidEntry, 0, len(bidderMap))
	for bidder, bid := range bidderMap {
		entries = append(entries, BidEntry{
			bidder: bidder,
			bid:    bid,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].bid.Price > entries[j].bid.Price
	})

	result := &CoreRankingResult{
		Ranks:         make(map[string]int, len(entries)),
		HighestBids:   make(map[string]*CoreBid, len(entries)),
		SortedBidders: make([]string, len(entries)),
	}

	for rank, entry := range entries {
		rankValue := rank + 1
		result.Ranks[entry.bidder] = rankValue
		result.HighestBids[entry.bidder] = entry.bid
		result.SortedBidders[rank] = entry.bidder
	}

	return result
}
