package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
)

// RandSource provides random number generation for tie-breaking.
// This interface enables dependency injection for deterministic testing.
type RandSource interface {
	Intn(n int) (int, error)
}

// cryptoRandSource wraps crypto/rand for production use
type cryptoRandSource struct{}

// Intn returns a cryptographically secure random integer in [0, n).
// Returns an error if n <= 0 or if reading from crypto/rand fails.
// The returned int is undefined when error is non-nil.
func (cryptoRandSource) Intn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("cryptoRandSource.Intn: n must be positive, got %d", n)
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("cryptoRandSource.Intn: failed to read from crypto/rand: %w", err)
	}
	return int(nBig.Int64()), nil
}

// defaultRandSource provides a cryptographically secure random source for production
var defaultRandSource RandSource = cryptoRandSource{}

func RankCoreBids(bids []CoreBid, randSource RandSource) (*CoreRankingResult, error) {
	if len(bids) == 0 {
		return &CoreRankingResult{
			Ranks:         make(map[string]int),
			HighestBids:   make(map[string]*CoreBid),
			SortedBidders: make([]string, 0),
		}, nil
	}

	type BidEntry struct {
		bidder string
		bid    *CoreBid
	}

	// Find highest bid per bidder while preserving order of first occurrence
	bidderMap := make(map[string]*CoreBid)
	bidderOrder := make([]string, 0, len(bids))
	seenBidders := make(map[string]bool)

	for i := range bids {
		bid := &bids[i]

		// Track first occurrence order
		if !seenBidders[bid.Bidder] {
			bidderOrder = append(bidderOrder, bid.Bidder)
			seenBidders[bid.Bidder] = true
		}

		// Keep highest bid per bidder
		existing, exists := bidderMap[bid.Bidder]
		if !exists || bid.Price > existing.Price {
			bidderMap[bid.Bidder] = bid
		}
	}

	// Build entries in order of first occurrence
	entries := make([]BidEntry, 0, len(bidderOrder))
	for _, bidder := range bidderOrder {
		entries = append(entries, BidEntry{
			bidder: bidder,
			bid:    bidderMap[bidder],
		})
	}

	// Sort by price descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].bid.Price > entries[j].bid.Price
	})

	// Use default crypto/rand source if none provided
	if randSource == nil {
		randSource = defaultRandSource
	}

	// Break ties randomly: shuffle groups of bids with the same price using Fisher-Yates
	i := 0
	for i < len(entries) {
		// Find the range of entries with the same price
		price := entries[i].bid.Price
		j := i + 1
		for j < len(entries) && entries[j].bid.Price == price {
			j++
		}

		// If there are ties (j-i > 1), shuffle this group
		if j-i > 1 {
			for k := j - 1; k > i; k-- {
				// Pick a random index from i to k (inclusive)
				r, err := randSource.Intn(k - i + 1)
				if err != nil {
					return nil, fmt.Errorf("failed to generate random number for tie-breaking: %w", err)
				}
				randIdx := i + r
				entries[k], entries[randIdx] = entries[randIdx], entries[k]
			}
		}

		i = j
	}

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

	return result, nil
}
