package core

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

// ComputeBidHash computes the bid hash using the TEE algorithm.
// This is used by both the enclave (to generate hashes) and validation (to verify hashes).
//
// Formula: SHA256(bid_id + "|" + sprintf("%.6f", price) + "|" + nonce)
//
// The price is formatted to exactly 6 decimal places to ensure consistent hashing
// regardless of how the float is represented in memory.
func ComputeBidHash(bidID string, price float64, nonce string) string {
	data := fmt.Sprintf("%s|%.6f|%s", bidID, price, nonce)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// ComputeRequestHash computes the auction request hash using the TEE algorithm.
// This is used by both the enclave (to generate hashes) and validation (to verify hashes).
//
// Formula: SHA256(auction_id + "|" + round_id + "|" + nonce)
func ComputeRequestHash(auctionID string, roundID int, nonce string) string {
	data := fmt.Sprintf("%s|%d|%s", auctionID, roundID, nonce)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// ComputeAdjustmentFactorsHash computes the adjustment factors hash using the TEE algorithm.
// This is used by both the enclave (to generate hashes) and validation (to verify hashes).
//
// Formula: SHA256(nonce + "|" + sorted_key_value_pairs)
// where sorted_key_value_pairs = "bidder1:factor1|bidder2:factor2|..." (sorted by bidder name)
//
// Factors are formatted to exactly 6 decimal places for consistent hashing.
func ComputeAdjustmentFactorsHash(adjustmentFactors map[string]float64, nonce string) string {
	data := nonce

	// Sort bidders to ensure deterministic hash calculation
	bidders := make([]string, 0, len(adjustmentFactors))
	for bidder := range adjustmentFactors {
		bidders = append(bidders, bidder)
	}
	sort.Strings(bidders)

	for _, bidder := range bidders {
		factor := adjustmentFactors[bidder]
		data += fmt.Sprintf("|%s:%.6f", bidder, factor)
	}
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}
