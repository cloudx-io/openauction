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
// regardless of how the float is represented in memory. A zero price is hashed
// as +0, so a bidder's -0 hashes like 0.
func ComputeBidHash(bidID string, price float64, nonce string) string {
	data := fmt.Sprintf("%s|%.6f|%s", bidID, positiveZero(price), nonce)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// ComputeDealBidHash computes the hash of a bid that names a deal the round
// lists, which binds the deal ID to the bid.
//
// Formula: SHA256(bid_id + "|" + sprintf("%.6f", price) + "|deal:" + deal_id + "|" + nonce)
//
// Deal IDs cannot contain "|" (see ValidateDeals), and a "%.6f" price never
// starts with "deal:", so a deal-bid preimage never equals an open-bid one.
// Price formatting is as in ComputeBidHash.
func ComputeDealBidHash(bidID string, price float64, dealID string, nonce string) string {
	data := fmt.Sprintf("%s|%.6f|deal:%s|%s", bidID, positiveZero(price), dealID, nonce)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// ComputeAttestedBidHash computes the hash the enclave attests for a bid:
// ComputeDealBidHash when dealID names one of the round's deals, and
// ComputeBidHash otherwise. The deal lookup is the one RunAuction uses for the
// price and floor rules, so the hash form always matches the rules applied.
func ComputeAttestedBidHash(bidID string, price float64, dealID string, deals []Deal, nonce string) string {
	if _, listed := findDeal(deals, dealID); listed {
		return ComputeDealBidHash(bidID, price, dealID, nonce)
	}
	return ComputeBidHash(bidID, price, nonce)
}

// ComputeRequestHash computes the auction request hash using the TEE algorithm.
// This is used by both the enclave (to generate hashes) and validation (to verify hashes).
//
// Formula: SHA256(auction_id + "|" + round_id + "|" + nonce)
func ComputeRequestHash(auctionID string, roundID string, nonce string) string {
	data := fmt.Sprintf("%s|%s|%s", auctionID, roundID, nonce)
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
