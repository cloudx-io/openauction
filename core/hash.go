package core

import (
	"crypto/sha256"
	"fmt"
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
func ComputeRequestHash(auctionID string, roundID string, nonce string) string {
	data := fmt.Sprintf("%s|%s|%s", auctionID, roundID, nonce)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}
