package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/cloudx-io/openauction/core"
	"github.com/cloudx-io/openauction/enclaveapi"
)

// decryptedBidPayload represents the decrypted bid payload structure.
type decryptedBidPayload struct {
	Price        float64 `json:"price"`                   // Bid price in USD
	AuctionToken string  `json:"auction_token,omitempty"` // Optional single-use token for replay protection
}

func ProcessAuction(attester EnclaveAttester, req enclaveapi.EnclaveAuctionRequest, keyManager *KeyManager, tokenManager *TokenManager) enclaveapi.EnclaveAuctionResponse {
	startTime := time.Now()
	log.Printf("INFO: Processing auction %s with %d bids", req.AuctionID, len(req.Bids))

	// Validate bid floor is non-negative
	if req.BidFloor < 0.0 {
		return enclaveapi.EnclaveAuctionResponse{
			Type:           "auction_response",
			Success:        false,
			Message:        fmt.Sprintf("Invalid negative floor price %.4f", req.BidFloor),
			AttestationDoc: nil,
			ProcessingTime: time.Since(startTime).Milliseconds(),
		}
	}
	// Validate bid floors are non-negative
	for bidder, floor := range req.BidFloors {
		if floor < 0.0 {
			return enclaveapi.EnclaveAuctionResponse{
				Type:           "auction_response",
				Success:        false,
				Message:        fmt.Sprintf("Invalid negative floor price %.4f for bidder %s", floor, bidder),
				AttestationDoc: nil,
				ProcessingTime: time.Since(startTime).Milliseconds(),
			}
		}
	}

	// Decrypt encrypted prices if present (returns unencrypted bids)
	decryptedBids, decryptionExcluded, decryptErrors := decryptAllBids(req.Bids, keyManager)
	if len(decryptErrors) > 0 {
		log.Printf("INFO: Decryption errors encountered: %d bids failed to decrypt", len(decryptErrors))
		for i, err := range decryptErrors {
			if err != nil {
				log.Printf("INFO: Bid decryption error %d: %v", i, err)
			}
		}
	}

	consumedTokens := extractAndConsumeUniqueTokens(decryptedBids, tokenManager)
	log.Printf("INFO: Consumed %d unique auction tokens: %v", len(consumedTokens), getTokenList(consumedTokens))

	unencryptedBids, tokenExcluded := filterBidsByConsumedTokens(decryptedBids, consumedTokens)

	excludedBids := append(decryptionExcluded, tokenExcluded...)
	// Run unified auction logic: adjustment → floor enforcement → ranking
	var auctionResult *core.AuctionResult
	if req.BidFloor > 0.0 {
		auctionResult = core.RunAuctionSingleBidFloor(unencryptedBids, req.AdjustmentFactors, req.BidFloor)
	} else { // TODO(kestutisg): remove else case once switch to single bid floor is complete
		auctionResult = core.RunAuction(unencryptedBids, req.AdjustmentFactors, req.BidFloors)
	}

	floorRejectedBidIDs := auctionResult.FloorRejectedBidIDs

	// Extract winner and runner-up from auction result
	winner := auctionResult.Winner
	runnerUp := auctionResult.RunnerUp

	teeData, err := GenerateTEEProofs(attester, req, unencryptedBids, winner, runnerUp)
	processingTime := time.Since(startTime).Milliseconds()

	log.Printf("INFO: Auction complete: winner=%s (%.2f), runner-up=%s (%.2f), processing=%dms",
		getBidderName(winner), getBidPrice(winner),
		getBidderName(runnerUp), getBidPrice(runnerUp),
		processingTime)

	if err != nil {
		log.Printf("ERROR: TEE attestation failed: %v", err)
		return enclaveapi.EnclaveAuctionResponse{
			Type:           "auction_response",
			Success:        false,
			Message:        fmt.Sprintf("Enclave processing failed: %v", err),
			AttestationDoc: nil,
			ProcessingTime: processingTime,
		}
	}

	return enclaveapi.EnclaveAuctionResponse{
		Type:                "auction_response",
		Success:             true,
		Message:             fmt.Sprintf("Processed %d bids in enclave", len(req.Bids)),
		AttestationDoc:      teeData,
		ExcludedBids:        excludedBids,
		FloorRejectedBidIDs: floorRejectedBidIDs,
		ProcessingTime:      processingTime,
	}
}

func getBidderName(bid *core.CoreBid) string {
	if bid == nil {
		return "none"
	}
	return bid.Bidder
}

func getBidPrice(bid *core.CoreBid) float64 {
	if bid == nil {
		return 0.0
	}
	return bid.Price
}

func getTokenList(tokens map[string]bool) []string {
	tokenList := make([]string, 0, len(tokens))
	for token := range tokens {
		tokenList = append(tokenList, token)
	}
	return tokenList
}

// decryptedBidData holds a bid with its decrypted payload
type decryptedBidData struct {
	encBid  enclaveapi.EncryptedCoreBid
	payload *decryptedBidPayload
}

// decryptAllBids decrypts all encrypted bids once
// Returns decrypted bid data (only successfully decrypted), excluded bids, and errors
func decryptAllBids(encryptedBids []enclaveapi.EncryptedCoreBid, keyManager *KeyManager) ([]decryptedBidData, []core.ExcludedBid, []error) {
	decryptedBids := make([]decryptedBidData, 0, len(encryptedBids))
	excludedBids := make([]core.ExcludedBid, 0)
	errors := make([]error, 0)

	for i, encBid := range encryptedBids {
		// If bid doesn't have encrypted price, store with nil payload
		if encBid.EncryptedPrice == nil {
			decryptedBids = append(decryptedBids, decryptedBidData{
				encBid:  encBid,
				payload: nil,
			})
			continue
		}

		if keyManager == nil {
			err := fmt.Errorf("no key manager available")
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  encBid.ID,
				Reason: "decryption_failed",
			})
			errors = append(errors, fmt.Errorf("decryption failed for bid %s: %w", encBid.ID, err))
			continue
		}

		log.Printf("INFO: Decrypting bid %d (ID: %s, Bidder: %s)", i, encBid.ID, encBid.Bidder)

		// Get hash algorithm from bid, default to SHA-256 if not specified
		hashAlg := HashAlgorithm(encBid.EncryptedPrice.HashAlgorithm)
		if hashAlg == "" {
			hashAlg = HashAlgorithmSHA256
		}

		plaintextBytes, err := DecryptHybrid(
			encBid.EncryptedPrice.AESKeyEncrypted,
			encBid.EncryptedPrice.EncryptedPayload,
			encBid.EncryptedPrice.Nonce,
			keyManager.privateKey,
			hashAlg,
		)
		if err != nil {
			log.Printf("INFO: Failed to decrypt bid %s: %v", encBid.ID, err)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  encBid.ID,
				Reason: "decryption_failed",
			})
			errors = append(errors, fmt.Errorf("decryption failed for bid %s: %w", encBid.ID, err))
			continue
		}

		var payload decryptedBidPayload
		if err := json.Unmarshal(plaintextBytes, &payload); err != nil {
			log.Printf("INFO: Failed to parse decrypted payload for bid %s: %v", encBid.ID, err)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  encBid.ID,
				Reason: "invalid_payload_format",
			})
			errors = append(errors, fmt.Errorf("invalid payload format for bid %s: %w", encBid.ID, err))
			continue
		}

		log.Printf("INFO: Successfully decrypted bid %s: price=%.2f", encBid.ID, payload.Price)
		decryptedBids = append(decryptedBids, decryptedBidData{
			encBid:  encBid,
			payload: &payload,
		})
	}

	return decryptedBids, excludedBids, errors
}

// extractAndConsumeUniqueTokens extracts tokens from decrypted bids, then atomically consumes unique tokens
// Returns a set of successfully consumed tokens for validation during bid processing
func extractAndConsumeUniqueTokens(decryptedBids []decryptedBidData, tokenManager *TokenManager) map[string]bool {
	// Extract unique tokens from all successfully decrypted bids
	uniqueTokens := make(map[string]struct{})
	for _, decBid := range decryptedBids {
		if decBid.payload != nil && decBid.payload.AuctionToken != "" {
			uniqueTokens[decBid.payload.AuctionToken] = struct{}{}
		}
	}

	// Atomically consume all unique tokens
	consumedTokens := make(map[string]bool)
	for token := range uniqueTokens {
		if tokenManager.ValidateAndConsumeToken(token) {
			consumedTokens[token] = true
			log.Printf("INFO: Consumed auction token: %s", token)
		} else {
			log.Printf("WARNING: Failed to consume token (invalid or already used): %s", token)
		}
	}

	return consumedTokens
}

// filterBidsByConsumedTokens validates and filters decrypted bids based on consumed tokens
// Returns unencrypted CoreBids and excluded bids
// consumedTokens is a set of tokens that were successfully consumed upfront
func filterBidsByConsumedTokens(decryptedBids []decryptedBidData, consumedTokens map[string]bool) ([]core.CoreBid, []core.ExcludedBid) {
	unencryptedBids := make([]core.CoreBid, 0, len(decryptedBids))
	excludedBids := make([]core.ExcludedBid, 0)

	for _, decBid := range decryptedBids {
		// If bid doesn't have encrypted price, use as-is
		if decBid.encBid.EncryptedPrice == nil {
			unencryptedBids = append(unencryptedBids, decBid.encBid.CoreBid)
			continue
		}

		// Validate that token was successfully consumed upfront
		if decBid.payload.AuctionToken != "" {
			if !consumedTokens[decBid.payload.AuctionToken] {
				// Token was not successfully consumed (invalid or already used in another auction)
				log.Printf("WARNING: Bid %s excluded due to invalid/consumed token: %s", decBid.encBid.ID, decBid.payload.AuctionToken)
				excludedBids = append(excludedBids, core.ExcludedBid{
					BidID:  decBid.encBid.ID,
					Reason: "invalid_or_consumed_auction_token",
				})
				continue // Skip this bid, don't include in auction
			}

			// Token is valid - already consumed upfront
			log.Printf("INFO: Bid %s has valid token: %s", decBid.encBid.ID, decBid.payload.AuctionToken)
		}

		// Validate decrypted price
		if decBid.payload.Price <= 0 {
			log.Printf("INFO: Invalid price in decrypted bid %s: %.2f", decBid.encBid.ID, decBid.payload.Price)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  decBid.encBid.ID,
				Reason: "invalid_price",
			})
			continue // Exclude this bid from auction
		}

		// Create CoreBid with decrypted price
		unencryptedBid := decBid.encBid.CoreBid
		unencryptedBid.Price = decBid.payload.Price

		unencryptedBids = append(unencryptedBids, unencryptedBid)
	}

	log.Printf("INFO: Bid filtering complete: %d bids ready for auction, %d excluded",
		len(unencryptedBids), len(excludedBids))

	return unencryptedBids, excludedBids
}
