package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/cloudx-io/openauction/core"
	"github.com/cloudx-io/openauction/enclaveapi"
)

// Exclusion reasons reported for bids dropped before the auction. These are
// surfaced on the wire in ExcludedBid.Reason, so they double as a stable
// vocabulary for callers inspecting why a bid did not participate.
const (
	// reasonDecryptionFailed is used when an encrypted bid could not be
	// decrypted (no key manager, or no live epoch's key resolved it).
	reasonDecryptionFailed = "decryption_failed"
	// reasonInvalidPayloadFormat is used when a decrypted payload did not parse
	// as the expected JSON structure.
	reasonInvalidPayloadFormat = "invalid_payload_format"
	// reasonDuplicateCiphertext is used when a bid's ciphertext fingerprint was
	// already seen for the epoch that decrypted it (a byte-identical replay).
	reasonDuplicateCiphertext = "duplicate_ciphertext"
	// reasonFingerprintFailed covers the two post-decryption paths that cannot
	// establish a dedup fingerprint, in the order they are checked: (1) a bid
	// decrypted but resolved to no key epoch, and (2) a decrypted bid whose
	// ciphertext fingerprint could not be computed. Both are unreachable by
	// construction today and both fail closed (exclude the bid) rather than skip
	// replay protection. Distinct from reasonDecryptionFailed because decryption
	// has already succeeded by the time either can occur.
	reasonFingerprintFailed = "fingerprint_failed"
)

// decryptedBidPayload represents the decrypted bid payload structure.
type decryptedBidPayload struct {
	Price float64 `json:"price"` // Bid price in USD
	// Deprecated: AuctionToken is parsed for backward compatibility with clients
	// that still embed a per-request token, but it is ignored. Replay protection
	// is enforced by ciphertext fingerprint deduplication, not by tokens.
	AuctionToken string `json:"auction_token,omitempty"`
}

func ProcessAuction(attester EnclaveAttester, req enclaveapi.EnclaveAuctionRequest, keyManager *KeyManager) enclaveapi.EnclaveAuctionResponse {
	startTime := time.Now()
	log.Printf("INFO: Processing auction %s with %d bids", req.AuctionID, len(req.Bids))

	// Validate bid floor is non-negative
	if req.BidFloor < 0.0 {
		return enclaveapi.EnclaveAuctionResponse{
			Type:           "auction_response",
			Success:        false,
			Message:        fmt.Sprintf("Invalid negative floor price %.4f", req.BidFloor),
			ProcessingTime: time.Since(startTime).Milliseconds(),
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

	// Replay protection: exclude any encrypted bid whose ciphertext fingerprint
	// was already seen for the epoch that decrypted it.
	unencryptedBids, dedupExcluded := dedupAndBuildBids(decryptedBids)

	excludedBids := append(decryptionExcluded, dedupExcluded...)
	// Run unified auction logic: adjustment → floor enforcement → ranking
	auctionResult := core.RunAuction(unencryptedBids, req.AdjustmentFactors, req.BidFloor)

	floorRejectedBidIDs := auctionResult.FloorRejectedBidIDs

	// Extract winner and runner-up from auction result
	winner := auctionResult.Winner
	runnerUp := auctionResult.RunnerUp

	coseAttestation, attestationUs, err := GenerateTEEProofs(attester, req, unencryptedBids, winner, runnerUp)
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
			ProcessingTime: processingTime,
		}
	}

	return enclaveapi.EnclaveAuctionResponse{
		Type:                  "auction_response",
		Success:               true,
		Message:               fmt.Sprintf("Processed %d bids in enclave", len(req.Bids)),
		AttestationCOSEBase64: coseAttestation.EncodeBase64(),
		ExcludedBids:          excludedBids,
		FloorRejectedBidIDs:   floorRejectedBidIDs,
		ProcessingTime:        processingTime,
		AttestationUs:         attestationUs,
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

// decryptedBidData holds a bid with its decrypted payload and the key epoch that
// decrypted it. For unencrypted bids, payload and epoch are nil.
type decryptedBidData struct {
	encBid  enclaveapi.EncryptedCoreBid
	payload *decryptedBidPayload
	epoch   *keyEpoch
}

// decryptAllBids decrypts all encrypted bids once, trying every live key epoch
// so that bids sealed to a recently-rotated key still decrypt.
// Returns decrypted bid data (only successfully decrypted), excluded bids, and errors.
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
				Reason: reasonDecryptionFailed,
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

		plaintextBytes, epoch, err := keyManager.DecryptBid(encBid.EncryptedPrice, hashAlg)
		if err != nil {
			log.Printf("INFO: Failed to decrypt bid %s: %v", encBid.ID, err)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  encBid.ID,
				Reason: reasonDecryptionFailed,
			})
			errors = append(errors, fmt.Errorf("decryption failed for bid %s: %w", encBid.ID, err))
			continue
		}

		var payload decryptedBidPayload
		if err := json.Unmarshal(plaintextBytes, &payload); err != nil {
			log.Printf("INFO: Failed to parse decrypted payload for bid %s: %v", encBid.ID, err)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  encBid.ID,
				Reason: reasonInvalidPayloadFormat,
			})
			errors = append(errors, fmt.Errorf("invalid payload format for bid %s: %w", encBid.ID, err))
			continue
		}

		log.Printf("INFO: Successfully decrypted bid %s: price=%.2f", encBid.ID, payload.Price)
		decryptedBids = append(decryptedBids, decryptedBidData{
			encBid:  encBid,
			payload: &payload,
			epoch:   epoch,
		})
	}

	return decryptedBids, excludedBids, errors
}

// dedupAndBuildBids turns decrypted bids into CoreBids for the auction, excluding
// any encrypted bid whose ciphertext was already seen for its key epoch.
//
// The fingerprint is scoped to the epoch that decrypted the bid, so replay is
// detected only within the lifetime of that epoch's key. Byte-identical
// resubmission (the only replayable artifact under authenticated encryption) is
// caught here; a bid re-encrypted with fresh randomness produces a different
// ciphertext and is not treated as a replay. Any legacy auction_token present in
// the payload is intentionally ignored.
func dedupAndBuildBids(decryptedBids []decryptedBidData) ([]core.CoreBid, []core.ExcludedBid) {
	unencryptedBids := make([]core.CoreBid, 0, len(decryptedBids))
	excludedBids := make([]core.ExcludedBid, 0)

	for _, decBid := range decryptedBids {
		// If bid doesn't have encrypted price, use as-is. Plaintext bids carry
		// no ciphertext to fingerprint and are never subject to dedup.
		if decBid.encBid.EncryptedPrice == nil {
			unencryptedBids = append(unencryptedBids, decBid.encBid.CoreBid)
			continue
		}

		// This bid carried an EncryptedPrice and reached here, so it decrypted
		// successfully and must have a resolving epoch. If it somehow does not
		// (e.g. a future refactor produces a decrypted-but-epochless bid), fail
		// closed: without an epoch there is no dedup set to fingerprint against,
		// and passing it through would silently drop replay protection.
		if decBid.epoch == nil {
			log.Printf("WARNING: Bid %s decrypted but resolved to no epoch; excluding to preserve replay protection", decBid.encBid.ID)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  decBid.encBid.ID,
				Reason: reasonFingerprintFailed,
			})
			continue
		}

		fingerprint, err := ciphertextFingerprint(decBid.encBid.EncryptedPrice)
		if err != nil {
			// The only failure ciphertextFingerprint can return is a base64
			// decode error over AESKeyEncrypted/EncryptedPayload/Nonce -- the
			// exact same fields DecryptHybrid already decoded to get here, so a
			// bid that decrypted cannot fail this step. It should not happen;
			// exclude the bid rather than risk skipping replay protection.
			// Decryption already succeeded, so this is a fingerprint failure,
			// not a decryption failure.
			log.Printf("WARNING: Failed to fingerprint bid %s: %v", decBid.encBid.ID, err)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  decBid.encBid.ID,
				Reason: reasonFingerprintFailed,
			})
			continue
		}

		if decBid.epoch.dedup.recordAndCheckDuplicate(fingerprint) {
			log.Printf("WARNING: Bid %s excluded as duplicate ciphertext (replay)", decBid.encBid.ID)
			excludedBids = append(excludedBids, core.ExcludedBid{
				BidID:  decBid.encBid.ID,
				Reason: reasonDuplicateCiphertext,
			})
			continue
		}

		// Create CoreBid with decrypted price.
		unencryptedBid := decBid.encBid.CoreBid
		unencryptedBid.Price = decBid.payload.Price

		unencryptedBids = append(unencryptedBids, unencryptedBid)
	}

	log.Printf("INFO: Bid dedup complete: %d bids ready for auction, %d excluded",
		len(unencryptedBids), len(excludedBids))

	return unencryptedBids, excludedBids
}
