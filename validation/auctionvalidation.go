package validation

import (
	"encoding/json"
	"fmt"

	"github.com/cloudx-io/openauction/core"
	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
)

// AuctionValidationInput contains all inputs needed for auction attestation validation
type AuctionValidationInput struct {
	AttestationCOSEGzip enclaveapi.AttestationCOSEGzip // Gzipped format from win/loss notifications
	BidID               string
	BidPrice            float64            // For unencrypted bids
	EncryptedPayload    string             // For encrypted bids (base64-encoded encrypted data)
	BidFloor            float64            // Always validated against attestation.bid_floor
	ClearingPrice       *float64           // nil = no winner expected, non-nil = winner with this price
	AdjustmentFactors   map[string]float64 // Compute hash and validate (empty map = no adjustments)
	IsWinner            bool               // Expected auction result (true = expect to win, false = expect to lose)
}

// ValidateAuctionAttestation validates a TEE auction attestation and verifies:
// - Bid was included in the auction
// - Clearing price matches
// - Bid floor matches
// - Adjustment factors hash matches
// - Winner/loser determination
//
// Returns:
//   - AuctionValidationResult with detailed results (call result.IsValid() to check overall status)
//   - error if validation cannot be performed (e.g., malformed input, missing config)
func ValidateAuctionAttestation(input *AuctionValidationInput) (*AuctionValidationResult, error) {
	// Decompress and convert attestation
	attestationCOSE, err := input.AttestationCOSEGzip.Decompress()
	if err != nil {
		return nil, fmt.Errorf("decompress attestation: %w", err)
	}
	attestationCOSEBase64 := attestationCOSE.EncodeBase64()

	// Perform common attestation validation (PCRs, certificate, signature)
	baseResult, err := validateCommonAttestation(attestationCOSEBase64)
	if err != nil {
		return nil, err
	}

	// Parse auction attestation to get user data for auction-specific validation
	auctionAttestation, err := parseAuctionAttestationFromCOSE(attestationCOSEBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation from attestation_cose_base64: %w", err)
	}

	// Create auction-specific result with base validation results
	result := &AuctionValidationResult{
		BaseValidationResult: *baseResult,
	}

	// Validate user data is present
	if auctionAttestation.UserData == nil {
		result.BidHashValid = false
		result.ClearingPriceValid = false
		result.BidFloorValid = false
		result.AdjustmentHashValid = false
		result.WinnerValid = false
		result.ValidationDetails = append(result.ValidationDetails, "Attestation user data missing")
		return result, nil
	}

	// Validate bid hash
	result.BidHashValid = validateBidHash(input, auctionAttestation, result)

	// Validate clearing price
	result.ClearingPriceValid = validateClearingPrice(input, auctionAttestation, result)

	// Validate bid floor
	result.BidFloorValid = validateBidFloor(input, auctionAttestation, result)

	// Validate adjustment factors hash
	result.AdjustmentHashValid = validateAdjustmentHash(input, auctionAttestation, result)

	// Validate winner determination
	result.WinnerValid = validateWinnerAndRunnerUp(input, auctionAttestation, result)

	return result, nil
}

func validateBidHash(input *AuctionValidationInput, attestation *enclaveapi.AuctionAttestationDoc, result *AuctionValidationResult) bool {
	bidHashNonce := attestation.UserData.BidHashNonce
	if bidHashNonce == "" {
		result.ValidationDetails = append(result.ValidationDetails, "Bid hash nonce missing from attestation")
		return false
	}

	// Compute hash using the decrypted price
	// All bids (encrypted and unencrypted) are hashed using their decrypted price
	computedHash := core.ComputeBidHash(input.BidID, input.BidPrice, bidHashNonce)
	result.ValidationDetails = append(result.ValidationDetails, "Computing bid hash using decrypted price")

	for _, attestedHash := range attestation.UserData.BidHashes {
		if computedHash == attestedHash {
			result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Bid hash found in attestation: %s", computedHash))
			return true
		}
	}

	result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Bid hash NOT found in attestation. Computed: %s", computedHash))
	result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Total hashes in attestation: %d", len(attestation.UserData.BidHashes)))
	return false
}

func validateClearingPrice(input *AuctionValidationInput, attestation *enclaveapi.AuctionAttestationDoc, result *AuctionValidationResult) bool {
	if input.ClearingPrice == nil {
		// User expects no winner
		if attestation.UserData.Winner == nil {
			result.ValidationDetails = append(result.ValidationDetails, "Clearing price validation passed: no winner expected and no winner in attestation")
			return true
		}
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Clearing price mismatch: expected no winner, but attestation has winner with price %.6f", attestation.UserData.Winner.Price))
		return false
	}

	// User expects a winner with specific price
	if attestation.UserData.Winner == nil {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Clearing price mismatch: expected winner with price %.6f, but attestation has no winner", *input.ClearingPrice))
		return false
	}

	if *input.ClearingPrice == attestation.UserData.Winner.Price {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Clearing price validation passed: %.6f", *input.ClearingPrice))
		return true
	}

	result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Clearing price mismatch: expected %.6f, attestation has %.6f", *input.ClearingPrice, attestation.UserData.Winner.Price))
	return false
}

func validateBidFloor(input *AuctionValidationInput, attestation *enclaveapi.AuctionAttestationDoc, result *AuctionValidationResult) bool {
	if input.BidFloor == attestation.UserData.BidFloor {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Bid floor validation passed: %.6f", input.BidFloor))
		return true
	}

	result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Bid floor mismatch: expected %.6f, attestation has %.6f", input.BidFloor, attestation.UserData.BidFloor))
	return false
}

func validateAdjustmentHash(input *AuctionValidationInput, attestation *enclaveapi.AuctionAttestationDoc, result *AuctionValidationResult) bool {
	nonce := attestation.UserData.AdjustmentFactorsNonce
	if nonce == "" {
		result.ValidationDetails = append(result.ValidationDetails, "Adjustment factors nonce missing from attestation")
		return false
	}

	computedHash := core.ComputeAdjustmentFactorsHash(input.AdjustmentFactors, nonce)
	attestedHash := attestation.UserData.AdjustmentFactorsHash

	if computedHash == attestedHash {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Adjustment factors hash validation passed: %s", computedHash))
		return true
	}

	result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Adjustment factors hash mismatch: computed %s, attestation has %s", computedHash, attestedHash))
	return false
}

func validateWinnerAndRunnerUp(input *AuctionValidationInput, attestation *enclaveapi.AuctionAttestationDoc, result *AuctionValidationResult) bool {
	winner := attestation.UserData.Winner
	actuallyWon := winner != nil && winner.ID == input.BidID

	// Validate bidder's expectation matches attestation
	if input.IsWinner == actuallyWon {
		if actuallyWon {
			result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Winner validation passed: bid won as expected (price: %.6f)", winner.Price))
		} else {
			result.ValidationDetails = append(result.ValidationDetails, "Winner validation passed: bid lost as expected")
		}
		return true
	}

	// Mismatch between expectation and reality
	if input.IsWinner && !actuallyWon {
		result.ValidationDetails = append(result.ValidationDetails, "Winner validation failed: expected to win, but did not win")
	} else {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Winner validation failed: expected to lose, but won with price %.6f", winner.Price))
	}
	return false
}

// parseAuctionAttestationFromCOSE parses an AuctionAttestationDoc from base64-encoded COSE bytes
// This extracts the attestation document from the COSE_Sign1 payload
func parseAuctionAttestationFromCOSE(attestationCOSEB64 enclaveapi.AttestationCOSEBase64) (*enclaveapi.AuctionAttestationDoc, error) {
	// Decode base64 COSE bytes
	coseBytes, err := attestationCOSEB64.Decode()
	if err != nil {
		return nil, fmt.Errorf("decode COSE bytes: %w", err)
	}

	// Parse the CBOR attestation document using the standard method
	// ParseAttestationDoc internally extracts the COSE_Sign1 payload and parses it
	attestationDoc, userDataBytes, err := coseBytes.ParseAttestationDoc()
	if err != nil {
		return nil, err
	}

	// Parse user data as AuctionAttestationUserData
	var userData enclaveapi.AuctionAttestationUserData
	if err := json.Unmarshal(userDataBytes, &userData); err != nil {
		return nil, fmt.Errorf("parse user data: %w", err)
	}

	return &enclaveapi.AuctionAttestationDoc{
		AttestationDoc: attestationDoc,
		UserData:       &userData,
	}, nil
}
