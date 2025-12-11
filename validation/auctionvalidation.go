package validation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/cloudx-io/openauction/core"
	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
	"github.com/cloudx-io/openauction/enclaveapi/parsing"
)

// AuctionValidationInput contains all inputs needed for auction attestation validation
type AuctionValidationInput struct {
	AttestationCOSEGzip enclaveapi.AttestationCOSEGzip // Gzipped format from win/loss notifications
	BidID               string
	BidPrice            float64
	BidFloor            float64            // Case 8: Always validated against attestation.bid_floor
	ClearingPrice       *float64           // Case 6: nil = no winner expected, non-nil = winner with this price
	AdjustmentFactors   map[string]float64 // Case 4: Compute hash and validate (empty map = no adjustments)
	AuctionID           string             // Case 5: For request hash validation
	RoundID             int                // Case 5: For request hash validation
}

// ValidateAuctionAttestation validates a TEE auction attestation and verifies:
// - Bid was included in the auction (Case 2)
// - Clearing price matches (Case 6)
// - Bid floor matches (Case 8)
// - Adjustment factors hash matches (Case 4)
// - Request hash matches (Case 5)
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
		result.RequestHashValid = false
		result.ValidationDetails = append(result.ValidationDetails, "Attestation user data missing")
		return result, nil
	}

	// Case 2: Validate bid hash
	result.BidHashValid = validateBidHash(input, auctionAttestation, result)

	// Case 6: Validate clearing price
	result.ClearingPriceValid = validateClearingPrice(input, auctionAttestation, result)

	// Case 8: Validate bid floor
	result.BidFloorValid = validateBidFloor(input, auctionAttestation, result)

	// Case 4: Validate adjustment factors hash
	result.AdjustmentHashValid = validateAdjustmentHash(input, auctionAttestation, result)

	// Case 5: Validate request hash
	result.RequestHashValid = validateRequestHash(input, auctionAttestation, result)

	return result, nil
}

func validateBidHash(input *AuctionValidationInput, attestation *enclaveapi.AuctionAttestationDoc, result *AuctionValidationResult) bool {
	bidHashNonce := attestation.UserData.BidHashNonce
	if bidHashNonce == "" {
		result.ValidationDetails = append(result.ValidationDetails, "Bid hash nonce missing from attestation")
		return false
	}

	computedHash := core.ComputeBidHash(input.BidID, input.BidPrice, bidHashNonce)

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

func validateRequestHash(input *AuctionValidationInput, attestation *enclaveapi.AuctionAttestationDoc, result *AuctionValidationResult) bool {
	nonce := attestation.UserData.RequestNonce
	if nonce == "" {
		result.ValidationDetails = append(result.ValidationDetails, "Request nonce missing from attestation")
		return false
	}

	computedHash := core.ComputeRequestHash(input.AuctionID, input.RoundID, nonce)
	attestedHash := attestation.UserData.RequestHash

	if computedHash == attestedHash {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Request hash validation passed: %s", computedHash))
		return true
	}

	result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Request hash mismatch: computed %s, attestation has %s", computedHash, attestedHash))
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

	// Extract payload from COSE_Sign1 array
	payload, err := ExtractCOSEPayload(coseBytes)
	if err != nil {
		return nil, fmt.Errorf("extract COSE payload: %w", err)
	}

	// Parse the CBOR attestation document
	var doc parsing.NitroAttestationDocument
	err = cbor.Unmarshal(payload, &doc)
	if err != nil {
		return nil, fmt.Errorf("parse CBOR attestation document: %w", err)
	}

	// Extract PCRs and convert to hex strings
	pcrs := parsing.ExtractPCRs(doc.PCRs)

	// Parse user data JSON to get AttestationUserData
	var auctionUserData enclaveapi.AttestationUserData
	if len(doc.UserData) > 0 {
		if err := json.Unmarshal(doc.UserData, &auctionUserData); err != nil {
			return nil, fmt.Errorf("parse user data: %w", err)
		}
	}

	// Convert timestamp from milliseconds to time.Time
	timestamp := time.Unix(int64(doc.Timestamp/1000), int64((doc.Timestamp%1000)*1000000))

	// Build AuctionAttestationDoc
	attestation := &enclaveapi.AuctionAttestationDoc{
		AttestationDoc: enclaveapi.AttestationDoc{
			ModuleID:        doc.ModuleID,
			Timestamp:       timestamp,
			DigestAlgorithm: doc.Digest,
			PCRs:            pcrs,
			Certificate:     base64.StdEncoding.EncodeToString(doc.Certificate),
			CABundle:        parsing.EncodeCertificateBundle(doc.CABundle),
			PublicKey:       base64.StdEncoding.EncodeToString(doc.PublicKey),
			Nonce:           string(doc.Nonce),
		},
		UserData: &auctionUserData,
	}

	return attestation, nil
}
