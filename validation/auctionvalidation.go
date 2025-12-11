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

// ValidateAuctionAttestation validates a TEE auction attestation from COSE bytes
// and verifies that a specific bid was included in the auction by checking its hash
//
// Parameters:
//   - attestationCOSEBase64: Base64-encoded COSE_Sign1 bytes from auction attestation
//   - bidID: The bid ID to verify
//   - bidPrice: The bid price to verify (will be formatted to 6 decimal places)
//
// Returns:
//   - AuctionValidationResult with detailed results (call result.IsValid() to check overall status)
//   - error if validation cannot be performed (e.g., malformed input, missing config)
func ValidateAuctionAttestation(attestationCOSEBase64 enclaveapi.AttestationCOSEBase64, bidID string, bidPrice float64) (*AuctionValidationResult, error) {
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
		result.ValidationDetails = append(result.ValidationDetails, "Attestation user data missing")
		return result, nil
	}

	// Extract bid hash nonce from attestation
	bidHashNonce := auctionAttestation.UserData.BidHashNonce
	if bidHashNonce == "" {
		result.BidHashValid = false
		result.ValidationDetails = append(result.ValidationDetails, "Bid hash nonce missing from attestation")
		return result, nil
	}

	// Compute the bid hash using the shared core function
	computedHash := core.ComputeBidHash(bidID, bidPrice, bidHashNonce)

	// Check if the computed hash exists in the attestation's bid_hashes array
	result.BidHashValid = false
	for _, attestedHash := range auctionAttestation.UserData.BidHashes {
		if computedHash == attestedHash {
			result.BidHashValid = true
			result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Bid hash found in attestation: %s", computedHash))
			break
		}
	}

	if !result.BidHashValid {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Bid hash NOT found in attestation. Computed: %s", computedHash))
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Total hashes in attestation: %d", len(auctionAttestation.UserData.BidHashes)))
	}

	return result, nil
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
