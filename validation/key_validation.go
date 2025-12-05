package validation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
	"github.com/cloudx-io/openauction/enclaveapi/parsing"
)

// ValidateKeyAttestation validates a TEE key attestation from COSE bytes
//
// Parameters:
//   - attestationCOSEBase64: Base64-encoded COSE_Sign1 bytes from KeyResponse.AttestationCOSEBase64
//   - expectedPublicKey: PEM-encoded public key to validate (from KeyResponse.PublicKey)
//
// Returns:
//   - KeyValidationResult with detailed results (call result.IsValid() to check overall status)
//   - error if validation cannot be performed (e.g., malformed input, missing config)
func ValidateKeyAttestation(attestationCOSEBase64 string, expectedPublicKey string) (*KeyValidationResult, error) {
	// Perform common attestation validation (PCRs, certificate, signature)
	baseResult, err := validateCommonAttestation(attestationCOSEBase64)
	if err != nil {
		return nil, err
	}

	// Parse key attestation to get user data for key-specific validation
	keyAttestation, err := parseKeyAttestationFromCOSE(attestationCOSEBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation from attestation_cose_base64: %w", err)
	}

	// Create key-specific result with base validation results
	result := &KeyValidationResult{
		BaseValidationResult: *baseResult,
	}

	// Validate user data present and public key matches
	if keyAttestation.UserData == nil || keyAttestation.UserData.PublicKey == "" {
		result.PublicKeyMatch = false
		result.ValidationDetails = append(result.ValidationDetails, "Public key missing from attestation")
	} else {
		// Validate provided public key matches attestation
		// Trim whitespace from both keys (handles trailing newlines from PEM encoding)
		providedKeyTrimmed := strings.TrimSpace(expectedPublicKey)
		attestedKeyTrimmed := strings.TrimSpace(keyAttestation.UserData.PublicKey)

		if providedKeyTrimmed == attestedKeyTrimmed {
			result.PublicKeyMatch = true
			result.ValidationDetails = append(result.ValidationDetails, "Public key matches attestation")
		} else {
			result.PublicKeyMatch = false
			result.ValidationDetails = append(result.ValidationDetails, "Public key mismatch: provided key does not match attested key")
		}
	}

	return result, nil
}

// parseKeyAttestationFromCOSE parses a KeyAttestationDoc from base64-encoded COSE bytes
// This extracts the attestation document from the COSE_Sign1 payload
func parseKeyAttestationFromCOSE(attestationCOSEB64 string) (*enclaveapi.KeyAttestationDoc, error) {
	// Decode base64 COSE bytes
	coseBytes, err := base64.StdEncoding.DecodeString(attestationCOSEB64)
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

	// Parse user data JSON to get KeyAttestationUserData
	var keyUserData enclaveapi.KeyAttestationUserData
	if len(doc.UserData) > 0 {
		if err := json.Unmarshal(doc.UserData, &keyUserData); err != nil {
			return nil, fmt.Errorf("parse user data: %w", err)
		}
	}

	// Convert timestamp from milliseconds to time.Time
	timestamp := time.Unix(int64(doc.Timestamp/1000), int64((doc.Timestamp%1000)*1000000))

	// Build KeyAttestationDoc
	attestation := &enclaveapi.KeyAttestationDoc{
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
		UserData: &keyUserData,
	}

	return attestation, nil
}
