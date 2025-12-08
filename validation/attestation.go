package validation

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
	"github.com/cloudx-io/openauction/enclaveapi/parsing"
)

// validateCommonAttestation performs validation common to all attestation types
// Parses the COSE bytes internally and validates PCRs, certificate chain, and signature
// Returns BaseValidationResult with validation results
func validateCommonAttestation(attestationCOSEBase64 string) (*BaseValidationResult, error) {
	// Decode and parse COSE to get attestation document
	coseBytes, err := base64.StdEncoding.DecodeString(attestationCOSEBase64)
	if err != nil {
		return nil, fmt.Errorf("decode COSE bytes: %w", err)
	}

	payload, err := ExtractCOSEPayload(coseBytes)
	if err != nil {
		return nil, fmt.Errorf("extract COSE payload: %w", err)
	}

	var doc parsing.NitroAttestationDocument
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse CBOR attestation document: %w", err)
	}

	// Convert to AttestationDoc
	pcrs := parsing.ExtractPCRs(doc.PCRs)
	attestationDoc := &enclaveapi.AttestationDoc{
		PCRs:        pcrs,
		Certificate: base64.StdEncoding.EncodeToString(doc.Certificate),
		CABundle:    parsing.EncodeCertificateBundle(doc.CABundle),
	}
	result := &BaseValidationResult{
		ValidationDetails: []string{},
	}

	// Load known PCR sets from config file
	knownPCRs, err := LoadPCRsFromFile(DefaultPCRConfigPath())
	if err != nil {
		return nil, fmt.Errorf("failed to load PCR configuration: %w", err)
	}

	// Validate PCRs
	pcrMatch, matchedSet := ValidatePCRs(attestationDoc.PCRs, knownPCRs)
	result.PCRsValid = pcrMatch
	if !pcrMatch {
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("PCR0: %s (no match)", attestationDoc.PCRs.ImageFileHash))
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("PCR1: %s (no match)", attestationDoc.PCRs.KernelHash))
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("PCR2: %s (no match)", attestationDoc.PCRs.ApplicationHash))
	} else {
		result.ValidationDetails = append(result.ValidationDetails, "PCR measurements valid")
		if matchedSet >= 0 && matchedSet < len(knownPCRs) {
			result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Matched PCR set: #%d (commit: %s)",
				matchedSet, knownPCRs[matchedSet].CommitHash))
		}
	}

	// Validate certificate chain
	if attestationDoc.Certificate == "" {
		result.CertificateValid = false
		result.ValidationDetails = append(result.ValidationDetails, "Missing certificate")
	} else if len(attestationDoc.CABundle) == 0 {
		result.CertificateValid = false
		result.ValidationDetails = append(result.ValidationDetails, "Missing CA bundle")
	} else {
		err = ValidateCertificateChain(attestationDoc.Certificate, attestationDoc.CABundle)
		if err != nil {
			result.CertificateValid = false
			result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("Certificate chain validation failed: %v", err))
		} else {
			result.CertificateValid = true
			result.ValidationDetails = append(result.ValidationDetails, "Certificate chain verified")
		}
	}

	// Verify COSE signature
	err = VerifyCOSESignature(attestationCOSEBase64, attestationDoc.Certificate)
	if err != nil {
		result.SignatureValid = false
		result.ValidationDetails = append(result.ValidationDetails, fmt.Sprintf("COSE signature verification failed: %v", err))
	} else {
		result.SignatureValid = true
		result.ValidationDetails = append(result.ValidationDetails, "COSE signature verified")
	}

	return result, nil
}
