package validation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
)

// ExtractCOSEPayload extracts the payload from a COSE_Sign1 4-element array
// COSE_Sign1 structure: [protected, unprotected, payload, signature]
// Returns the payload bytes (element 2)
func ExtractCOSEPayload(coseBytes []byte) ([]byte, error) {
	var coseArray []any
	err := cbor.Unmarshal(coseBytes, &coseArray)
	if err != nil {
		return nil, fmt.Errorf("parse COSE array: %w", err)
	}

	if len(coseArray) != 4 {
		return nil, fmt.Errorf("invalid COSE_Sign1 structure: expected 4 elements, got %d", len(coseArray))
	}

	payload, ok := coseArray[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload in COSE structure")
	}

	return payload, nil
}

// VerifyCOSESignature verifies a COSE_Sign1 signature given base64-encoded COSE bytes and certificate
func VerifyCOSESignature(coseB64 enclaveapi.AttestationCOSEBase64, certB64 string) error {
	// Decode base64 COSE bytes
	coseBytes, err := coseB64.Decode()
	if err != nil {
		return fmt.Errorf("decode COSE bytes: %w", err)
	}

	// Get public key from certificate first
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// AWS Nitro returns untagged COSE_Sign1 (4-element array)
	// Parse it manually: [protected, unprotected, payload, signature]
	var coseArray []any
	err = cbor.Unmarshal(coseBytes, &coseArray)
	if err != nil {
		return fmt.Errorf("parse COSE array: %w", err)
	}

	if len(coseArray) != 4 {
		return fmt.Errorf("invalid COSE_Sign1 structure: expected 4 elements, got %d", len(coseArray))
	}

	// Extract components
	protectedBytes, ok := coseArray[0].([]byte)
	if !ok {
		return fmt.Errorf("invalid protected headers")
	}

	payload, ok := coseArray[2].([]byte)
	if !ok {
		return fmt.Errorf("invalid payload")
	}

	signature, ok := coseArray[3].([]byte)
	if !ok {
		return fmt.Errorf("invalid signature")
	}

	// Verify the signature manually
	// AWS Nitro uses ES384 (ECDSA P-384 with SHA-384)
	ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not ECDSA")
	}

	// Create Sig_structure for COSE_Sign1: ["Signature1", protected, external_aad, payload]
	// For attestation documents, external_aad is empty
	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{}, // empty external_aad
		payload,
	}

	sigStructureBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("marshal Sig_structure: %w", err)
	}

	// Verify using go-cose's verifier
	verifier, err := cose.NewVerifier(cose.AlgorithmES384, ecdsaKey)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	// Verify the signature against the Sig_structure
	err = verifier.Verify(sigStructureBytes, signature)
	if err != nil {
		return fmt.Errorf("COSE signature verification failed: %w", err)
	}

	return nil
}
