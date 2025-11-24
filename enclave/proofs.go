package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"sort"
	"time"

	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"
	"github.com/fxamacker/cbor/v2"

	"github.com/cloudx-io/openauction/core"
	"github.com/cloudx-io/openauction/enclaveapi"
)

// EnclaveAttester interface for dependency injection and testing
type EnclaveAttester interface {
	Attest(options enclave.AttestationOptions) ([]byte, error)
}

func GenerateTEEProofs(attester EnclaveAttester, req enclaveapi.EnclaveAuctionRequest, unencryptedBids []core.CoreBid, winner, runnerUp *core.CoreBid) (*enclaveapi.AuctionAttestationDoc, error) {
	bidHashNonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate bid hash nonce: %w", err)
	}

	requestNonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request nonce: %w", err)
	}

	adjustmentFactorsNonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate adjustment factors nonce: %w", err)
	}

	// Build list of bid hashes from unencrypted bid prices
	bidHashes := make([]string, 0, len(unencryptedBids))
	for _, bid := range unencryptedBids {
		bidHashes = append(bidHashes, generateBidHash(bid.ID, bid.Price, bidHashNonce))
	}

	requestHash := calculateRequestHash(req, requestNonce)
	adjustmentFactorsHash := calculateAdjustmentFactorsHash(req.AdjustmentFactors, adjustmentFactorsNonce)

	return GenerateAttestation(attester, req, bidHashes, requestHash, adjustmentFactorsHash,
		bidHashNonce, requestNonce, adjustmentFactorsNonce, winner, runnerUp)
}

// generateSecureRandomBytes generates cryptographically secure random bytes
// Uses crypto/rand which automatically leverages the best available entropy:
// - In NSM enclave: crypto/rand uses NSM-enhanced kernel entropy pool
// - In development: crypto/rand uses standard kernel entropy pool
// Both provide cryptographic security - NSM just adds hardware isolation
func generateSecureRandomBytes(length int) ([]byte, error) {
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("entropy generation failed: %w", err)
	}
	return randomBytes, nil
}

func generateNonce() (string, error) {
	randomBytes, err := generateSecureRandomBytes(32) // 256 bits of entropy
	if err != nil {
		return "", fmt.Errorf("failed to generate secure nonce - %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}

func generateBidHash(bidID string, price float64, nonce string) string {
	data := fmt.Sprintf("%s|%.6f|%s", bidID, price, nonce)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func calculateRequestHash(req enclaveapi.EnclaveAuctionRequest, nonce string) string {
	data := fmt.Sprintf("%s|%d|%s", req.AuctionID, req.RoundID, nonce)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func calculateAdjustmentFactorsHash(adjustmentFactors map[string]float64, nonce string) string {
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

// stripBidderName converts a CoreBid to CoreBidWithoutBidder, removing bidder identity
func stripBidderName(bid *core.CoreBid) *enclaveapi.CoreBidWithoutBidder {
	if bid == nil {
		return nil
	}
	return &enclaveapi.CoreBidWithoutBidder{
		ID:       bid.ID,
		Price:    bid.Price,
		Currency: bid.Currency,
		DealID:   bid.DealID,
		BidType:  bid.BidType,
	}
}

func GenerateAttestation(
	attester EnclaveAttester,
	req enclaveapi.EnclaveAuctionRequest,
	bidHashes []string,
	requestHash string,
	adjustmentFactorsHash string,
	bidHashNonce string,
	requestNonce string,
	adjustmentFactorsNonce string,
	winner *core.CoreBid,
	runnerUp *core.CoreBid,
) (*enclaveapi.AuctionAttestationDoc, error) {
	now := time.Now()

	// Create the user data that will be embedded in the attestation
	userData := &enclaveapi.AttestationUserData{
		AuctionID:              req.AuctionID,
		RoundID:                req.RoundID,
		BidHashes:              bidHashes,
		RequestHash:            requestHash,
		AdjustmentFactorsHash:  adjustmentFactorsHash,
		BidFloor:               req.BidFloor,
		BidFloors:              req.BidFloors, // TODO(kestutisg): remove to fully transition to single bid floor
		BidHashNonce:           bidHashNonce,
		Winner:                 stripBidderName(winner),
		RunnerUp:               stripBidderName(runnerUp),
		RequestNonce:           requestNonce,
		AdjustmentFactorsNonce: adjustmentFactorsNonce,
		Timestamp:              now,
	}

	if attester == nil {
		return nil, fmt.Errorf("enclave attester is nil")
	}

	// Marshal user data for the real attestation
	userDataBytes, err := json.Marshal(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user data: %w", err)
	}
	randomNonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation nonce: %w", err)
	}

	attestationCBOR, err := attester.Attest(enclave.AttestationOptions{
		UserData: userDataBytes,
		Nonce:    []byte(randomNonce),
	})
	if err != nil {
		log.Printf("ERROR: NSM attestation failed: %v", err)
		return nil, fmt.Errorf("NSM attestation failed: %w", err)
	}

	log.Printf("INFO: Real NSM attestation generated: %d bytes", len(attestationCBOR))

	// Parse the CBOR attestation document into structured format
	return ParseCBORAttestation(attestationCBOR, userData, now)
}

// NitroAttestationDocument represents the raw CBOR structure from AWS Nitro Enclaves
type NitroAttestationDocument struct {
	ModuleID    string            `cbor:"module_id"`
	Digest      string            `cbor:"digest"`
	Timestamp   uint64            `cbor:"timestamp"`
	PCRs        map[uint64][]byte `cbor:"pcrs"`
	Certificate []byte            `cbor:"certificate"`
	CABundle    [][]byte          `cbor:"cabundle"`
	PublicKey   []byte            `cbor:"public_key"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
}

// ParseCBORAttestation parses the CBOR attestation document from AWS Nitro Enclaves for auctions
func ParseCBORAttestation(cborData []byte, userData *enclaveapi.AttestationUserData, timestamp time.Time) (*enclaveapi.AuctionAttestationDoc, error) {
	// Extract nested attestation document from AWS Nitro 4-element array
	attestationDoc, err := extractNestedAttestationDoc(cborData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract nested attestation document: %w", err)
	}

	// Parse the nested document directly into our struct
	var doc NitroAttestationDocument
	err = cbor.Unmarshal(attestationDoc, &doc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CBOR attestation document: %w", err)
	}

	// Extract PCRs with safe formatting
	pcrs := extractPCRs(doc.PCRs)

	log.Printf("INFO: Successfully parsed attestation document with module ID: %s", doc.ModuleID)

	return &enclaveapi.AuctionAttestationDoc{
		AttestationDoc: enclaveapi.AttestationDoc{
			ModuleID:        doc.ModuleID,
			Timestamp:       timestamp,
			DigestAlgorithm: doc.Digest,
			PCRs:            pcrs,
			Certificate:     base64.StdEncoding.EncodeToString(doc.Certificate),
			CABundle:        encodeCertificateBundle(doc.CABundle),
			PublicKey:       base64.StdEncoding.EncodeToString(doc.PublicKey),
			Nonce:           string(doc.Nonce),
		},
		UserData: userData,
	}, nil
}

// extractNestedAttestationDoc extracts the nested attestation document from AWS Nitro's 4-element CBOR array
func extractNestedAttestationDoc(cborData []byte) ([]byte, error) {
	var outerArray []any
	err := cbor.Unmarshal(cborData, &outerArray)
	if err != nil {
		return nil, fmt.Errorf("parse outer array: %w", err)
	}

	if len(outerArray) < 3 {
		return nil, fmt.Errorf("outer array has only %d elements, expected at least 3", len(outerArray))
	}

	nestedBytes, ok := outerArray[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("array[2] is not []byte, type: %T", outerArray[2])
	}

	return nestedBytes, nil
}

// extractPCRs extracts and formats PCR values from the raw CBOR PCR map
func extractPCRs(rawPCRs map[uint64][]byte) enclaveapi.PCRs {
	formatPCR := func(pcrData []byte) string {
		if len(pcrData) == 0 {
			return ""
		}
		return fmt.Sprintf("%x", pcrData)
	}

	return enclaveapi.PCRs{
		ImageFileHash:   formatPCR(rawPCRs[0]),
		KernelHash:      formatPCR(rawPCRs[1]),
		ApplicationHash: formatPCR(rawPCRs[2]),
		IAMRoleHash:     formatPCR(rawPCRs[3]),
		InstanceIDHash:  formatPCR(rawPCRs[4]),
		SigningCertHash: formatPCR(rawPCRs[8]),
	}
}

// encodeCertificateBundle converts certificate bundle to base64 strings
func encodeCertificateBundle(certs [][]byte) []string {
	encoded := make([]string, len(certs))
	for i, cert := range certs {
		encoded[i] = base64.StdEncoding.EncodeToString(cert)
	}
	return encoded
}

// publicKeyToPEM converts an RSA public key to PEM format
func publicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// GenerateKeyAttestation generates an attestation document for E2EE public keys
func GenerateKeyAttestation(attester EnclaveAttester, publicKey *rsa.PublicKey, auctionToken string) (*enclaveapi.KeyAttestationDoc, error) {
	if attester == nil {
		return nil, fmt.Errorf("enclave attester is nil")
	}

	// Convert public key to PEM format for inclusion in attestation
	publicKeyPEM, err := publicKeyToPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}

	keyUserData := &enclaveapi.KeyAttestationUserData{
		KeyAlgorithm: "RSA-2048",
		PublicKey:    publicKeyPEM,
		AuctionToken: auctionToken,
	}

	userDataBytes, err := json.Marshal(keyUserData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key user data: %w", err)
	}

	randomNonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation nonce: %w", err)
	}

	attestationCBOR, err := attester.Attest(enclave.AttestationOptions{
		UserData: userDataBytes,
		Nonce:    []byte(randomNonce),
	})
	if err != nil {
		log.Printf("ERROR: NSM key attestation failed: %v", err)
		return nil, fmt.Errorf("NSM key attestation failed: %w", err)
	}

	log.Printf("Key attestation generated: %d bytes", len(attestationCBOR))

	return ParseKeyAttestation(attestationCBOR, keyUserData, time.Now())
}

// ParseKeyAttestation parses CBOR attestation specifically for key attestation
func ParseKeyAttestation(cborData []byte, keyUserData *enclaveapi.KeyAttestationUserData, timestamp time.Time) (*enclaveapi.KeyAttestationDoc, error) {
	// Extract nested attestation document
	attestationDoc, err := extractNestedAttestationDoc(cborData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract nested attestation document: %w", err)
	}

	// Parse the nested document
	var doc NitroAttestationDocument
	err = cbor.Unmarshal(attestationDoc, &doc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CBOR attestation document: %w", err)
	}

	// Extract PCRs
	pcrs := extractPCRs(doc.PCRs)

	log.Printf("INFO: Successfully parsed key attestation document with module ID: %s", doc.ModuleID)

	return &enclaveapi.KeyAttestationDoc{
		AttestationDoc: enclaveapi.AttestationDoc{
			ModuleID:        doc.ModuleID,
			Timestamp:       timestamp,
			DigestAlgorithm: doc.Digest,
			PCRs:            pcrs,
			Certificate:     base64.StdEncoding.EncodeToString(doc.Certificate),
			CABundle:        encodeCertificateBundle(doc.CABundle),
			PublicKey:       base64.StdEncoding.EncodeToString(doc.PublicKey),
			Nonce:           string(doc.Nonce),
		},
		UserData: keyUserData,
	}, nil
}
