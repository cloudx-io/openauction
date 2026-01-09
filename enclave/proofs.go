package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"

	"github.com/cloudx-io/openauction/core"
	"github.com/cloudx-io/openauction/enclaveapi"
)

// EnclaveAttester interface for dependency injection and testing
type EnclaveAttester interface {
	Attest(options enclave.AttestationOptions) ([]byte, error)
}

func GenerateTEEProofs(attester EnclaveAttester, req enclaveapi.EnclaveAuctionRequest, _ []core.CoreBid, winner, runnerUp *core.CoreBid) (enclaveapi.AttestationCOSE, error) {
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

	// Build list of bid hashes from original bids (use encrypted payload if encrypted, price if not)
	bidHashes := make([]string, 0, len(req.Bids))
	for _, bid := range req.Bids {
		var hash string
		if bid.EncryptedPrice != nil {
			// For encrypted bids, hash the encrypted payload
			hash = core.ComputeBidHashEncrypted(bid.ID, bid.EncryptedPrice.EncryptedPayload, bidHashNonce)
		} else {
			// For unencrypted bids, hash the price
			hash = core.ComputeBidHash(bid.ID, bid.Price, bidHashNonce)
		}
		bidHashes = append(bidHashes, hash)
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

func calculateRequestHash(req enclaveapi.EnclaveAuctionRequest, nonce string) string {
	return core.ComputeRequestHash(req.AuctionID, req.RoundID, nonce)
}

func calculateAdjustmentFactorsHash(adjustmentFactors map[string]float64, nonce string) string {
	return core.ComputeAdjustmentFactorsHash(adjustmentFactors, nonce)
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
) (enclaveapi.AttestationCOSE, error) {
	now := time.Now()

	// Create the user data that will be embedded in the attestation
	userData := &enclaveapi.AuctionAttestationUserData{
		AuctionID:              req.AuctionID,
		RoundID:                req.RoundID,
		BidHashes:              bidHashes,
		RequestHash:            requestHash,
		AdjustmentFactorsHash:  adjustmentFactorsHash,
		BidFloor:               req.BidFloor,
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

	return enclaveapi.AttestationCOSE(attestationCBOR), nil
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

// GenerateKeyAttestation generates raw COSE bytes for E2EE public keys
func GenerateKeyAttestation(attester EnclaveAttester, publicKey *rsa.PublicKey, auctionToken string) (enclaveapi.AttestationCOSE, error) {
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

	return enclaveapi.AttestationCOSE(attestationCBOR), nil
}
