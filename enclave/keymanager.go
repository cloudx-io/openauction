package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/cloudx-io/openauction/enclaveapi"
)

// KeyManager manages the enclave's RSA key pair for E2EE
type KeyManager struct {
	privateKey *rsa.PrivateKey // Keep private - sensitive!
	PublicKey  *rsa.PublicKey
}

// NewKeyManager creates a new KeyManager and generates a fresh RSA key pair
func NewKeyManager() (*KeyManager, error) {
	// Generate RSA key pair
	privateKey, err := GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &KeyManager{
		privateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// PublicKeyPEM returns the public key in PEM format
func (km *KeyManager) PublicKeyPEM() (string, error) {
	// Marshal public key to PKIX format
	derBytes, err := x509.MarshalPKIXPublicKey(km.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// HandleKeyRequest processes key requests and returns public key with attestation and auction token
func HandleKeyRequest(attester EnclaveAttester, keyManager *KeyManager, tokenManager *TokenManager) (*enclaveapi.KeyResponse, error) {
	publicKeyPEM, err := keyManager.PublicKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to export public key: %w", err)
	}

	auctionToken := tokenManager.GenerateToken()

	keyAttestation, attestationCBOR, err := GenerateKeyAttestation(attester, keyManager.PublicKey, auctionToken)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key attestation: %w", err)
	}

	// Encode COSE bytes to base64 for JSON transport
	attestationCOSEBase64 := base64.StdEncoding.EncodeToString(attestationCBOR)

	return &enclaveapi.KeyResponse{
		Type:                  "key_response",
		PublicKey:             publicKeyPEM,
		KeyAttestation:        keyAttestation,
		AttestationCOSEBase64: attestationCOSEBase64,
	}, nil
}
