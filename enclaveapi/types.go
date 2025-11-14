package enclaveapi

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"time"

	"github.com/cloudx-io/openauction/core"
)

// EncryptedBidPrice represents encrypted price data using RSA-OAEP/AES-256-GCM.
// Bidders may encrypt their bid prices using a public key provided in the initial bid request,
// ensuring that prices are only ever decrypted inside the TEE where the auction runs.
type EncryptedBidPrice struct {
	AESKeyEncrypted  string `json:"aes_key_encrypted"`        // base64-encoded RSA-OAEP encrypted AES key
	EncryptedPayload string `json:"encrypted_payload"`        // base64-encoded AES-GCM encrypted {"price": X}
	Nonce            string `json:"nonce"`                    // base64-encoded GCM nonce (12 bytes)
	HashAlgorithm    string `json:"hash_algorithm,omitempty"` // Optional: "SHA-256" (default) or "SHA-1" for RSA-OAEP
}

// PCRs represents the Platform Configuration Registers from AWS Nitro Enclaves
type PCRs struct {
	// PCR0: Hash of the Enclave Image File (EIF)
	ImageFileHash string `json:"0"`

	// PCR1: Hash of the Linux kernel and initial RAM data (initramfs)
	KernelHash string `json:"1"`

	// PCR2: Hash of user applications, excluding the boot ramfs
	ApplicationHash string `json:"2"`

	// PCR3: Hash of the IAM role assigned to the parent instance
	IAMRoleHash string `json:"3"`

	// PCR4: Hash of the parent instance's ID
	InstanceIDHash string `json:"4"`

	// PCR8: Hash of the enclave image file's signing certificate
	SigningCertHash string `json:"8,omitempty"`
}

// AttestationDoc represents the base structured attestation data from AWS Nitro Enclaves
// This contains the common fields shared by all attestation types
type AttestationDoc struct {
	// Module ID identifies the enclave
	ModuleID string `json:"module_id"`

	// Timestamp when the attestation was generated
	Timestamp time.Time `json:"timestamp"`

	// Digest algorithm used (e.g., "SHA384")
	DigestAlgorithm string `json:"digest"`

	// PCRs (Platform Configuration Registers) containing measurements
	PCRs PCRs `json:"pcrs"`

	// Certificate containing the attestation signature
	Certificate string `json:"certificate"`

	// Cabundle for certificate chain validation
	CABundle []string `json:"cabundle"`

	// Public key used for attestation
	PublicKey string `json:"public_key"`

	// Nonce for replay protection
	Nonce string `json:"nonce"`
}

// AuctionAttestationDoc represents attestation specifically for auction processing
type AuctionAttestationDoc struct {
	AttestationDoc
	// User data embedded in the attestation (auction proof data)
	UserData *AttestationUserData `json:"user_data"`
}

// KeyAttestationDoc represents attestation specifically for key distribution
type KeyAttestationDoc struct {
	AttestationDoc
	// User data embedded in the attestation (key metadata)
	UserData *KeyAttestationUserData `json:"user_data"`
}

// CoreBidWithoutBidder represents a bid without bidder name for TEE attestation
// This ensures bidder identity is not leaked in the attestation document
type CoreBidWithoutBidder struct {
	ID       string  `json:"id"`
	Price    float64 `json:"price"`
	Currency string  `json:"currency"`
	DealID   string  `json:"deal_id,omitempty"`
	BidType  string  `json:"bid_type,omitempty"`
}

// AttestationUserData represents the auction-specific data embedded in the attestation
type AttestationUserData struct {
	AuctionID              string                `json:"auction_id"`
	RoundID                int                   `json:"round_id"`
	BidHashes              []string              `json:"bid_hashes"`
	RequestHash            string                `json:"request_hash"`
	AdjustmentFactorsHash  string                `json:"adjustment_factors_hash"`
	BidFloors              map[string]float64    `json:"bid_floors"`
	BidHashNonce           string                `json:"bid_hash_nonce"`
	Winner                 *CoreBidWithoutBidder `json:"winner,omitempty"`
	RunnerUp               *CoreBidWithoutBidder `json:"runner_up,omitempty"`
	RequestNonce           string                `json:"request_nonce"`
	AdjustmentFactorsNonce string                `json:"adjustment_factors_nonce"`
	Timestamp              time.Time             `json:"timestamp"`
}

// URLEncode encodes attestation for URLs
func (a *AttestationDoc) URLEncode() string {
	data, _ := json.Marshal(a)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(data))
}

// URLEncode encodes auction attestation for URLs
func (a *AuctionAttestationDoc) URLEncode() string {
	data, _ := json.Marshal(a)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(data))
}

// EncryptedCoreBid wraps a CoreBid with optional encrypted price data
// Used as input to enclave when bids may be encrypted
type EncryptedCoreBid struct {
	core.CoreBid
	EncryptedPrice *EncryptedBidPrice `json:"encrypted_price,omitempty"` // If present, Price field is encrypted
}

// EnclaveAuctionRequest represents the format expected by TEE enclaves for auction processing
type EnclaveAuctionRequest struct {
	Type              string             `json:"type"`
	AuctionID         string             `json:"auction_id"`
	RoundID           int                `json:"round_id"`
	Bids              []EncryptedCoreBid `json:"bids"`
	AdjustmentFactors map[string]float64 `json:"adjustment_factors"`
	BidFloors         map[string]float64 `json:"bid_floors"`
	Timestamp         time.Time          `json:"timestamp"`
}

// ExcludedBid represents a bid that was excluded from the auction (e.g., decryption failure)
type ExcludedBid struct {
	BidID  string `json:"bid_id"`
	Bidder string `json:"bidder"`
	Reason string `json:"reason"`
}

// EnclaveAuctionResponse represents the response from TEE enclaves after auction processing
type EnclaveAuctionResponse struct {
	Type              string                 `json:"type"`
	Success           bool                   `json:"success"`
	Message           string                 `json:"message"`
	AttestationDoc    *AuctionAttestationDoc `json:"attestation_document,omitempty"`
	ExcludedBids      []ExcludedBid          `json:"excluded_bids,omitempty"`       // Decryption failures, validation errors
	FloorRejectedBids []ExcludedBid          `json:"floor_rejected_bids,omitempty"` // Bids below floor
	ProcessingTime    int64                  `json:"processing_time_ms"`
}

// KeyResponse represents the response from a key request to the TEE enclave
type KeyResponse struct {
	Type           string             `json:"type"`
	PublicKey      string             `json:"public_key"`                // PEM format
	TEEInstanceIP  string             `json:"tee_instance_ip,omitempty"` // Injected by HTTP bridge
	KeyAttestation *KeyAttestationDoc `json:"key_attestation"`
}

// KeyAttestationUserData represents the key-specific data embedded in key attestation
type KeyAttestationUserData struct {
	KeyAlgorithm string `json:"key_algorithm"` // e.g., "RSA-2048"
	PublicKey    string `json:"public_key"`    // PEM-encoded public key
	AuctionToken string `json:"auction_token"` // Single-use token for bid replay protection
}
