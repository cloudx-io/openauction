package enclaveapi

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
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
	BidFloor               float64               `json:"bid_floor"`
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
	BidFloor          float64            `json:"bid_floor"`
	Timestamp         time.Time          `json:"timestamp"`
}

// EnclaveAuctionResponse represents the response from TEE enclaves after auction processing
type EnclaveAuctionResponse struct {
	Type                  string                 `json:"type"`
	Success               bool                   `json:"success"`
	Message               string                 `json:"message"`
	AttestationDoc        *AuctionAttestationDoc `json:"attestation_document,omitempty"`    // Deprecated: Use attestation_cose_base64
	AttestationCOSEBase64 AttestationCOSEBase64  `json:"attestation_cose_base64,omitempty"` // Base64-encoded COSE_Sign1 attestation
	ExcludedBids          []core.ExcludedBid     `json:"excluded_bids,omitempty"`           // Decryption failures, validation errors
	FloorRejectedBidIDs   []string               `json:"floor_rejected_bid_ids,omitempty"`  // Bid IDs that were below floor
	ProcessingTime        int64                  `json:"processing_time_ms"`
}

// KeyResponse represents the response from a key request to the TEE enclave
type KeyResponse struct {
	Type                  string                `json:"type"`
	PublicKey             string                `json:"public_key"`                        // PEM format
	TEEInstanceIP         string                `json:"tee_instance_ip,omitempty"`         // Injected by HTTP bridge
	KeyAttestation        *KeyAttestationDoc    `json:"key_attestation"`                   // Deprecated: Use attestation_cose_base64 instead
	AttestationCOSEBase64 AttestationCOSEBase64 `json:"attestation_cose_base64,omitempty"` // Base64-encoded COSE_Sign1 attestation
}

// KeyWithAttestation represents a public key with its TEE attestation
// Used in bid requests and key validation tools
type KeyWithAttestation struct {
	PublicKey   string              `json:"public_key"`                             // PEM-encoded RSA public key
	Attestation AttestationCOSEGzip `json:"attestation_cose_gzip_base64,omitempty"` // Gzipped and base64-encoded COSE_Sign1 attestation
}

// KeyAttestationUserData represents the key-specific data embedded in key attestation
type KeyAttestationUserData struct {
	KeyAlgorithm string `json:"key_algorithm"` // e.g., "RSA-2048"
	PublicKey    string `json:"public_key"`    // PEM-encoded public key
	AuctionToken string `json:"auction_token"` // Single-use token for bid replay protection
}

// AttestationCOSE represents raw COSE_Sign1 bytes from AWS Nitro Enclaves
type AttestationCOSE []byte

// EncodeBase64 converts COSE bytes to standard base64 string
func (a AttestationCOSE) EncodeBase64() AttestationCOSEBase64 {
	return AttestationCOSEBase64(base64.StdEncoding.EncodeToString(a))
}

// EncodeURLSafe converts COSE bytes to URL-safe base64 string (no padding)
func (a AttestationCOSE) EncodeURLSafe() AttestationCOSEURLBase64 {
	encoded := base64.URLEncoding.EncodeToString(a)
	// Remove padding for URL safety
	encoded = strings.TrimRight(encoded, "=")
	return AttestationCOSEURLBase64(encoded)
}

// CompressGzip compresses COSE bytes with GZIP and encodes as base64url (no padding)
// Used for URL-safe transmission in win/loss notifications and bid responses
func (a AttestationCOSE) CompressGzip() (AttestationCOSEGzip, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", fmt.Errorf("create gzip writer: %w", err)
	}
	if _, err := w.Write(a); err != nil {
		return "", fmt.Errorf("gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("gzip close: %w", err)
	}

	// Encode to URL-safe base64 without padding
	encoded := base64.URLEncoding.EncodeToString(buf.Bytes())
	encoded = strings.TrimRight(encoded, "=")
	return AttestationCOSEGzip(encoded), nil
}

// AttestationCOSEBase64 represents standard base64-encoded COSE bytes
type AttestationCOSEBase64 string

// Decode converts base64 string to raw COSE bytes
func (a AttestationCOSEBase64) Decode() (AttestationCOSE, error) {
	data, err := base64.StdEncoding.DecodeString(string(a))
	if err != nil {
		return nil, fmt.Errorf("decode COSE base64: %w", err)
	}
	return AttestationCOSE(data), nil
}

// String returns the underlying string value for JSON marshaling
func (a AttestationCOSEBase64) String() string {
	return string(a)
}

// CompressGzip decodes, compresses with GZIP, and encodes as base64url (no padding)
// Convenience method that combines Decode() and CompressGzip()
func (a AttestationCOSEBase64) CompressGzip() (AttestationCOSEGzip, error) {
	cose, err := a.Decode()
	if err != nil {
		return "", err
	}
	return cose.CompressGzip()
}

// AttestationCOSEURLBase64 represents URL-safe base64-encoded COSE bytes (no padding)
type AttestationCOSEURLBase64 string

// Decode converts URL-safe base64 string to raw COSE bytes
func (a AttestationCOSEURLBase64) Decode() (AttestationCOSE, error) {
	str := string(a)
	// Add padding if needed
	if padding := len(str) % 4; padding > 0 {
		str += strings.Repeat("=", 4-padding)
	}
	data, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("decode COSE URL base64: %w", err)
	}
	return AttestationCOSE(data), nil
}

// String returns the underlying string value
func (a AttestationCOSEURLBase64) String() string {
	return string(a)
}

// AttestationCOSEGzip represents GZIP-compressed, base64url-encoded (no padding) COSE bytes
// optimized for URL inclusion. Common format for win/loss notifications and bid responses.
// Encoding pipeline: COSE bytes → GZIP compress → base64url encode → trim padding
type AttestationCOSEGzip string

// String returns the underlying string value for JSON marshaling
func (a AttestationCOSEGzip) String() string {
	return string(a)
}

// Decompress decompresses and returns raw COSE bytes
func (a AttestationCOSEGzip) Decompress() (AttestationCOSE, error) {
	// Add padding if needed for base64url decoding
	str := string(a)
	if padding := len(str) % 4; padding > 0 {
		str += strings.Repeat("=", 4-padding)
	}

	// Decode base64url
	gzipData, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("decode base64url: %w", err)
	}

	// GZIP decompress
	reader, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer func() { _ = reader.Close() }()

	coseBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	return AttestationCOSE(coseBytes), nil
}
