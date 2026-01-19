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

	"github.com/fxamacker/cbor/v2"

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
	UserData *AuctionAttestationUserData `json:"user_data"`
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

// AuctionAttestationUserData represents the auction-specific data embedded in the attestation
type AuctionAttestationUserData struct {
	AuctionID              string                `json:"auction_id"`
	RoundID                string                `json:"round_id"`
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
	RoundID           string             `json:"round_id"`
	Bids              []EncryptedCoreBid `json:"bids"`
	AdjustmentFactors map[string]float64 `json:"adjustment_factors"`
	BidFloor          float64            `json:"bid_floor"`
	Timestamp         time.Time          `json:"timestamp"`
}

// EnclaveAuctionResponse represents the response from TEE enclaves after auction processing
type EnclaveAuctionResponse struct {
	Type                  string                `json:"type"`
	Success               bool                  `json:"success"`
	Message               string                `json:"message"`
	AttestationCOSEBase64 AttestationCOSEBase64 `json:"attestation_cose_base64,omitempty"` // Base64-encoded COSE_Sign1 attestation
	ExcludedBids          []core.ExcludedBid    `json:"excluded_bids,omitempty"`           // Decryption failures, validation errors
	FloorRejectedBidIDs   []string              `json:"floor_rejected_bid_ids,omitempty"`  // Bid IDs that were below floor
	ProcessingTime        int64                 `json:"processing_time_ms"`
}

// KeyResponse represents the response from a key request to the TEE enclave
type KeyResponse struct {
	KeyWithAttestation
	Type string `json:"type"`
}

// KeyWithAttestation represents a public key with its TEE attestation
// Used in bid requests and key validation tools
type KeyWithAttestation struct {
	PublicKey    string              `json:"public_key"`                   // PEM-encoded RSA public key
	Attestation  AttestationCOSEGzip `json:"attestation_cose_gzip_base64"` // Gzipped and base64-encoded COSE_Sign1 attestation
	AuctionToken string              `json:"auction_token"`                // Single-use token for bid replay protection
}

// KeyAttestationUserData represents the key-specific data embedded in key attestation
type KeyAttestationUserData struct {
	KeyAlgorithm string `json:"key_algorithm"` // e.g., "RSA-2048"
	PublicKey    string `json:"public_key"`    // PEM-encoded public key
	AuctionToken string `json:"auction_token"` // Single-use token for bid replay protection
}

// AttestationCOSE represents raw COSE_Sign1 bytes from AWS Nitro Enclaves
type AttestationCOSE []byte

// nitroAttestationDocument represents the raw CBOR structure from AWS Nitro Enclaves
// This is an internal type used only by ParseAttestationDoc()
type nitroAttestationDocument struct {
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

// ParseAttestationDoc extracts the AttestationDoc and user data from AWS Nitro COSE bytes.
// Returns the attestation document and raw user_data bytes that can be unmarshaled into
// the appropriate type (AttestationUserData for auctions, KeyAttestationUserData for keys, etc.).
func (a AttestationCOSE) ParseAttestationDoc() (AttestationDoc, []byte, error) {
	// Extract nested attestation document from AWS Nitro 4-element CBOR array
	var outerArray []any
	if err := cbor.Unmarshal(a, &outerArray); err != nil {
		return AttestationDoc{}, nil, fmt.Errorf("parse outer array: %w", err)
	}
	if len(outerArray) < 3 {
		return AttestationDoc{}, nil, fmt.Errorf("outer array has only %d elements, expected at least 3", len(outerArray))
	}
	nestedBytes, ok := outerArray[2].([]byte)
	if !ok {
		return AttestationDoc{}, nil, fmt.Errorf("array[2] is not []byte, type: %T", outerArray[2])
	}

	// Parse the CBOR into nitroAttestationDocument
	var doc nitroAttestationDocument
	if err := cbor.Unmarshal(nestedBytes, &doc); err != nil {
		return AttestationDoc{}, nil, fmt.Errorf("unmarshal CBOR attestation: %w", err)
	}

	// Format PCRs
	pcrs := PCRs{
		ImageFileHash:   formatPCR(doc.PCRs[0]),
		KernelHash:      formatPCR(doc.PCRs[1]),
		ApplicationHash: formatPCR(doc.PCRs[2]),
		IAMRoleHash:     formatPCR(doc.PCRs[3]),
		InstanceIDHash:  formatPCR(doc.PCRs[4]),
		SigningCertHash: formatPCR(doc.PCRs[8]),
	}

	// Encode certificate bundle
	caBundle := make([]string, len(doc.CABundle))
	for i, cert := range doc.CABundle {
		caBundle[i] = base64.StdEncoding.EncodeToString(cert)
	}

	// Build AttestationDoc
	attestationDoc := AttestationDoc{
		ModuleID:        doc.ModuleID,
		Timestamp:       time.Unix(int64(doc.Timestamp/1000), 0),
		DigestAlgorithm: doc.Digest,
		PCRs:            pcrs,
		Certificate:     base64.StdEncoding.EncodeToString(doc.Certificate),
		CABundle:        caBundle,
		PublicKey:       base64.StdEncoding.EncodeToString(doc.PublicKey),
		Nonce:           string(doc.Nonce),
	}

	return attestationDoc, doc.UserData, nil
}

// formatPCR formats PCR bytes as hex string
func formatPCR(pcrData []byte) string {
	if len(pcrData) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", pcrData)
}

// EncodeBase64 converts COSE bytes to standard base64 string
func (a AttestationCOSE) EncodeBase64() AttestationCOSEBase64 {
	return AttestationCOSEBase64(base64.StdEncoding.EncodeToString(a))
}

// EncodeURLSafe converts COSE bytes to URL-safe base64 string (no padding)
func (a AttestationCOSE) EncodeURLSafe() AttestationCOSEURLBase64 {
	encoded := base64.URLEncoding.EncodeToString(a)
	return AttestationCOSEURLBase64(removeBase64Padding(encoded))
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
	return AttestationCOSEGzip(removeBase64Padding(encoded)), nil
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

// addBase64Padding adds padding to a base64 string if needed
func addBase64Padding(str string) string {
	if padding := len(str) % 4; padding > 0 {
		str += strings.Repeat("=", 4-padding)
	}
	return str
}

// removeBase64Padding removes padding from a base64 string for URL safety
func removeBase64Padding(str string) string {
	return strings.TrimRight(str, "=")
}

// Decode converts URL-safe base64 string to raw COSE bytes
func (a AttestationCOSEURLBase64) Decode() (AttestationCOSE, error) {
	str := addBase64Padding(string(a))
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
	str := addBase64Padding(string(a))

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
