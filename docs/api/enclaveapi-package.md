# EnclaveAPI Package API Reference

The `enclaveapi` package defines the communication contract between auction server hosts and TEE (Trusted Execution Environment) enclaves.

## Overview

Import path: `github.com/cloudx-io/openauction/enclaveapi`

This package maintains type safety and compatibility between two separate binaries:
- **Host**: Auction server (web server handling auctions)
- **Enclave**: TEE binary running in AWS Nitro Enclaves

## Request/Response Types

### EnclaveAuctionRequest

Request format sent from host to enclave for auction processing.

```go
type EnclaveAuctionRequest struct {
    Type              string             `json:"type"`                // Must be "auction_request"
    AuctionID         string             `json:"auction_id"`          // Unique auction identifier
    RoundID           int                `json:"round_id"`            // Round number within auction
    Bids              []EncryptedCoreBid `json:"bids"`                // Bids (may be encrypted)
    AdjustmentFactors map[string]float64 `json:"adjustment_factors"`  // Per-bidder multipliers
    BidFloor          float64            `json:"bid_floor"`           // Minimum acceptable bid price
    Timestamp         time.Time          `json:"timestamp"`           // Request timestamp
}
```

**Example:**

```go
req := enclaveapi.EnclaveAuctionRequest{
    Type:      "auction_request",
    AuctionID: "auction-123",
    RoundID:   1,
    Bids: []enclaveapi.EncryptedCoreBid{
        {
            CoreBid: core.CoreBid{
                ID:       "bid-1",
                Bidder:   "bidder-a",
                Price:    2.5,
                Currency: "USD",
            },
        },
    },
    AdjustmentFactors: map[string]float64{
        "bidder-a": 0.95,
    },
    BidFloor:  2.0,
    Timestamp: time.Now(),
}
```

### EnclaveAuctionResponse

Response format returned from enclave after auction completion.

```go
type EnclaveAuctionResponse struct {
    Type                  string                 `json:"type"`                              // "auction_response"
    Success               bool                   `json:"success"`                           // Processing success
    Message               string                 `json:"message"`                           // Status message
    AttestationDoc        *AuctionAttestationDoc `json:"attestation_document,omitempty"`    // Deprecated: use AttestationCOSEBase64
    AttestationCOSEBase64 string                 `json:"attestation_cose_base64,omitempty"` // Base64 COSE_Sign1 attestation
    ExcludedBids          []core.ExcludedBid     `json:"excluded_bids,omitempty"`           // Failed bids
    FloorRejectedBidIDs   []string               `json:"floor_rejected_bid_ids,omitempty"`  // Below-floor bid IDs
    ProcessingTime        int64                  `json:"processing_time_ms"`                // Processing duration (ms)
}
```

**Important**: Use `AttestationCOSEBase64` for attestation validation. The `AttestationDoc` field is deprecated.

### KeyResponse

Response from key request to TEE enclave (for E2EE).

```go
type KeyResponse struct {
    Type                  string             `json:"type"`                              // "key_response"
    PublicKey             string             `json:"public_key"`                        // PEM format RSA public key
    TEEInstanceIP         string             `json:"tee_instance_ip,omitempty"`         // Injected by HTTP bridge
    KeyAttestation        *KeyAttestationDoc `json:"key_attestation"`                   // Deprecated
    AttestationCOSEBase64 string             `json:"attestation_cose_base64,omitempty"` // Base64 COSE_Sign1 attestation
}
```

## Bid Types

### EncryptedCoreBid

Wraps a `CoreBid` with optional encrypted price data.

```go
type EncryptedCoreBid struct {
    core.CoreBid
    EncryptedPrice *EncryptedBidPrice `json:"encrypted_price,omitempty"` // Optional encryption
}
```

**Usage:**
- If `EncryptedPrice` is `nil`, the `Price` field in `CoreBid` is used as plaintext
- If `EncryptedPrice` is present, the `Price` field is ignored and the encrypted payload is decrypted in the TEE

### EncryptedBidPrice

Represents encrypted price data using RSA-OAEP + AES-256-GCM hybrid encryption.

```go
type EncryptedBidPrice struct {
    AESKeyEncrypted  string `json:"aes_key_encrypted"`        // base64 RSA-OAEP encrypted AES key
    EncryptedPayload string `json:"encrypted_payload"`        // base64 AES-GCM encrypted payload
    Nonce            string `json:"nonce"`                    // base64 GCM nonce (12 bytes)
    HashAlgorithm    string `json:"hash_algorithm,omitempty"` // "SHA-256" (default) or "SHA-1"
}
```

**Hash Algorithm Support:**
- `"SHA-256"` (recommended, default): Modern standard for RSA-OAEP
- `"SHA-1"`: Legacy support for backward compatibility

**Encrypted Payload Format:**

The `EncryptedPayload` field contains AES-GCM encrypted JSON:

```json
{
    "price": 2.5,
    "auction_token": "uuid-token-here"
}
```

**Example (Encrypted Bid):**

```go
encryptedBid := enclaveapi.EncryptedCoreBid{
    CoreBid: core.CoreBid{
        ID:       "bid-1",
        Bidder:   "bidder-a",
        Currency: "USD",
        // Price field ignored when EncryptedPrice is present
    },
    EncryptedPrice: &enclaveapi.EncryptedBidPrice{
        AESKeyEncrypted:  "base64-rsa-encrypted-aes-key",
        EncryptedPayload: "base64-aes-gcm-encrypted-payload",
        Nonce:            "base64-gcm-nonce",
        HashAlgorithm:    "SHA-256",
    },
}
```

## Attestation Types

### AttestationDoc

Base attestation document structure from AWS Nitro Enclaves.

```go
type AttestationDoc struct {
    ModuleID        string    `json:"module_id"`         // Enclave identifier
    Timestamp       time.Time `json:"timestamp"`         // Attestation generation time
    DigestAlgorithm string    `json:"digest"`            // e.g., "SHA384"
    PCRs            PCRs      `json:"pcrs"`              // Platform Configuration Registers
    Certificate     string    `json:"certificate"`       // base64 attestation signature cert
    CABundle        []string  `json:"cabundle"`          // base64 cert chain
    PublicKey       string    `json:"public_key"`        // base64 attestation public key
    Nonce           string    `json:"nonce"`             // Replay protection nonce
}
```

### AuctionAttestationDoc

Attestation specifically for auction processing.

```go
type AuctionAttestationDoc struct {
    AttestationDoc
    UserData *AttestationUserData `json:"user_data"` // Auction proof data
}
```

### KeyAttestationDoc

Attestation specifically for key distribution.

```go
type KeyAttestationDoc struct {
    AttestationDoc
    UserData *KeyAttestationUserData `json:"user_data"` // Key metadata
}
```

### AttestationUserData

Auction-specific data embedded in attestation.

```go
type AttestationUserData struct {
    AuctionID              string                `json:"auction_id"`
    RoundID                int                   `json:"round_id"`
    BidHashes              []string              `json:"bid_hashes"`                // SHA-256 hashes of bids
    RequestHash            string                `json:"request_hash"`              // SHA-256 of auction request
    AdjustmentFactorsHash  string                `json:"adjustment_factors_hash"`   // SHA-256 of adjustments
    BidFloor               float64               `json:"bid_floor"`
    BidHashNonce           string                `json:"bid_hash_nonce"`            // Nonce for bid hashes
    Winner                 *CoreBidWithoutBidder `json:"winner,omitempty"`          // Winner (no bidder name)
    RunnerUp               *CoreBidWithoutBidder `json:"runner_up,omitempty"`       // Runner-up (no bidder name)
    RequestNonce           string                `json:"request_nonce"`             // Nonce for request hash
    AdjustmentFactorsNonce string                `json:"adjustment_factors_nonce"`  // Nonce for adjustment hash
    Timestamp              time.Time             `json:"timestamp"`
}
```

**Privacy Note**: Winner and runner-up are represented as `CoreBidWithoutBidder` to ensure bidder identity is not leaked in the attestation.

### KeyAttestationUserData

Key-specific data embedded in key attestation.

```go
type KeyAttestationUserData struct {
    KeyAlgorithm string `json:"key_algorithm"` // e.g., "RSA-2048"
    PublicKey    string `json:"public_key"`    // PEM-encoded public key
    AuctionToken string `json:"auction_token"` // Single-use token for replay protection
}
```

### CoreBidWithoutBidder

Bid representation without bidder identity (for attestation privacy).

```go
type CoreBidWithoutBidder struct {
    ID       string  `json:"id"`
    Price    float64 `json:"price"`
    Currency string  `json:"currency"`
    DealID   string  `json:"deal_id,omitempty"`
    BidType  string  `json:"bid_type,omitempty"`
}
```

## PCR Types

### PCRs

Platform Configuration Registers from AWS Nitro Enclaves.

```go
type PCRs struct {
    ImageFileHash   string `json:"0"`           // PCR0: Hash of Enclave Image File (EIF)
    KernelHash      string `json:"1"`           // PCR1: Hash of Linux kernel and initramfs
    ApplicationHash string `json:"2"`           // PCR2: Hash of user applications
    IAMRoleHash     string `json:"3"`           // PCR3: Hash of IAM role
    InstanceIDHash  string `json:"4"`           // PCR4: Hash of parent instance ID
    SigningCertHash string `json:"8,omitempty"` // PCR8: Hash of signing certificate
}
```

**PCR Validation**: PCRs are used to verify that the enclave is running the expected code. See the validation package for PCR validation.

## Utility Methods

### URLEncode

Encode attestation documents for URL transmission.

```go
func (a *AttestationDoc) URLEncode() string
func (a *AuctionAttestationDoc) URLEncode() string
```

**Returns**: URL-encoded base64 JSON representation

**Example:**

```go
encoded := attestation.URLEncode()
url := fmt.Sprintf("https://example.com/verify?attestation=%s", encoded)
```

## Integration Example

### Host-Side (Sending Request to Enclave)

```go
package main

import (
    "encoding/json"
    "time"

    "github.com/cloudx-io/openauction/core"
    "github.com/cloudx-io/openauction/enclaveapi"
)

func sendAuctionToEnclave(bids []core.CoreBid) (*enclaveapi.EnclaveAuctionResponse, error) {
    // Create request
    req := enclaveapi.EnclaveAuctionRequest{
        Type:      "auction_request",
        AuctionID: "auction-123",
        RoundID:   1,
        Bids:      convertToEncryptedBids(bids),
        AdjustmentFactors: map[string]float64{
            "bidder-a": 0.95,
        },
        BidFloor:  2.0,
        Timestamp: time.Now(),
    }

    // Send to enclave via vsock or HTTP
    // ... (implementation specific)

    return nil, nil
}

func convertToEncryptedBids(bids []core.CoreBid) []enclaveapi.EncryptedCoreBid {
    result := make([]enclaveapi.EncryptedCoreBid, len(bids))
    for i, bid := range bids {
        result[i] = enclaveapi.EncryptedCoreBid{CoreBid: bid}
    }
    return result
}
```

### Enclave-Side (Processing Request)

```go
package main

import (
    "encoding/json"

    "github.com/cloudx-io/openauction/core"
    "github.com/cloudx-io/openauction/enclaveapi"
)

func processAuctionRequest(reqJSON []byte) ([]byte, error) {
    var req enclaveapi.EnclaveAuctionRequest
    if err := json.Unmarshal(reqJSON, &req); err != nil {
        return nil, err
    }

    // Process auction (simplified)
    bids := extractCoreBids(req.Bids)
    result := core.RunAuction(bids, req.AdjustmentFactors, req.BidFloor)

    // Create response with attestation
    resp := enclaveapi.EnclaveAuctionResponse{
        Type:    "auction_response",
        Success: true,
        Message: "Auction processed",
        // AttestationCOSEBase64: ... (generated in real implementation)
    }

    return json.Marshal(resp)
}

func extractCoreBids(encBids []enclaveapi.EncryptedCoreBid) []core.CoreBid {
    bids := make([]core.CoreBid, len(encBids))
    for i, encBid := range encBids {
        bids[i] = encBid.CoreBid
        // In real implementation, decrypt EncryptedPrice if present
    }
    return bids
}
```

## See Also

- [Validation Package](validation-package.md) - Attestation validation
- [Core Package](core-package.md) - Auction logic
- [E2EE Guide](../guides/e2ee-encryption.md) - End-to-end encryption usage
