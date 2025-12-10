# End-to-End Encryption (E2EE) Guide

This guide explains how to use end-to-end encryption with OpenAuction to ensure bid prices are only decrypted inside the TEE enclave.

## Overview

OpenAuction supports optional E2EE for bid prices using **hybrid encryption**:
1. **RSA-OAEP** (2048-bit) for key exchange
2. **AES-256-GCM** for payload encryption

With E2EE, bid prices are encrypted by bidders using the enclave's public key and can only be decrypted inside the TEE, ensuring complete price confidentiality.

## Architecture

```
Bidder → Encrypt Price → Encrypted Bid → TEE Enclave → Decrypt → Auction
         (Public Key)                      (Private Key)
```

1. Bidder requests enclave's public key (with attestation)
2. Bidder validates attestation to ensure genuine TEE
3. Bidder encrypts bid price with public key
4. Enclave decrypts price inside TEE
5. Auction runs on decrypted prices
6. Results include attestation proof

## Step 1: Request Enclave Public Key

First, request the enclave's public key with attestation:

```go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/cloudx-io/openauction/enclaveapi"
    "github.com/cloudx-io/openauction/validation"
)

func getEnclavePublicKey(enclaveURL string) (*enclaveapi.KeyResponse, error) {
    // Request key from enclave
    resp, err := http.Get(enclaveURL + "/key")
    if err != nil {
        return nil, fmt.Errorf("failed to request key: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }

    var keyResp enclaveapi.KeyResponse
    if err := json.Unmarshal(body, &keyResp); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    return &keyResp, nil
}
```

**Response includes:**
- `PublicKey`: PEM-encoded RSA public key
- `AttestationCOSEBase64`: COSE_Sign1 attestation proving the key came from the TEE
- `AuctionToken`: Single-use token for bid replay protection (embedded in attestation)

## Step 2: Validate Attestation

**Critical**: Always validate the attestation before trusting the public key:

```go
func validateAndGetKey(enclaveURL string) (string, string, error) {
    // Get key response
    keyResp, err := getEnclavePublicKey(enclaveURL)
    if err != nil {
        return "", "", err
    }

    // Validate attestation
    result, err := validation.ValidateKeyAttestation(
        keyResp.AttestationCOSEBase64,
        keyResp.PublicKey,
    )
    if err != nil {
        return "", "", fmt.Errorf("validation failed: %w", err)
    }

    if !result.IsValid() {
        return "", "", fmt.Errorf("attestation invalid: %v", result.ValidationDetails)
    }

    // Extract auction token from attestation
    auctionToken := extractAuctionToken(keyResp.AttestationCOSEBase64)

    fmt.Println("✓ Attestation validated successfully")
    return keyResp.PublicKey, auctionToken, nil
}
```

**Security Note**: If attestation validation fails, **do not use the public key**. It may not be from a genuine TEE.

## Step 3: Encrypt Bid Price

Encrypt your bid price using the validated public key:

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "fmt"
)

// Encrypted payload structure
type bidPayload struct {
    Price        float64 `json:"price"`
    AuctionToken string  `json:"auction_token,omitempty"`
}

func encryptBidPrice(publicKeyPEM string, price float64, auctionToken string) (*enclaveapi.EncryptedBidPrice, error) {
    // Parse PEM public key
    block, _ := pem.Decode([]byte(publicKeyPEM))
    if block == nil {
        return nil, fmt.Errorf("failed to parse PEM block")
    }

    pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse public key: %w", err)
    }

    rsaPubKey, ok := pubKey.(*rsa.PublicKey)
    if !ok {
        return nil, fmt.Errorf("not an RSA public key")
    }

    // Create payload
    payload := bidPayload{
        Price:        price,
        AuctionToken: auctionToken,
    }

    payloadJSON, err := json.Marshal(payload)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal payload: %w", err)
    }

    // Generate random AES-256 key
    aesKey := make([]byte, 32)
    if _, err := rand.Read(aesKey); err != nil {
        return nil, fmt.Errorf("failed to generate AES key: %w", err)
    }

    // Encrypt AES key with RSA-OAEP (SHA-256)
    encryptedAESKey, err := rsa.EncryptOAEP(
        sha256.New(),
        rand.Reader,
        rsaPubKey,
        aesKey,
        nil,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt AES key: %w", err)
    }

    // Encrypt payload with AES-256-GCM
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %w", err)
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %w", err)
    }

    // Generate nonce
    nonce := make([]byte, aesgcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }

    // Encrypt
    ciphertext := aesgcm.Seal(nil, nonce, payloadJSON, nil)

    // Return base64-encoded result
    return &enclaveapi.EncryptedBidPrice{
        AESKeyEncrypted:  base64.StdEncoding.EncodeToString(encryptedAESKey),
        EncryptedPayload: base64.StdEncoding.EncodeToString(ciphertext),
        Nonce:            base64.StdEncoding.EncodeToString(nonce),
        HashAlgorithm:    "SHA-256", // Important: must match encryption
    }, nil
}
```

## Step 4: Create Encrypted Bid

Wrap your encrypted price in an `EncryptedCoreBid`:

```go
func createEncryptedBid(bidID, bidder string, encryptedPrice *enclaveapi.EncryptedBidPrice) enclaveapi.EncryptedCoreBid {
    return enclaveapi.EncryptedCoreBid{
        CoreBid: core.CoreBid{
            ID:       bidID,
            Bidder:   bidder,
            Currency: "USD",
            // Price field is ignored when EncryptedPrice is present
        },
        EncryptedPrice: encryptedPrice,
    }
}
```

## Step 5: Submit Encrypted Auction

Send encrypted bids to the enclave:

```go
func submitEncryptedAuction(enclaveURL string, bids []enclaveapi.EncryptedCoreBid) (*enclaveapi.EnclaveAuctionResponse, error) {
    // Create auction request
    req := enclaveapi.EnclaveAuctionRequest{
        Type:              "auction_request",
        AuctionID:         "auction-123",
        RoundID:           1,
        Bids:              bids,
        AdjustmentFactors: map[string]float64{},
        BidFloor:          2.0,
        Timestamp:         time.Now(),
    }

    // Marshal request
    reqJSON, err := json.Marshal(req)
    if err != nil {
        return nil, err
    }

    // Send to enclave
    resp, err := http.Post(
        enclaveURL+"/auction",
        "application/json",
        bytes.NewReader(reqJSON),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // Parse response
    body, _ := io.ReadAll(resp.Body)
    var auctionResp enclaveapi.EnclaveAuctionResponse
    if err := json.Unmarshal(body, &auctionResp); err != nil {
        return nil, err
    }

    return &auctionResp, nil
}
```

## Step 6: Validate Auction Attestation

The auction response includes an attestation that proves the auction ran inside the TEE:

```go
func validateAuctionResult(resp *enclaveapi.EnclaveAuctionResponse) error {
    if !resp.Success {
        return fmt.Errorf("auction failed: %s", resp.Message)
    }

    // Validate attestation (similar to key validation)
    // Parse COSE, verify PCRs, certificate chain, signature
    // See validation package for details

    fmt.Println("✓ Auction result attestation validated")
    return nil
}
```

## Complete E2EE Example

Here's a complete example from start to finish:

```go
package main

import (
    "fmt"
    "log"

    "github.com/cloudx-io/openauction/core"
    "github.com/cloudx-io/openauction/enclaveapi"
    "github.com/cloudx-io/openauction/validation"
)

func main() {
    enclaveURL := "https://enclave.example.com"

    // Step 1: Get and validate public key
    fmt.Println("Step 1: Requesting enclave public key...")
    publicKey, auctionToken, err := validateAndGetKey(enclaveURL)
    if err != nil {
        log.Fatalf("Failed to get key: %v", err)
    }
    fmt.Println("✓ Public key validated")

    // Step 2: Encrypt bid prices
    fmt.Println("\nStep 2: Encrypting bid prices...")

    encryptedPrice1, _ := encryptBidPrice(publicKey, 2.50, auctionToken)
    bid1 := createEncryptedBid("bid-1", "bidder-a", encryptedPrice1)

    encryptedPrice2, _ := encryptBidPrice(publicKey, 3.00, auctionToken)
    bid2 := createEncryptedBid("bid-2", "bidder-b", encryptedPrice2)

    bids := []enclaveapi.EncryptedCoreBid{bid1, bid2}
    fmt.Println("✓ Bids encrypted")

    // Step 3: Submit to enclave
    fmt.Println("\nStep 3: Submitting encrypted auction...")
    resp, err := submitEncryptedAuction(enclaveURL, bids)
    if err != nil {
        log.Fatalf("Failed to submit auction: %v", err)
    }
    fmt.Println("✓ Auction processed")

    // Step 4: Validate result
    fmt.Println("\nStep 4: Validating auction result...")
    if err := validateAuctionResult(resp); err != nil {
        log.Fatalf("Validation failed: %v", err)
    }

    fmt.Printf("\n=== Auction Complete ===\n")
    fmt.Printf("Processing time: %dms\n", resp.ProcessingTime)
    fmt.Printf("Excluded bids: %d\n", len(resp.ExcludedBids))
}
```

## Hash Algorithm Support

OpenAuction supports two hash algorithms for RSA-OAEP:

### SHA-256 (Recommended)

```go
encryptedPrice := &enclaveapi.EncryptedBidPrice{
    AESKeyEncrypted:  "...",
    EncryptedPayload: "...",
    Nonce:            "...",
    HashAlgorithm:    "SHA-256", // Or omit (default)
}
```

### SHA-1 (Legacy)

For compatibility with legacy clients:

```go
// Encrypt with SHA-1
encryptedAESKey, err := rsa.EncryptOAEP(
    sha1.New(), // SHA-1 instead of SHA-256
    rand.Reader,
    rsaPubKey,
    aesKey,
    nil,
)

encryptedPrice := &enclaveapi.EncryptedBidPrice{
    AESKeyEncrypted:  base64.StdEncoding.EncodeToString(encryptedAESKey),
    EncryptedPayload: "...",
    Nonce:            "...",
    HashAlgorithm:    "SHA-1", // Must specify
}
```

**Important**: Encryption and decryption must use the same hash algorithm.

## Replay Protection with Auction Tokens

The `auction_token` field provides replay protection:

1. **Generation**: Token is generated when you request the public key
2. **Embedding**: Token is embedded in the key attestation and returned
3. **Encryption**: Include the token in your encrypted bid payload
4. **Validation**: Enclave validates and consumes the token (single-use)
5. **Rejection**: Bids with invalid/reused tokens are excluded

**Example:**

```go
// Token from key response
auctionToken := "uuid-from-key-attestation"

// Include in encrypted payload
payload := bidPayload{
    Price:        2.50,
    AuctionToken: auctionToken, // Single-use token
}
```

## Security Best Practices

1. **Always Validate Attestations**: Never trust keys or results without validation
2. **Use SHA-256**: Prefer SHA-256 over SHA-1 for new implementations
3. **Secure Random**: Use `crypto/rand` for all randomness (keys, nonces)
4. **Token Binding**: Always include auction token for replay protection
5. **HTTPS**: Use TLS for all communication with the enclave endpoint

## Error Handling

The enclave may exclude encrypted bids for various reasons:

```go
// Check excluded bids in response
for _, excluded := range resp.ExcludedBids {
    fmt.Printf("Bid %s excluded: %s\n", excluded.BidID, excluded.Reason)
}
```

**Common exclusion reasons:**
- `"decryption_failed"`: Encryption error or wrong key
- `"invalid_payload_format"`: Malformed JSON payload
- `"invalid_or_consumed_auction_token"`: Token reused or invalid

## See Also

- [Validation Package](../api/validation-package.md) - Attestation validation
- [EnclaveAPI Package](../api/enclaveapi-package.md) - Type definitions
- [TEE Enclave Guide](tee-enclave.md) - Running the enclave
- [Security Architecture](../architecture/security.md) - Security design
