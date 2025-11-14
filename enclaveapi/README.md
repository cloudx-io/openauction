# Enclave API Package

Defines the communication contract between the auction server host and TEE (Trusted Execution Environment) enclaves.

## Types

- **`EnclaveAuctionRequest`** - Request format sent from host to enclave for auction processing
- **`EnclaveAuctionResponse`** - Response format returned from enclave after auction completion
- **`AuctionAttestationDoc`** - Attestation document with cryptographic proofs from secure enclave processing
- **`KeyResponse`** - Response containing public key and attestation from enclave
- **`EncryptedCoreBid`** - Wrapper for bids with optional end-to-end encryption

## End-to-End Encryption (E2EE)

Bidders can optionally encrypt their bid prices using the enclave's public key. The encrypted data will only be decrypted inside the TEE, ensuring price confidentiality.

### Encrypted Bid Structure

```go
type EncryptedBidPrice struct {
    AESKeyEncrypted  string // base64-encoded RSA-OAEP encrypted AES key
    EncryptedPayload string // base64-encoded AES-GCM encrypted {"price": X}
    Nonce            string // base64-encoded GCM nonce (12 bytes)
    HashAlgorithm    string // Optional: "SHA-256" (default) or "SHA-1" for RSA-OAEP
}
```

### Hash Algorithm Support

The `hash_algorithm` field specifies which hash function to use for RSA-OAEP decryption:
- **`"SHA-256"`** (recommended, default if omitted) - Modern standard
- **`"SHA-1"`** - Support for backward compatibility with legacy clients

**Important**: Both encryption and decryption must use the same hash algorithm. The enclave will read this field and use the appropriate algorithm for decryption.

## Usage

### Host (Exchange) Side
```go
"github.com/cloudx-io/openauction/enclaveapi"

// Send auction to enclave
request := &enclaveapi.EnclaveAuctionRequest{
    Type:      "auction_request",
    AuctionID: "auction-123", // OpenRTB BidRequest.ID
    RoundID:   1,             // Round number within auction
    // ...
}
```

### Enclave Side  
```go
import "github.com/cloudx-io/openauction/enclaveapi"

// Process auction and return response
func processAuction(req enclaveapi.EnclaveAuctionRequest) enclaveapi.EnclaveAuctionResponse {
    // ...
}
```

## Architecture

This package maintains the API contract between two separate binaries:
- **Host**: `auction-server` (web server handling OpenRTB auctions)
- **Enclave**: TEE binary running in AWS Nitro Enclaves

Both packages import from this shared contract to ensure type safety and compatibility.
