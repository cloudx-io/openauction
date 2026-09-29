# Enclave API Package

Defines the communication contract between the auction server host and TEE (Trusted Execution Environment) enclaves.

## Types

- **`EnclaveAuctionRequest`** - Request format sent from host to enclave for auction processing: bids, adjustment factors, the round floor and, optionally, the round's deals
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

## Deals

`EnclaveAuctionRequest.Deals` optionally lists the deals on the round's impression, each a `core.Deal` with the ID and floor of one `imp.pmp.deals` entry. The enclave applies them under the auction rules in the repository README, rejects a request whose list fails `core.ValidateDeals`, and records the list in the attestation user data as `deals`, next to `bid_floor`. An enclave that predates deals ignores the field and omits `deals` from the attestation, so a host can tell from the attestation whether its deals were applied.

## Usage

### Host (Exchange) Side
```go
"github.com/cloudx-io/openauction/core"
"github.com/cloudx-io/openauction/enclaveapi"

// Send auction to enclave
request := &enclaveapi.EnclaveAuctionRequest{
    Type:      "auction_request",
    AuctionID: "auction-123",       // OpenRTB BidRequest.ID
    RoundID:   1,                   // Round number (int)
    RoundIDString: "auction-123-1", // Optional: String round ID for uniqueness
    BidFloor:  1.50,                // Round floor
    Deals: []core.Deal{             // Optional: the deals in imp.pmp.deals
        {ID: "deal-1", BidFloor: 0},
    },

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
