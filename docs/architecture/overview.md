# Architecture Overview

This document provides a high-level overview of the OpenAuction architecture and design principles.

## System Components

OpenAuction consists of four main packages:

```
┌─────────────────────────────────────────────────────────┐
│                     OpenAuction                          │
├─────────────┬──────────────┬──────────────┬─────────────┤
│    core/    │ enclaveapi/  │  enclave/    │ validation/ │
│   Auction   │   Types &    │  TEE Server  │ Attestation │
│   Logic     │   Protocol   │  (Binary)    │  Validator  │
└─────────────┴──────────────┴──────────────┴─────────────┘
```

### 1. Core Package (`core/`)

**Purpose**: Unified auction logic used by both TEE and local environments

**Key Features:**
- Bid ranking with cryptographically secure tie-breaking
- Bid price adjustments (multipliers)
- Floor price enforcement
- Price validation
- Deterministic behavior (for testing and auditing)

**Thread Safety**: All functions are stateless and thread-safe

**Dependencies**: `shopspring/decimal` (monetary precision)

### 2. EnclaveAPI Package (`enclaveapi/`)

**Purpose**: Communication contract between auction server and TEE enclave

**Key Features:**
- Request/response type definitions
- Encrypted bid structures (E2EE)
- Attestation document types
- PCR (Platform Configuration Register) types

**Thread Safety**: Types only, no logic

**Dependencies**: `core` package for `CoreBid` types

### 3. Enclave Package (`enclave/`)

**Purpose**: TEE server binary that runs inside AWS Nitro Enclaves

**Key Features:**
- Auction processing with E2EE decryption
- RSA key management (ephemeral keys)
- Attestation generation (AWS Nitro NSM)
- Auction token management (replay protection)
- vsock communication with parent instance

**Security Model**: Isolated execution, no persistent storage, ephemeral keys

**Dependencies:**
- `core` - auction logic
- `enclaveapi` - communication types
- AWS Nitro Enclaves SDK
- CBOR/COSE libraries

### 4. Validation Package (`validation/`)

**Purpose**: Attestation validation for bidders and auction participants

**Key Features:**
- PCR validation against known-good measurements
- Certificate chain verification
- COSE signature verification
- Key attestation validation

**Thread Safety**: All functions are stateless and thread-safe

**Dependencies:**
- `enclaveapi` - attestation types
- X.509 certificate validation
- COSE/CBOR parsing

## Data Flow

### Standard Auction Flow

```
┌─────────┐
│ Bidder  │
└────┬────┘
     │ Bids (plaintext)
     ▼
┌─────────────────┐
│ Auction Server  │
│   (uses core)   │
└────┬────────────┘
     │ AuctionResult
     ▼
┌─────────┐
│ Bidder  │
└─────────┘
```

### TEE Auction Flow with E2EE

```
┌─────────┐                                 ┌──────────────────┐
│ Bidder  │◄────────────────────────────────┤ TEE Enclave      │
└────┬────┘  1. Key Request + Attestation   │  (enclave/)      │
     │                                       └──────────────────┘
     │ 2. Validate Attestation
     │    (validation/)
     │
     │ 3. Encrypt Bid (E2EE)
     │
     ▼
┌─────────────────┐    4. EnclaveAuctionRequest    ┌──────────────────┐
│ Auction Server  │───────────────────────────────►│ TEE Enclave      │
│  (HTTP bridge)  │                                │                  │
│                 │◄───────────────────────────────┤ - Decrypt bids   │
└─────────────────┘    5. EnclaveAuctionResponse   │ - Run auction    │
     │                     + Attestation            │ - Generate proof │
     ▼                                              └──────────────────┘
┌─────────┐
│ Bidder  │ 6. Validate Auction Attestation
└─────────┘
```

**Key Steps:**
1. **Key Request**: Bidder requests enclave's public key with attestation
2. **Validation**: Bidder validates key attestation (PCRs, cert chain, signature)
3. **Encryption**: Bidder encrypts bid price using validated public key
4. **Auction Request**: Server forwards encrypted bids to enclave
5. **Processing**: Enclave decrypts bids, runs auction, generates attestation
6. **Validation**: Bidder validates auction attestation to verify TEE processing

## Security Architecture

### Threat Model

**Protected Against:**
- Price disclosure to auction server
- Price tampering by server
- Auction manipulation by server
- Replay attacks (auction tokens)
- Code substitution (PCR validation)

**Assumptions:**
- AWS Nitro Enclaves hardware security
- Bidders validate attestations properly
- TLS for transport security
- Trusted build process for PCR generation

### Defense in Depth

1. **Hardware Isolation**: AWS Nitro Enclaves provide hardware-enforced isolation
2. **Cryptographic Proofs**: Attestations prove code identity and execution
3. **E2EE**: Prices never leave encrypted state outside TEE
4. **Ephemeral Keys**: RSA keys generated fresh per enclave boot
5. **Replay Protection**: Single-use auction tokens prevent replay attacks
6. **PCR Validation**: Ensures enclave runs approved code

### Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Bid Encryption | RSA-OAEP-2048 + AES-256-GCM | Hybrid E2EE |
| Hash (RSA-OAEP) | SHA-256 (default), SHA-1 (legacy) | Key derivation |
| Attestation Signature | ECDSA P-384 | AWS Nitro NSM |
| Bid Hashing | SHA-256 | Commitment proofs |
| Tie-Breaking | crypto/rand | Fair randomness |
| Token Generation | crypto/rand (UUID v4) | Replay protection |

## Concurrency Model

### Core Package

**Thread Safety**: All functions are **stateless** and **thread-safe**
- No shared mutable state
- Pure functions (inputs → outputs)
- Safe for concurrent use from multiple goroutines

**Example:**
```go
// Safe to call from multiple goroutines
go func() {
    result1 := core.RunAuction(bids1, adjustments, floor)
}()

go func() {
    result2 := core.RunAuction(bids2, adjustments, floor)
}()
```

### Enclave Package

**Token Manager**: Uses `sync.Map` for lock-free token operations
- Fine-grained per-token locking
- No global lock contention
- Optimized for concurrent auction processing

**Key Manager**: No concurrency (single-threaded enclave server)

## Determinism and Testing

### Deterministic Behavior

The auction logic is **deterministic** except for tie-breaking:

**Deterministic:**
- Bid ranking (price order)
- Adjustment application
- Floor enforcement
- Highest bid selection per bidder

**Non-Deterministic (by design):**
- Tie-breaking when prices are equal (uses crypto/rand)

### Testing Strategy

**Deterministic Testing**: Inject custom `RandSource` for tie-breaking

```go
type fixedRandSource struct{ values []int; index int }
func (f *fixedRandSource) Intn(n int) int { /* return deterministic value */ }

result := core.RankCoreBids(bids, &fixedRandSource{})
```

**Production**: Use default `nil` RandSource for cryptographic randomness

## Performance Characteristics

### Core Package

- **Time Complexity**: O(n log n) where n = number of bids
  - Sorting: O(n log n)
  - Deduplication: O(n)
  - Adjustments: O(n)
  - Floor enforcement: O(n)

- **Space Complexity**: O(n)
  - All operations create new slices/maps
  - No mutation of inputs

### Enclave Package

**Bottlenecks:**
- RSA decryption: ~1ms per bid (for E2EE)
- Attestation generation: ~50-100ms per auction
- Network I/O: vsock overhead

**Optimization:**
- Batch processing of bids
- Single attestation per auction (not per bid)
- Token manager uses lock-free `sync.Map`

**Benchmarks** (AWS Nitro Enclave on c5.xlarge):
- 100 bids: ~150ms total
- 1000 bids: ~1200ms total
- Attestation: ~50ms

## Extensibility

### Custom Bid Types

Extend `CoreBid` with custom fields:

```go
type CustomBid struct {
    core.CoreBid
    CustomField string `json:"custom_field"`
}
```

### Custom Adjustments

Implement custom adjustment logic:

```go
func customAdjustment(bid core.CoreBid) float64 {
    // Custom logic
    return bid.Price * factor
}
```

### Custom Ranking

For specialized ranking (not supported out-of-box):

```go
// Use RankCoreBids + custom post-processing
ranking := core.RankCoreBids(bids, nil)
// Apply custom rules
```

## Deployment Considerations

### AWS Nitro Enclaves

**Requirements:**
- EC2 instance with Nitro support (c5, m5, r5, etc.)
- Nitro CLI installed
- Sufficient vCPU and memory allocation

**Configuration:**
```json
{
  "cpu_count": 2,
  "memory_mib": 512
}
```

### PCR Management

**Critical**: Maintain `pcrs.json` with known-good measurements
- Generate PCRs during build process
- Store alongside git commit hash
- Update on each release

**Example workflow:**
```bash
# Build enclave image
nitro-cli build-enclave --docker-uri auction-enclave:latest --output-file auction.eif

# Extract PCR values
nitro-cli describe-eif --eif-path auction.eif

# Add to pcrs.json with commit hash
```

### Monitoring

**Key Metrics:**
- Auction processing time
- Decryption failures
- Token consumption rate
- Attestation generation time

**Health Checks:**
- Enclave availability
- vsock connectivity
- Token manager state

## See Also

- [Security Model](security.md) - Detailed security analysis
- [PCR Measurements](pcr-measurements.md) - PCR documentation
- [Deployment Guide](../deployment/aws-nitro.md) - AWS deployment
- [Performance Tuning](performance.md) - Optimization guide
