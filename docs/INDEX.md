# OpenAuction Documentation Index

Complete index of all available documentation.

## 📚 Getting Started

Start here if you're new to OpenAuction:

1. **[Getting Started Guide](guides/getting-started.md)** - Your first auction
2. **[Core Package API](api/core-package.md)** - Basic auction API
3. **[Architecture Overview](architecture/overview.md)** - System design

## 🔍 By Topic

### Auction Basics

- **[Getting Started](guides/getting-started.md)** - Quick start guide
  - Basic auction example
  - Bid adjustments
  - Floor price enforcement
  - Tie-breaking
  - Error handling

### Security & Privacy

- **[E2EE Encryption Guide](guides/e2ee-encryption.md)** - End-to-end encryption
  - Key request and validation
  - Bid encryption
  - Attestation validation
  - Replay protection

- **[Validation Package API](api/validation-package.md)** - Attestation validation
  - Key attestation validation
  - PCR verification
  - Certificate chain validation
  - COSE signature verification

### API References

- **[Core Package](api/core-package.md)** - Auction logic
  - `RunAuction()` - Complete auction processing
  - `RankCoreBids()` - Bid ranking
  - `ApplyBidAdjustmentFactors()` - Price adjustments
  - `EnforceBidFloor()` - Floor enforcement

- **[EnclaveAPI Package](api/enclaveapi-package.md)** - Communication types
  - `EnclaveAuctionRequest` - Auction request format
  - `EnclaveAuctionResponse` - Auction response format
  - `EncryptedCoreBid` - E2EE bid structure
  - `AttestationDoc` - Attestation types
  - `KeyResponse` - Key distribution

- **[Validation Package](api/validation-package.md)** - Validation tools
  - `ValidateKeyAttestation()` - Key validation
  - `ValidatePCRs()` - PCR verification
  - `ValidateCertificateChain()` - Certificate validation
  - `VerifyCOSESignature()` - Signature verification

### Architecture & Design

- **[Architecture Overview](architecture/overview.md)** - System design
  - Component overview
  - Data flow diagrams
  - Security architecture
  - Concurrency model
  - Performance characteristics
  - Deployment considerations

## 📦 By Package

### `core/` - Auction Logic

**API Reference**: [Core Package](api/core-package.md)

**Key Functions:**
- `RunAuction()` - Complete auction processing
- `RankCoreBids()` - Bid ranking with tie-breaking
- `ApplyBidAdjustmentFactors()` - Apply adjustments
- `EnforceBidFloor()` - Floor enforcement
- `BidMeetsFloor()` - Floor check

**Key Types:**
- `CoreBid` - Bid representation
- `AuctionResult` - Auction results
- `CoreRankingResult` - Ranking results
- `RandSource` - Randomness interface

### `enclaveapi/` - Communication Types

**API Reference**: [EnclaveAPI Package](api/enclaveapi-package.md)

**Request/Response:**
- `EnclaveAuctionRequest` - Auction request
- `EnclaveAuctionResponse` - Auction response
- `KeyResponse` - Key distribution

**Encryption:**
- `EncryptedCoreBid` - Encrypted bid wrapper
- `EncryptedBidPrice` - E2EE structure

**Attestation:**
- `AttestationDoc` - Base attestation
- `AuctionAttestationDoc` - Auction attestation
- `KeyAttestationDoc` - Key attestation
- `PCRs` - Platform measurements

### `validation/` - Attestation Validation

**API Reference**: [Validation Package](api/validation-package.md)

**Validation Functions:**
- `ValidateKeyAttestation()` - Validate key attestation
- `ValidatePCRs()` - Verify PCRs
- `ValidateCertificateChain()` - Verify cert chain
- `VerifyCOSESignature()` - Verify signature

**Configuration:**
- `LoadPCRsFromFile()` - Load PCR config
- `DefaultPCRConfigPath()` - Get default path

**Result Types:**
- `KeyValidationResult` - Validation results
- `BaseValidationResult` - Common results
- `PCRSet` - Known-good PCRs

### `enclave/` - TEE Server

**Status**: Binary package (main)

**Key Components:**
- Auction processing with decryption
- RSA key management
- Attestation generation
- Token management
- vsock server

## 🎯 By Use Case

### Basic Auction

1. [Getting Started](guides/getting-started.md) - Basic example
2. [Core Package](api/core-package.md) - API reference

### Bid Adjustments

1. [Getting Started](guides/getting-started.md#bid-adjustments) - Adjustment basics
2. [Core Package](api/core-package.md#applybidadjustmentfactors) - `ApplyBidAdjustmentFactors()`

### Floor Enforcement

1. [Getting Started](guides/getting-started.md#floor-price-enforcement) - Floor basics
2. [Core Package](api/core-package.md#enforcebidfloor) - `EnforceBidFloor()`

### End-to-End Encryption

1. [E2EE Guide](guides/e2ee-encryption.md) - Complete E2EE tutorial
2. [EnclaveAPI Package](api/enclaveapi-package.md#encryptedbidprice) - Encryption types
3. [Validation Package](api/validation-package.md) - Attestation validation

### TEE Deployment

1. [Architecture Overview](architecture/overview.md#deployment-considerations) - Deployment overview

### Attestation Validation

1. [E2EE Guide](guides/e2ee-encryption.md#step-2-validate-attestation) - Validation example
2. [Validation Package](api/validation-package.md) - Complete validation API

## 🔧 By Task

### I want to...

**Run a basic auction**
→ [Getting Started](guides/getting-started.md)

**Apply bid adjustments**
→ [Getting Started - Bid Adjustments](guides/getting-started.md#bid-adjustments)

**Enforce minimum prices**
→ [Getting Started - Floor Enforcement](guides/getting-started.md#floor-price-enforcement)

**Encrypt bid prices**
→ [E2EE Guide](guides/e2ee-encryption.md)

**Validate attestations**
→ [Validation Package API](api/validation-package.md)

**Deploy to AWS Nitro**
→ [Architecture - Deployment](architecture/overview.md#deployment-considerations)

**Understand the architecture**
→ [Architecture Overview](architecture/overview.md)

**Test tie-breaking**
→ [Core Package - RandSource](api/core-package.md#randsource)

**Handle errors**
→ [Getting Started - Error Handling](guides/getting-started.md#error-handling)

## 📖 Complete File Listing

```
docs/
├── README.md                                    # Documentation home
├── INDEX.md                                     # This file
│
├── guides/                                      # Usage guides
│   ├── getting-started.md                      # ✅ Quick start
│   └── e2ee-encryption.md                      # ✅ E2EE guide
│
├── api/                                         # API references
│   ├── core-package.md                         # ✅ Core package API
│   ├── enclaveapi-package.md                   # ✅ EnclaveAPI types
│   ├── validation-package.md                   # ✅ Validation API
│   └── openapi.yaml                            # ✅ OpenAPI spec
│
└── architecture/                                # Architecture docs
    └── overview.md                             # ✅ Architecture overview
```

**Legend:**
- ✅ Available
- 🚧 Coming soon

## 🆘 Need Help?

1. **Start with**: [Getting Started Guide](guides/getting-started.md)
2. **Check**: [Architecture Overview](architecture/overview.md)
3. **Search**: This index for your topic
4. **Not found?**: Check the main [README](README.md)

## 📝 Contributing to Docs

Documentation contributions welcome! Please ensure:
- Clear examples with working code
- Consistent formatting
- Cross-references to related docs
- Code examples are tested

---

**[← Back to Documentation Home](README.md)**
