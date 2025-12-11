# OpenAuction Documentation

Comprehensive documentation for the OpenAuction library - a Go package for secure, TEE-enabled auction processing.

## Quick Links

- **[Getting Started](guides/getting-started.md)** - Your first auction
- **[API Reference](api/)** - Complete API documentation
- **[Architecture](architecture/overview.md)** - System design and components
- **[GitHub Repository](https://github.com/cloudx-io/openauction)**

## What is OpenAuction?

OpenAuction is a Go library that provides:

1. **Core Auction Logic**: Bid ranking, adjustments, floor enforcement
2. **TEE Integration**: AWS Nitro Enclave support for secure auctions
3. **End-to-End Encryption**: Optional E2EE for bid price confidentiality
4. **Attestation Validation**: Tools to verify TEE attestations

## Documentation Structure

### 📚 Guides

Step-by-step tutorials and usage guides:

- **[Getting Started](guides/getting-started.md)** - Basic auction setup and usage
- **[E2EE Encryption](guides/e2ee-encryption.md)** - End-to-end encrypted auctions
- **[TEE Enclave Usage](guides/tee-enclave.md)** - AWS Nitro Enclave deployment *(coming soon)*
- **[Testing Guide](guides/testing.md)** - Testing your auction implementation *(coming soon)*
- **[Bid Adjustments](guides/bid-adjustments.md)** - Advanced adjustment strategies *(coming soon)*

### 📖 API Reference

Complete API documentation for all packages:

- **[Core Package](api/core-package.md)** - Auction logic (`core/`)
- **[EnclaveAPI Package](api/enclaveapi-package.md)** - Communication types (`enclaveapi/`)
- **[Validation Package](api/validation-package.md)** - Attestation validation (`validation/`)

### 🏗️ Architecture

System design and technical documentation:

- **[Architecture Overview](architecture/overview.md)** - System components and design
- **[Security Model](architecture/security.md)** - Security architecture *(coming soon)*
- **[PCR Measurements](architecture/pcr-measurements.md)** - Understanding PCRs *(coming soon)*
- **[Performance Tuning](architecture/performance.md)** - Optimization guide *(coming soon)*

### 🚀 Deployment

Deployment guides for various environments:

- **[AWS Nitro](deployment/aws-nitro.md)** - AWS Nitro Enclaves deployment *(coming soon)*
- **[Docker](deployment/docker.md)** - Docker deployment *(coming soon)*

## Quick Examples

### Basic Auction

```go
package main

import (
    "fmt"
    "github.com/cloudx-io/openauction/core"
)

func main() {
    bids := []core.CoreBid{
        {ID: "1", Bidder: "bidder-a", Price: 2.50, Currency: "USD"},
        {ID: "2", Bidder: "bidder-b", Price: 3.00, Currency: "USD"},
    }

    result := core.RunAuction(bids, nil, 2.00)

    fmt.Printf("Winner: %s at $%.2f\n",
        result.Winner.Bidder, result.Winner.Price)
}
```

### Bid Adjustments

```go
adjustments := map[string]float64{
    "bidder-a": 0.95, // 5% penalty
    "bidder-b": 1.05, // 5% bonus
}

result := core.RunAuction(bids, adjustments, 2.00)
```

### Attestation Validation

```go
import "github.com/cloudx-io/openauction/validation"

result, err := validation.ValidateKeyAttestation(
    keyResponse.AttestationCOSEBase64,
    keyResponse.PublicKey,
)

if result.IsValid() {
    fmt.Println("✓ Attestation valid - key is trusted")
}
```

## Key Features

### 🔐 Security

- **TEE Isolation**: AWS Nitro Enclaves hardware security
- **E2EE Support**: Optional end-to-end encryption for bid prices
- **Attestation Proofs**: Cryptographic proof of TEE execution
- **Replay Protection**: Single-use tokens prevent bid replay

### ⚡ Performance

- **O(n log n) Complexity**: Efficient bid ranking
- **Concurrent Processing**: Thread-safe auction logic
- **Lock-Free Tokens**: `sync.Map` for token management
- **Batch Auctions**: Process multiple auctions in parallel

### 🎯 Reliability

- **Deterministic**: Predictable behavior (except tie-breaking)
- **Well-Tested**: Comprehensive test coverage
- **Type-Safe**: Strong typing with Go interfaces
- **Error Handling**: Clear error messages and rejection tracking

### 🔧 Flexibility

- **Pluggable Randomness**: Inject custom RandSource for testing
- **Custom Adjustments**: Per-bidder price multipliers
- **Floor Enforcement**: Configurable minimum bid prices
- **Extensible Types**: Embed CoreBid in custom types

## Common Use Cases

### 1. Standard First-Price Auction

Winner pays their bid price:

```go
result := core.RunAuction(bids, nil, 0)
winningPrice := result.Winner.Price
```

### 2. Second-Price Auction

Winner pays runner-up price:

```go
result := core.RunAuction(bids, nil, 0)
winningPrice := result.RunnerUp.Price // Pay second price
```

### 3. Floor-Enforced Auction

Minimum acceptable bid:

```go
result := core.RunAuction(bids, nil, 2.00) // $2.00 floor
```

### 4. Adjusted Auction

Apply bidder-specific multipliers:

```go
adjustments := map[string]float64{
    "premium-bidder": 1.10, // 10% bonus
    "risky-bidder":   0.90, // 10% penalty
}
result := core.RunAuction(bids, adjustments, 0)
```

### 5. TEE Auction with E2EE

Complete privacy and verifiable execution:

```go
// 1. Get and validate enclave key
keyResp, _ := getEnclaveKey(enclaveURL)
validation.ValidateKeyAttestation(keyResp.AttestationCOSEBase64, keyResp.PublicKey)

// 2. Encrypt bids
encryptedBid := encryptBidPrice(keyResp.PublicKey, 2.50, auctionToken)

// 3. Submit to enclave
auctionResp, _ := submitToEnclave(encryptedBid)

// 4. Validate result attestation
validateAuctionAttestation(auctionResp.AttestationCOSEBase64)
```

## Package Overview

| Package | Purpose | Import Path |
|---------|---------|-------------|
| `core` | Auction logic | `github.com/cloudx-io/openauction/core` |
| `enclaveapi` | Communication types | `github.com/cloudx-io/openauction/enclaveapi` |
| `enclave` | TEE server binary | `github.com/cloudx-io/openauction/enclave` |
| `validation` | Attestation validation | `github.com/cloudx-io/openauction/validation` |

## System Requirements

### For Core Package

- Go 1.25+
- Dependencies:
  - `github.com/shopspring/decimal` (monetary precision)

### For TEE Enclave

- AWS EC2 instance with Nitro Enclave support
- AWS Nitro CLI
- 2+ vCPUs, 512+ MB memory allocation

### For Validation

- PCR configuration file (`validation/pcrs.json`)
- Dependencies:
  - `github.com/fxamacker/cbor` (CBOR parsing)
  - `github.com/veraison/go-cose` (COSE verification)

## Installation

```bash
# Install core package
go get github.com/cloudx-io/openauction/core

# Install validation package
go get github.com/cloudx-io/openauction/validation

# Install all packages
go get github.com/cloudx-io/openauction/...
```

## Contributing

Contributions are welcome! Please see:
- [Development Guide](contributing/development.md) *(coming soon)*
- [Code Style Guide](contributing/code-style.md) *(coming soon)*
- [Testing Guidelines](contributing/testing.md) *(coming soon)*

## License

See [LICENSE](../LICENSE) file in repository root.

## Support

- **Issues**: [GitHub Issues](https://github.com/cloudx-io/openauction/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cloudx-io/openauction/discussions)
- **Documentation**: This site

## Version History

See [CHANGELOG.md](../CHANGELOG.md) for version history and migration guides.

## Additional Resources

### AWS Nitro Enclaves

- [AWS Nitro Enclaves Overview](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)
- [Nitro Enclaves Developer Guide](https://docs.aws.amazon.com/enclaves/)
- [Attestation Documents](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

### Cryptography

- [COSE (CBOR Object Signing and Encryption)](https://datatracker.ietf.org/doc/html/rfc8152)
- [AWS Nitro Attestation Format](https://github.com/aws/aws-nitro-enclaves-nsm-api)

---

**[← Back to Main README](../README.md)**
