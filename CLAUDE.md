# OpenAuction Project Guide

## Project Overview

OpenAuction is a Go library for secure, TEE-enabled auction processing with AWS Nitro Enclaves support.

**Key Features:**
- Core auction logic (bid ranking, adjustments, floor enforcement)
- TEE integration with AWS Nitro Enclaves
- End-to-end encryption (E2EE) for bid prices
- Attestation validation (PCR, certificate chain, COSE signatures)

**NOT included:**
- No federated learning or ML services
- No full application stack (this is a library, not an app)

---

## Project Structure

```
openauction/
├── core/                   # Core auction logic (stateless, thread-safe)
│   ├── types.go           # CoreBid, AuctionResult, CoreRankingResult
│   ├── auction.go         # RunAuction() - main entry point
│   ├── auctionranking.go  # RankCoreBids() with tie-breaking
│   ├── bidadjustments.go  # ApplyBidAdjustmentFactors()
│   └── floorenforcement.go # EnforceBidFloor(), BidMeetsFloor()
│
├── enclaveapi/            # Communication types and protocol
│   └── types.go           # EnclaveAuctionRequest, EnclaveAuctionResponse,
│                          # EncryptedBidPrice, AttestationDoc, PCRs
│
├── enclave/               # TEE server binary (runs in AWS Nitro Enclave)
│   ├── auction.go         # ProcessAuction() with decryption
│   ├── crypto.go          # DecryptHybrid() - RSA-OAEP + AES-GCM
│   ├── keymanager.go      # RSA key pair management
│   ├── proofs.go          # Attestation generation (CBOR/COSE)
│   └── tokenmanager.go    # Replay protection with sync.Map
│
├── validation/            # Attestation validation for bidders
│   ├── keyvalidation.go   # ValidateKeyAttestation()
│   └── attestation.go     # PCR, cert chain, COSE verification
│
└── docs/                  # Comprehensive documentation
    ├── README.md          # Documentation home
    ├── INDEX.md           # Navigation index
    ├── api/               # API references
    ├── guides/            # Usage tutorials
    └── architecture/      # System design docs
```

---

## Development Guidelines

### Code Modification Rules

**Safe to modify:**
- Documentation (docs/)
- Test files (*_test.go)
- Examples and tools

**Requires careful review:**
- Core auction logic (core/)
- Cryptographic operations (enclave/crypto.go, validation/)
- Attestation handling (enclave/proofs.go, validation/)

**Key constraints:**
- Core package must remain **stateless** and **thread-safe**
- No breaking changes to public APIs without discussion
- Maintain decimal precision (4 decimal places) for monetary values
- Preserve cryptographically secure randomness for tie-breaking

### Testing

**Run tests:**
```bash
# All tests
go test ./...

# Specific package
go test ./core
go test ./validation

# With coverage
go test -cover ./...

# Verbose
go test -v ./core
```

**Testing strategy:**
- Core package uses `RandSource` interface for deterministic testing
- Crypto operations should use test vectors
- Attestation validation requires mock attestation documents

### Dependencies

**Core dependencies:**
- `github.com/shopspring/decimal` - Monetary precision (DO NOT remove)
- `github.com/fxamacker/cbor` - CBOR parsing (attestations)
- `github.com/veraison/go-cose` - COSE signature verification

**Dependency changes:**
- Always check impact on core auction logic before updating
- Test extensively after dependency updates
- Document any version constraints in go.mod

---

## Documentation Workflow

### When to update docs:

**API changes → Update immediately:**
- New functions/methods → Add to api/ reference docs
- Changed signatures → Update both API docs and guides
- New types → Document in api/ with examples

**Breaking changes:**
- Update migration guide (if one exists)
- Update all affected examples
- Mark deprecated features clearly

**New features:**
- Add to guides/ with step-by-step tutorial
- Update INDEX.md navigation
- Add to README.md quick examples if appropriate

### Documentation structure:

```
docs/
├── api/                    # Technical API references
│   ├── core-package.md     # Core functions and types
│   ├── enclaveapi-package.md  # Communication types
│   └── validation-package.md  # Validation API
│
├── guides/                 # User-facing tutorials
│   ├── getting-started.md  # First auction, basics
│   └── e2ee-encryption.md  # E2EE step-by-step
│
├── architecture/           # System design
│   └── overview.md         # Components, data flow, security
│
├── INDEX.md               # Navigation index (keep updated!)
└── README.md              # Documentation home
```

**File reference format:**
When referencing code, use `file_path:line_number` format:
```
Example: "Tie-breaking is handled in core/auctionranking.go:127"
```

---

## Common Tasks

### Adding a new auction feature:

1. **Design phase:**
   - Check if it fits in core/ (auction logic) or needs new package
   - Ensure thread-safety and statelessness
   - Consider backward compatibility

2. **Implementation:**
   - Write tests first (TDD recommended)
   - Implement in core/ package
   - Add examples in godoc comments

3. **Documentation:**
   - Update api/core-package.md with new function/type
   - Add usage example to guides/getting-started.md
   - Update INDEX.md navigation if needed

4. **Testing:**
   - Unit tests with edge cases
   - Test with deterministic RandSource for tie-breaking
   - Benchmark if performance-critical

### Adding cryptographic features:

**CRITICAL - Security review required:**
- All crypto changes need expert review
- Use standard library crypto primitives where possible
- Never implement custom crypto algorithms
- Test with known test vectors
- Document security assumptions

**Attestation changes:**
- Maintain compatibility with AWS Nitro NSM format
- Test PCR validation with known-good measurements
- Update validation/pcrs.json if PCR format changes

### Updating dependencies:

```bash
# Check for updates
go list -m -u all

# Update specific dependency
go get -u github.com/shopspring/decimal

# Update all (CAREFUL!)
go get -u ./...

# Verify everything still works
go test ./...
go build ./...
```

**After updates:**
- Run full test suite
- Check for breaking changes in dependency changelogs
- Update go.mod and go.sum
- Test E2EE encryption/decryption still works
- Verify attestation validation still works

---

## Troubleshooting

### "Decimal precision errors"
- Check that shopspring/decimal is being used for monetary calculations
- Verify 4 decimal places precision (auction requirement)
- Never use float64 directly for prices

### "Attestation validation failing"
- Check validation/pcrs.json has correct PCR values
- Verify AWS Nitro NSM certificate chain is current
- Test with known-good attestation documents first

### "Thread-safety issues"
- Core package must be stateless - no global vars
- Use sync.Map for token manager (already implemented)
- Check for shared mutable state in new code

### "Import cycle errors"
- Core package should import nothing internal
- enclaveapi can import core
- enclave can import core and enclaveapi
- validation can import enclaveapi

**Dependency order:**
```
core (no internal imports)
  ↑
enclaveapi
  ↑
enclave, validation
```

---

## Repository Context

**Main branch:** `main`
**This is a fork:** Working copy for documentation improvements and enhancements

**Git workflow:**
```bash
# Check status
git status

# View recent commits
git log --oneline -10

# Create feature branch
git checkout -b feature/description

# Commit with descriptive message
git add .
git commit -m "feat: description of changes"

# Push to remote
git push origin feature/description
```

---

## Go Version

**Required:** Go 1.25+

Check version:
```bash
go version
```

If updating Go version:
- Test all packages
- Update go.mod
- Check CI/CD compatibility

---

## Build and Test Commands

```bash
# Build all packages
go build ./...

# Build enclave binary
cd enclave && go build -o enclave .

# Run tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run benchmarks
go test -bench=. ./core

# Check formatting
gofmt -l .

# Run linter (if golangci-lint installed)
golangci-lint run

# Tidy dependencies
go mod tidy

# Verify dependencies
go mod verify
```

---

## External Resources

**AWS Nitro Enclaves:**
- [AWS Nitro Enclaves Overview](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)
- [Nitro Enclaves Developer Guide](https://docs.aws.amazon.com/enclaves/)
- [Attestation Documents](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

**Cryptography:**
- [COSE (RFC 8152)](https://datatracker.ietf.org/doc/html/rfc8152)
- [AWS Nitro NSM API](https://github.com/aws/aws-nitro-enclaves-nsm-api)

**Project Documentation:**
- Start here: [docs/README.md](docs/README.md)
- Navigation: [docs/INDEX.md](docs/INDEX.md)
- Getting started: [docs/guides/getting-started.md](docs/guides/getting-started.md)

---

## Important Notes

### What this project IS:
- ✅ Go library for auction processing
- ✅ TEE integration framework
- ✅ E2EE encryption utilities
- ✅ Attestation validation tools

### What this project IS NOT:
- ❌ Full application with frontend/backend
- ❌ ML/federated learning platform
- ❌ Kubernetes deployment (we removed that - it was unrelated)
- ❌ General-purpose TEE framework

### When making changes:
1. **Read the relevant source files first** - Never propose changes to code you haven't read
2. **Check documentation** - Ensure docs match your changes
3. **Test thoroughly** - Especially crypto and auction logic
4. **Think about thread-safety** - Core package must be thread-safe
5. **Consider backward compatibility** - This is a library, not an app

### Documentation philosophy:
- **Comprehensive** - Cover all public APIs with examples
- **Accurate** - Code examples must be tested and working
- **Clear** - Write for developers unfamiliar with the project
- **Up-to-date** - Update docs WITH code changes, not after
