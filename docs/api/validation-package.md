# Validation Package API Reference

The `validation` package provides tools for validating TEE attestations from AWS Nitro Enclaves, including PCR verification, certificate chain validation, and COSE signature verification.

## Overview

Import path: `github.com/cloudx-io/openauction/validation`

This package is used by bidders and auction participants to verify that auction results came from a genuine TEE enclave running approved code.

## Key Validation

### ValidateKeyAttestation

Validates a TEE key attestation from COSE bytes (recommended method).

```go
func ValidateKeyAttestation(
    attestationCOSEBase64 string,
    expectedPublicKey string,
) (*KeyValidationResult, error)
```

**Parameters:**
- `attestationCOSEBase64`: Base64-encoded COSE_Sign1 bytes from `KeyResponse.AttestationCOSEBase64`
- `expectedPublicKey`: PEM-encoded public key from `KeyResponse.PublicKey`

**Returns:**
- `*KeyValidationResult`: Validation results (call `result.IsValid()` for overall status)
- `error`: Only if validation cannot be performed (malformed input, missing config, etc.)

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/cloudx-io/openauction/validation"
)

func validateKey(keyResponse *enclaveapi.KeyResponse) {
    result, err := validation.ValidateKeyAttestation(
        keyResponse.AttestationCOSEBase64,
        keyResponse.PublicKey,
    )
    if err != nil {
        log.Fatalf("Validation error: %v", err)
    }

    if result.IsValid() {
        fmt.Println("✓ Key attestation is valid")
        fmt.Println("  - PCRs verified")
        fmt.Println("  - Certificate chain verified")
        fmt.Println("  - Signature verified")
        fmt.Println("  - Public key matches")
    } else {
        fmt.Println("✗ Key attestation is invalid")
        for _, detail := range result.ValidationDetails {
            fmt.Printf("  - %s\n", detail)
        }
    }
}
```

## Validation Result Types

### KeyValidationResult

Validation results specific to key attestations.

```go
type KeyValidationResult struct {
    BaseValidationResult
    PublicKeyMatch bool // Public key matches attestation
}

func (r *KeyValidationResult) IsValid() bool
```

**IsValid()** returns `true` only if all checks pass:
- PCRs match known-good values
- Certificate chain is valid
- COSE signature is valid
- Public key matches attestation

### BaseValidationResult

Common validation results for all attestation types.

```go
type BaseValidationResult struct {
    PCRsValid         bool     // PCR measurements match known-good values
    CertificateValid  bool     // Certificate chain is valid
    SignatureValid    bool     // COSE signature is valid
    ValidationDetails []string // Human-readable validation messages
}
```

**ValidationDetails** contains explanatory messages like:
- `"PCR measurements valid"`
- `"Matched PCR set: #0 (commit: abc123)"`
- `"Certificate chain verified"`
- `"COSE signature verified"`
- `"Public key matches attestation"`

Or error messages:
- `"PCR0: <hash> (no match)"`
- `"Certificate chain validation failed: <reason>"`
- `"Public key mismatch: provided key does not match attested key"`

## PCR Configuration

### PCRSet

Known-good set of PCR measurements.

```go
type PCRSet struct {
    PCR0       string `json:"pcr0"`        // EIF hash
    PCR1       string `json:"pcr1"`        // Kernel hash
    PCR2       string `json:"pcr2"`        // Application hash
    CommitHash string `json:"commit_hash"` // Git commit used to build enclave
}
```

### PCRConfig

PCR configuration file structure.

```go
type PCRConfig struct {
    PCRSets []PCRSet `json:"pcr_sets"`
}
```

**Default Location**: The package looks for PCR configuration at:
- `./validation/pcrs.json` (development)
- Embedded in binary (production - see `pcrs.json` in repo)

**Example `pcrs.json`:**

```json
{
  "pcr_sets": [
    {
      "pcr0": "a1b2c3...",
      "pcr1": "d4e5f6...",
      "pcr2": "g7h8i9...",
      "commit_hash": "abc123"
    }
  ]
}
```

### LoadPCRsFromFile

Load PCR configuration from a file.

```go
func LoadPCRsFromFile(filepath string) ([]PCRSet, error)
```

**Parameters:**
- `filepath`: Path to PCR configuration JSON file

**Returns:**
- `[]PCRSet`: Loaded PCR sets
- `error`: If file cannot be read or parsed

### DefaultPCRConfigPath

Get the default PCR configuration file path.

```go
func DefaultPCRConfigPath() string
```

**Returns:** `"./validation/pcrs.json"`

## PCR Validation

### ValidatePCRs

Validate PCRs against known-good sets.

```go
func ValidatePCRs(
    pcrs enclaveapi.PCRs,
    knownPCRSets []PCRSet,
) (match bool, matchedSetIndex int)
```

**Parameters:**
- `pcrs`: PCRs from attestation document
- `knownPCRSets`: Known-good PCR sets

**Returns:**
- `match`: `true` if PCRs match any known set
- `matchedSetIndex`: Index of matched set in `knownPCRSets`, or `-1` if no match

**Example:**

```go
knownPCRs, _ := validation.LoadPCRsFromFile("pcrs.json")
match, idx := validation.ValidatePCRs(attestation.PCRs, knownPCRs)

if match {
    fmt.Printf("PCRs match set #%d (commit: %s)\n",
        idx, knownPCRs[idx].CommitHash)
} else {
    fmt.Println("PCRs do not match any known set")
}
```

## Certificate Validation

### ValidateCertificateChain

Validate certificate chain from attestation.

```go
func ValidateCertificateChain(
    certificateB64 string,
    caBundleB64 []string,
) error
```

**Parameters:**
- `certificateB64`: Base64-encoded leaf certificate
- `caBundleB64`: Base64-encoded CA certificate chain

**Returns:**
- `nil` if chain is valid
- `error` describing validation failure

**Example:**

```go
err := validation.ValidateCertificateChain(
    attestation.Certificate,
    attestation.CABundle,
)
if err != nil {
    log.Printf("Certificate validation failed: %v", err)
}
```

## COSE Signature Validation

### VerifyCOSESignature

Verify COSE_Sign1 signature on attestation document.

```go
func VerifyCOSESignature(
    attestationCOSEBase64 string,
    certificateB64 string,
) error
```

**Parameters:**
- `attestationCOSEBase64`: Base64-encoded COSE_Sign1 bytes
- `certificateB64`: Base64-encoded certificate containing public key

**Returns:**
- `nil` if signature is valid
- `error` if signature verification fails

### ExtractCOSEPayload

Extract payload from COSE_Sign1 structure.

```go
func ExtractCOSEPayload(coseBytes []byte) ([]byte, error)
```

**Parameters:**
- `coseBytes`: Raw COSE_Sign1 bytes

**Returns:**
- Payload bytes (CBOR attestation document)
- `error` if extraction fails

## Complete Validation Example

### Validating Key Response

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/cloudx-io/openauction/enclaveapi"
    "github.com/cloudx-io/openauction/validation"
)

func main() {
    // Get key response from enclave (via HTTP or vsock)
    var keyResp enclaveapi.KeyResponse
    // ... fetch response ...

    // Validate attestation
    result, err := validation.ValidateKeyAttestation(
        keyResp.AttestationCOSEBase64,
        keyResp.PublicKey,
    )
    if err != nil {
        log.Fatalf("Validation failed: %v", err)
    }

    // Check overall status
    if !result.IsValid() {
        fmt.Println("❌ Attestation validation FAILED:")
        for _, detail := range result.ValidationDetails {
            fmt.Printf("  • %s\n", detail)
        }
        return
    }

    // All checks passed
    fmt.Println("✅ Attestation validation PASSED")
    fmt.Println("\nDetails:")
    for _, detail := range result.ValidationDetails {
        fmt.Printf("  ✓ %s\n", detail)
    }

    // Safe to use the public key for encryption
    fmt.Printf("\nPublic key verified and ready to use:\n%s\n", keyResp.PublicKey)
}
```

### Manual PCR Validation

```go
package main

import (
    "fmt"
    "log"

    "github.com/cloudx-io/openauction/validation"
)

func manualPCRValidation() {
    // Load known PCR sets
    knownPCRs, err := validation.LoadPCRsFromFile("validation/pcrs.json")
    if err != nil {
        log.Fatalf("Failed to load PCRs: %v", err)
    }

    // Parse attestation to get PCRs
    // ... (get attestation.PCRs) ...

    // Validate
    match, idx := validation.ValidatePCRs(attestation.PCRs, knownPCRs)

    if match {
        pcrSet := knownPCRs[idx]
        fmt.Printf("✓ PCRs valid (matched set #%d)\n", idx)
        fmt.Printf("  Build commit: %s\n", pcrSet.CommitHash)
        fmt.Printf("  PCR0 (EIF):   %s\n", pcrSet.PCR0[:16])
        fmt.Printf("  PCR1 (Kernel): %s\n", pcrSet.PCR1[:16])
        fmt.Printf("  PCR2 (App):    %s\n", pcrSet.PCR2[:16])
    } else {
        fmt.Println("✗ PCRs do not match any known set")
        fmt.Printf("  PCR0: %s\n", attestation.PCRs.ImageFileHash[:16])
        fmt.Printf("  PCR1: %s\n", attestation.PCRs.KernelHash[:16])
        fmt.Printf("  PCR2: %s\n", attestation.PCRs.ApplicationHash[:16])
    }
}
```

## Security Considerations

### PCR Validation

**Critical**: Always validate PCRs against known-good values. This ensures the enclave is running the expected code.

- **PCR0**: Verifies the Enclave Image File (EIF) - the exact enclave binary
- **PCR1**: Verifies the kernel and initramfs
- **PCR2**: Verifies the application code

If PCRs don't match, **do not trust the attestation**.

### Certificate Chain Validation

Certificate chain validation ensures the attestation was signed by AWS Nitro Enclaves hardware, not a malicious actor.

### COSE Signature Validation

COSE signature verification ensures the attestation hasn't been tampered with.

### Defense in Depth

All three validations (PCRs, certificate chain, COSE signature) must pass for an attestation to be considered valid. Use the `IsValid()` method to check overall status.

## Command-Line Validator

The package includes a command-line tool for validating key responses:

```bash
# Build the validator
cd validation/cmd/key-validator
go build

# Validate a key response
./key-validator --key-response response.json

# Validate with custom PCR config
./key-validator --key-response response.json --pcr-config pcrs.json
```

See `validation/cmd/key-validator/` for implementation.

## See Also

- [EnclaveAPI Package](enclaveapi-package.md) - Attestation document types
- [E2EE Guide](../guides/e2ee-encryption.md) - Using validated keys for encryption
- [PCR Documentation](../architecture/pcr-measurements.md) - Understanding PCRs
