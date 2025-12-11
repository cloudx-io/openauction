package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
	"github.com/cloudx-io/openauction/validation"
)

func main() {
	// Define CLI flags
	var (
		outputFormat = flag.String("format", "text", "Output format: text or json")
		help         = flag.Bool("help", false, "Show usage information")
	)

	flag.Parse()

	// Show help
	if *help {
		showUsage()
		os.Exit(0)
	}

	// Check for JSON input argument
	if flag.NArg() == 0 {
		showUsage()
		fmt.Fprintf(os.Stderr, "\nError: JSON input is required\n")
		os.Exit(1)
	}

	// Parse JSON input
	jsonInput := flag.Arg(0)
	keyWithAttestation, err := parseKeyWithAttestation(jsonInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON input: %v\n", err)
		os.Exit(2)
	}

	// Convert AttestationCOSEGzip to AttestationCOSEBase64
	attestationCOSE, err := keyWithAttestation.Attestation.Decompress()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decompressing attestation: %v\n", err)
		os.Exit(2)
	}
	attestationCOSEBase64 := attestationCOSE.EncodeBase64()

	// Validate using library
	result, err := validation.ValidateKeyAttestation(attestationCOSEBase64, keyWithAttestation.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
		os.Exit(2)
	}

	// Output results
	if *outputFormat == "json" {
		outputJSON(result)
	} else {
		outputText(result)
	}

	// Exit with appropriate code
	if !result.IsValid() {
		os.Exit(1)
	}
	os.Exit(0)
}

func showUsage() {
	fmt.Println("TEE Key Attestation Validator")
	fmt.Println()
	fmt.Println("Validates TEE public key attestations for E2E encryption.")
	fmt.Println("Example CLI tool demonstrating the validation library.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  tee-key-validator <json-input> [options]")
	fmt.Println()
	fmt.Println("Arguments:")
	fmt.Println("  <json-input>                      JSON string containing public_key and attestation_cose_gzip_base64")
	fmt.Println()
	fmt.Println("Optional Flags:")
	fmt.Println("  --format <text|json>              Output format (default: text)")
	fmt.Println("  --help                            Show this help message")
	fmt.Println()
	fmt.Println("JSON Input Format:")
	fmt.Println("  {")
	fmt.Println("    \"public_key\": \"-----BEGIN PUBLIC KEY-----\\n...\",")
	fmt.Println("    \"attestation_cose_gzip_base64\": \"H4sIAAAA...\"")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Validate key attestation")
	fmt.Println("  tee-key-validator '{\"public_key\":\"...\",\"attestation_cose_gzip_base64\":\"...\"}'")
	fmt.Println()
	fmt.Println("  # JSON output")
	fmt.Println("  tee-key-validator --format json '{\"public_key\":\"...\",\"attestation_cose_gzip_base64\":\"...\"}'")
	fmt.Println()
	fmt.Println("Exit Codes:")
	fmt.Println("  0 - Validation passed")
	fmt.Println("  1 - Validation failed")
	fmt.Println("  2 - Invalid input or runtime error")
	fmt.Println()
	fmt.Println("Library Usage:")
	fmt.Println("  This CLI tool is an example. For programmatic use, import:")
	fmt.Println("  github.com/cloudx-io/openauction/validation")
}

func parseKeyWithAttestation(jsonInput string) (*enclaveapi.KeyWithAttestation, error) {
	var keyWithAttestation enclaveapi.KeyWithAttestation
	if err := json.Unmarshal([]byte(jsonInput), &keyWithAttestation); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if keyWithAttestation.PublicKey == "" {
		return nil, fmt.Errorf("missing public_key field in JSON input")
	}

	if keyWithAttestation.Attestation.String() == "" {
		return nil, fmt.Errorf("missing attestation_cose_gzip_base64 field in JSON input")
	}

	return &keyWithAttestation, nil
}

func outputText(result *validation.KeyValidationResult) {
	fmt.Println("TEE Key Attestation Validator")
	fmt.Println("=============================")
	fmt.Println()

	fmt.Println("Validation Results:")
	fmt.Println("-------------------")

	fmt.Println()
	fmt.Println("Summary:")
	fmt.Printf("  PCRs Valid:        %v\n", result.PCRsValid)
	fmt.Printf("  Certificate Valid: %v\n", result.CertificateValid)
	fmt.Printf("  Signature Valid:   %v\n", result.SignatureValid)
	fmt.Printf("  Public Key Match:  %v\n", result.PublicKeyMatch)

	fmt.Println()
	fmt.Println("=============================")
	if result.IsValid() {
		fmt.Println("VALIDATION: ✓ PASSED")
		fmt.Println("Exit Code: 0")
	} else {
		fmt.Println("VALIDATION: ✗ FAILED")
		fmt.Println("Exit Code: 1")
	}
}

func outputJSON(result *validation.KeyValidationResult) {
	output := map[string]any{
		"valid":             result.IsValid(),
		"pcrs_valid":        result.PCRsValid,
		"certificate_valid": result.CertificateValid,
		"signature_valid":   result.SignatureValid,
		"public_key_match":  result.PublicKeyMatch,
		"details":           result.ValidationDetails,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(data))
}
