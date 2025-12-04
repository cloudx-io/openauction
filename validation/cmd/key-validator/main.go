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
		attestationPath = flag.String("attestation", "", "Path to key response JSON file (required)")
		publicKeyPath   = flag.String("public-key", "", "Path to public key PEM file (required)")
		outputFormat    = flag.String("format", "text", "Output format: text or json")
		help            = flag.Bool("help", false, "Show usage information")
	)

	flag.Parse()

	// Show help
	if *help || *attestationPath == "" || *publicKeyPath == "" {
		showUsage()
		if *attestationPath == "" || *publicKeyPath == "" {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Read key response file
	keyResponse, err := readKeyResponse(*attestationPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading attestation: %v\n", err)
		os.Exit(2)
	}

	// Read public key file
	publicKey, err := readPublicKey(*publicKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public key: %v\n", err)
		os.Exit(2)
	}

	// Validate using library
	result, err := validation.ValidateKeyAttestation(keyResponse.AttestationCOSEBase64, publicKey)
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
	fmt.Println("  tee-key-validator --attestation <path> --public-key <pem> [options]")
	fmt.Println()
	fmt.Println("Required Flags:")
	fmt.Println("  --attestation <path>              Path to key response JSON file")
	fmt.Println("  --public-key <path>               Path to public key PEM file")
	fmt.Println()
	fmt.Println("Optional Flags:")
	fmt.Println("  --format <text|json>              Output format (default: text)")
	fmt.Println("  --help                            Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Validate key attestation")
	fmt.Println("  tee-key-validator --attestation response.json --public-key public_key.pem")
	fmt.Println()
	fmt.Println("  # JSON output")
	fmt.Println("  tee-key-validator --attestation response.json --public-key public_key.pem --format json")
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

func readKeyResponse(path string) (*enclaveapi.KeyResponse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var keyResponse enclaveapi.KeyResponse
	if err := json.Unmarshal(data, &keyResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if keyResponse.AttestationCOSEBase64 == "" {
		return nil, fmt.Errorf("missing attestation_cose_base64 field in key response")
	}

	return &keyResponse, nil
}

func readPublicKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return string(data), nil
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
	output := map[string]interface{}{
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
