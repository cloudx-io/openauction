package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"

	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
	"github.com/cloudx-io/openauction/validation"
)

// plainTextHandler is a simple slog handler that writes plain text to stdout
// without timestamps or log levels - appropriate for CLI output
type plainTextHandler struct{}

func (*plainTextHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (*plainTextHandler) Handle(_ context.Context, r slog.Record) error {
	_, err := fmt.Fprintln(os.Stdout, r.Message)
	return err
}

func (h *plainTextHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *plainTextHandler) WithGroup(_ string) slog.Handler {
	return h
}

var logger = slog.New(&plainTextHandler{})

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
		if err := outputJSON(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(2)
		}
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
	logger.Info("TEE Key Attestation Validator")
	logger.Info("")
	logger.Info("Validates TEE public key attestations for E2E encryption.")
	logger.Info("Example CLI tool demonstrating the validation library.")
	logger.Info("")
	logger.Info("Usage:")
	logger.Info("  tee-key-validator --attestation <path> --public-key <pem> [options]")
	logger.Info("")
	logger.Info("Required Flags:")
	logger.Info("  --attestation <path>              Path to key response JSON file")
	logger.Info("  --public-key <path>               Path to public key PEM file")
	logger.Info("")
	logger.Info("Optional Flags:")
	logger.Info("  --format <text|json>              Output format (default: text)")
	logger.Info("  --help                            Show this help message")
	logger.Info("")
	logger.Info("Examples:")
	logger.Info("  # Validate key attestation")
	logger.Info("  tee-key-validator --attestation response.json --public-key public_key.pem")
	logger.Info("")
	logger.Info("  # JSON output")
	logger.Info("  tee-key-validator --attestation response.json --public-key public_key.pem --format json")
	logger.Info("")
	logger.Info("Exit Codes:")
	logger.Info("  0 - Validation passed")
	logger.Info("  1 - Validation failed")
	logger.Info("  2 - Invalid input or runtime error")
	logger.Info("")
	logger.Info("Library Usage:")
	logger.Info("  This CLI tool is an example. For programmatic use, import:")
	logger.Info("  github.com/cloudx-io/openauction/validation")
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
	logger.Info("TEE Key Attestation Validator")
	logger.Info("=============================")
	logger.Info("")

	logger.Info("Validation Results:")
	logger.Info("-------------------")

	logger.Info("")
	logger.Info("Summary:")
	logger.Info(fmt.Sprintf("  PCRs Valid:        %v", result.PCRsValid))
	logger.Info(fmt.Sprintf("  Certificate Valid: %v", result.CertificateValid))
	logger.Info(fmt.Sprintf("  Signature Valid:   %v", result.SignatureValid))
	logger.Info(fmt.Sprintf("  Public Key Match:  %v", result.PublicKeyMatch))

	logger.Info("")
	logger.Info("=============================")
	if result.IsValid() {
		logger.Info("VALIDATION: ✓ PASSED")
		logger.Info("Exit Code: 0")
	} else {
		logger.Info("VALIDATION: ✗ FAILED")
		logger.Info("Exit Code: 1")
	}
}

func outputJSON(result *validation.KeyValidationResult) error {
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
		return err
	}
	logger.Info(string(data))
	return nil
}
