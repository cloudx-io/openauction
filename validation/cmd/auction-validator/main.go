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
	auctionInput, err := parseAuctionInput(jsonInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON input: %v\n", err)
		os.Exit(2)
	}

	// Validate using library
	result, err := validation.ValidateAuctionAttestation(auctionInput)
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
	fmt.Println("TEE Auction Attestation Validator")
	fmt.Println()
	fmt.Println("Validates TEE auction attestations and verifies bid inclusion.")
	fmt.Println("Example CLI tool demonstrating the validation library.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  auction-validator <json-input> [options]")
	fmt.Println()
	fmt.Println("Arguments:")
	fmt.Println("  <json-input>                      JSON string with bid details and attestation")
	fmt.Println()
	fmt.Println("Optional Flags:")
	fmt.Println("  --format <text|json>              Output format (default: text)")
	fmt.Println("  --help                            Show this help message")
	fmt.Println()
	fmt.Println("JSON Input Format:")
	fmt.Println("  {")
	fmt.Println("    \"bid_id\": \"bid-123\",")
	fmt.Println("    \"bid_price\": 2.50,")
	fmt.Println("    \"bid_floor\": 2.00,")
	fmt.Println("    \"clearing_price\": 2.50,                    // or null if no winner")
	fmt.Println("    \"adjustment_factors\": {\"meta\": 1.0},     // optional, defaults to {}")
	fmt.Println("    \"auction_id\": \"auction-123\",             // required for request hash")
	fmt.Println("    \"round_id\": 1,                             // required for request hash")
	fmt.Println("    \"attestation_cose_gzip_base64\": \"H4sIAAAA...\"")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Validate winning bid")
	fmt.Println("  auction-validator '{\"bid_id\":\"bid-123\",\"bid_price\":2.50,\"bid_floor\":2.00,\"clearing_price\":2.50,\"auction_id\":\"auction-123\",\"round_id\":1,\"attestation_cose_gzip_base64\":\"...\"}'")
	fmt.Println()
	fmt.Println("  # Validate losing bid (no winner)")
	fmt.Println("  auction-validator '{\"bid_id\":\"bid-456\",\"bid_price\":1.50,\"bid_floor\":2.00,\"clearing_price\":null,\"auction_id\":\"auction-123\",\"round_id\":1,\"attestation_cose_gzip_base64\":\"...\"}'")
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

func parseAuctionInput(jsonInput string) (*validation.AuctionValidationInput, error) {
	var rawInput struct {
		BidID             string                         `json:"bid_id"`
		BidPrice          float64                        `json:"bid_price"`
		BidFloor          float64                        `json:"bid_floor"`
		ClearingPrice     *float64                       `json:"clearing_price"`
		AdjustmentFactors map[string]float64             `json:"adjustment_factors"`
		AuctionID         string                         `json:"auction_id"`
		RoundID           int                            `json:"round_id"`
		Attestation       enclaveapi.AttestationCOSEGzip `json:"attestation_cose_gzip_base64"`
	}

	if err := json.Unmarshal([]byte(jsonInput), &rawInput); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if rawInput.BidID == "" {
		return nil, fmt.Errorf("missing bid_id field in JSON input")
	}

	if rawInput.BidPrice == 0 {
		return nil, fmt.Errorf("missing or zero bid_price field in JSON input")
	}

	if rawInput.Attestation.String() == "" {
		return nil, fmt.Errorf("missing attestation_cose_gzip_base64 field in JSON input")
	}

	if rawInput.AuctionID == "" {
		return nil, fmt.Errorf("missing auction_id field in JSON input")
	}

	// Initialize adjustment factors to empty map if not provided
	if rawInput.AdjustmentFactors == nil {
		rawInput.AdjustmentFactors = map[string]float64{}
	}

	return &validation.AuctionValidationInput{
		AttestationCOSEGzip: rawInput.Attestation,
		BidID:               rawInput.BidID,
		BidPrice:            rawInput.BidPrice,
		BidFloor:            rawInput.BidFloor,
		ClearingPrice:       rawInput.ClearingPrice,
		AdjustmentFactors:   rawInput.AdjustmentFactors,
		AuctionID:           rawInput.AuctionID,
		RoundID:             rawInput.RoundID,
	}, nil
}

func outputText(result *validation.AuctionValidationResult) {
	fmt.Println("TEE Auction Attestation Validator")
	fmt.Println("==================================")
	fmt.Println()

	fmt.Println("Validation Results:")
	fmt.Println("-------------------")

	fmt.Println()
	fmt.Println("Summary:")
	fmt.Printf("  PCRs Valid:              %v\n", result.PCRsValid)
	fmt.Printf("  Certificate Valid:       %v\n", result.CertificateValid)
	fmt.Printf("  Signature Valid:         %v\n", result.SignatureValid)
	fmt.Printf("  Bid Hash Valid:          %v\n", result.BidHashValid)
	fmt.Printf("  Clearing Price Valid:    %v\n", result.ClearingPriceValid)
	fmt.Printf("  Bid Floor Valid:         %v\n", result.BidFloorValid)
	fmt.Printf("  Adjustment Hash Valid:   %v\n", result.AdjustmentHashValid)
	fmt.Printf("  Request Hash Valid:      %v\n", result.RequestHashValid)

	fmt.Println()
	fmt.Println("Details:")
	for _, detail := range result.ValidationDetails {
		fmt.Printf("  - %s\n", detail)
	}

	fmt.Println()
	fmt.Println("==================================")
	if result.IsValid() {
		fmt.Println("VALIDATION: ✓ PASSED")
		fmt.Println("Exit Code: 0")
	} else {
		fmt.Println("VALIDATION: ✗ FAILED")
		fmt.Println("Exit Code: 1")
	}
}

func outputJSON(result *validation.AuctionValidationResult) {
	output := map[string]any{
		"valid":                 result.IsValid(),
		"pcrs_valid":            result.PCRsValid,
		"certificate_valid":     result.CertificateValid,
		"signature_valid":       result.SignatureValid,
		"bid_hash_valid":        result.BidHashValid,
		"clearing_price_valid":  result.ClearingPriceValid,
		"bid_floor_valid":       result.BidFloorValid,
		"adjustment_hash_valid": result.AdjustmentHashValid,
		"request_hash_valid":    result.RequestHashValid,
		"details":               result.ValidationDetails,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(data))
}
