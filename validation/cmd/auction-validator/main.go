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
		bidRequestInput   = flag.String("bid-request", "", "Bid request JSON (file path or inline JSON)")
		bidResponseInput  = flag.String("bid-response", "", "Bid response JSON (file path or inline JSON)")
		notificationInput = flag.String("notification", "", "Win/loss notification params JSON (file path or inline JSON)")
		outputFormat      = flag.String("format", "text", "Output format: text or json")
		help              = flag.Bool("help", false, "Show usage information")
	)

	flag.Parse()

	// Show help
	if *help {
		showUsage()
		os.Exit(0)
	}

	// Check for required inputs
	if *bidRequestInput == "" || *bidResponseInput == "" || *notificationInput == "" {
		showUsage()
		fmt.Fprintf(os.Stderr, "\nError: All three inputs are required (--bid-request, --bid-response, --notification)\n")
		os.Exit(1)
	}

	// Parse inputs
	bidRequest, err := readJSONInput(*bidRequestInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading bid request: %v\n", err)
		os.Exit(2)
	}

	bidResponse, err := readJSONInput(*bidResponseInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading bid response: %v\n", err)
		os.Exit(2)
	}

	notification, err := readJSONInput(*notificationInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading notification: %v\n", err)
		os.Exit(2)
	}

	// Extract validation data
	validationInput, err := extractValidationInput(bidRequest, bidResponse, notification)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting validation data: %v\n", err)
		os.Exit(2)
	}

	// Validate using library
	result, err := validation.ValidateAuctionAttestation(validationInput)
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
	fmt.Println("Validates TEE auction attestations using real bid request/response data.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  auction-validator --bid-request <json> --bid-response <json> --notification <json> [options]")
	fmt.Println()
	fmt.Println("Required Flags:")
	fmt.Println("  --bid-request <json>              OpenRTB bid request (what bidder received)")
	fmt.Println("  --bid-response <json>             OpenRTB bid response (what bidder sent)")
	fmt.Println("  --notification <json>             Win/loss notification params")
	fmt.Println()
	fmt.Println("Optional Flags:")
	fmt.Println("  --format <text|json>              Output format (default: text)")
	fmt.Println("  --help                            Show this help message")
	fmt.Println()
	fmt.Println("Input Format:")
	fmt.Println("  Each flag accepts either a file path or inline JSON string.")
	fmt.Println()
	fmt.Println("Bid Request (from S3: {bidder}_request_0.json):")
	fmt.Println("  {")
	fmt.Println("    \"id\": \"auction-123\",")
	fmt.Println("    \"imp\": [{\"bidfloor\": 2.00}],")
	fmt.Println("    \"ext\": {")
	fmt.Println("      \"prebid\": {")
	fmt.Println("        \"bidadjustmentfactors\": {\"meta\": 1.0}")
	fmt.Println("      }")
	fmt.Println("    }")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("Bid Response (from S3: {bidder}_response_0.json):")
	fmt.Println("  {")
	fmt.Println("    \"seatbid\": [{")
	fmt.Println("      \"bid\": [{")
	fmt.Println("        \"id\": \"bid-123\",")
	fmt.Println("        \"price\": 2.50")
	fmt.Println("      }]")
	fmt.Println("    }]")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("Notification (from win/loss URL params):")
	fmt.Println("  {")
	fmt.Println("    \"clearing_price\": 2.50,                          // or null if no winner")
	fmt.Println("    \"is_winner\": true,                               // true for win, false for loss")
	fmt.Println("    \"attestation_cose_gzip_base64\": \"H4sIAAAA...\"")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Using files from S3 logs")
	fmt.Println("  auction-validator \\")
	fmt.Println("    --bid-request s3_logs/meta_request_0.json \\")
	fmt.Println("    --bid-response s3_logs/meta_response_0.json \\")
	fmt.Println("    --notification notification.json")
	fmt.Println()
	fmt.Println("  # Using inline JSON (winning bid)")
	fmt.Println("  auction-validator \\")
	fmt.Println("    --bid-request '{\"id\":\"auction-123\",\"imp\":[{\"bidfloor\":2.0}]}' \\")
	fmt.Println("    --bid-response '{\"seatbid\":[{\"bid\":[{\"id\":\"bid-123\",\"price\":2.5}]}]}' \\")
	fmt.Println("    --notification '{\"clearing_price\":2.5,\"is_winner\":true,\"attestation_cose_gzip_base64\":\"...\"}'")
	fmt.Println()
	fmt.Println("Exit Codes:")
	fmt.Println("  0 - Validation passed")
	fmt.Println("  1 - Validation failed")
	fmt.Println("  2 - Invalid input or runtime error")
}

func readJSONInput(input string) ([]byte, error) {
	// Try reading as file first
	if data, err := os.ReadFile(input); err == nil {
		return data, nil
	}
	// Treat as inline JSON
	return []byte(input), nil
}

func extractValidationInput(bidRequestJSON, bidResponseJSON, notificationJSON []byte) (*validation.AuctionValidationInput, error) {
	// Parse bid request
	var bidRequest map[string]interface{}
	if err := json.Unmarshal(bidRequestJSON, &bidRequest); err != nil {
		return nil, fmt.Errorf("parse bid request: %w", err)
	}

	// Parse bid response
	var bidResponse map[string]interface{}
	if err := json.Unmarshal(bidResponseJSON, &bidResponse); err != nil {
		return nil, fmt.Errorf("parse bid response: %w", err)
	}

	// Parse notification
	var notification map[string]interface{}
	if err := json.Unmarshal(notificationJSON, &notification); err != nil {
		return nil, fmt.Errorf("parse notification: %w", err)
	}

	// Extract bid floor from first impression
	bidFloor := 0.0
	if imps, ok := bidRequest["imp"].([]interface{}); ok && len(imps) > 0 {
		if imp, ok := imps[0].(map[string]interface{}); ok {
			if floor, ok := imp["bidfloor"].(float64); ok {
				bidFloor = floor
			}
		}
	}

	// Extract adjustment factors from ext.prebid.bidadjustmentfactors
	adjustmentFactors := map[string]float64{}
	if ext, ok := bidRequest["ext"].(map[string]interface{}); ok {
		if prebid, ok := ext["prebid"].(map[string]interface{}); ok {
			if factors, ok := prebid["bidadjustmentfactors"].(map[string]interface{}); ok {
				for bidder, factor := range factors {
					if f, ok := factor.(float64); ok {
						adjustmentFactors[bidder] = f
					}
				}
			}
		}
	}

	// Extract bid_id, bid_price, and optional encrypted_payload from bid response
	var bidID string
	var bidPrice float64
	var encryptedPayload string

	if seatbids, ok := bidResponse["seatbid"].([]interface{}); ok && len(seatbids) > 0 {
		if seatbid, ok := seatbids[0].(map[string]interface{}); ok {
			if bids, ok := seatbid["bid"].([]interface{}); ok && len(bids) > 0 {
				if bid, ok := bids[0].(map[string]interface{}); ok {
					if id, ok := bid["id"].(string); ok {
						bidID = id
					}
					if price, ok := bid["price"].(float64); ok {
						bidPrice = price
					}

					// Check for encrypted bid
					if ext, ok := bid["ext"].(map[string]interface{}); ok {
						if encBid, ok := ext["encrypted_bid"].(map[string]interface{}); ok {
							if payload, ok := encBid["encrypted_payload"].(string); ok {
								encryptedPayload = payload
							}
						}
					}
				}
			}
		}
	}

	if bidID == "" {
		return nil, fmt.Errorf("missing or invalid bid ID in bid response")
	}

	// Extract clearing_price from notification (can be null)
	var clearingPrice *float64
	if cp, ok := notification["clearing_price"]; ok && cp != nil {
		if cpFloat, ok := cp.(float64); ok {
			clearingPrice = &cpFloat
		}
	}

	// Extract attestation from notification
	attestationStr, ok := notification["attestation_cose_gzip_base64"].(string)
	if !ok || attestationStr == "" {
		return nil, fmt.Errorf("missing or invalid 'attestation_cose_gzip_base64' in notification")
	}

	// Extract isWinner from notification (defaults to false if not present)
	isWinner := false
	if winner, ok := notification["is_winner"].(bool); ok {
		isWinner = winner
	}

	return &validation.AuctionValidationInput{
		AttestationCOSEGzip: enclaveapi.AttestationCOSEGzip(attestationStr),
		BidID:               bidID,
		BidPrice:            bidPrice,
		EncryptedPayload:    encryptedPayload,
		BidFloor:            bidFloor,
		ClearingPrice:       clearingPrice,
		AdjustmentFactors:   adjustmentFactors,
		IsWinner:            isWinner,
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
	fmt.Printf("  Winner Valid:            %v\n", result.WinnerValid)

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
		"winner_valid":          result.WinnerValid,
		"details":               result.ValidationDetails,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(data))
}
