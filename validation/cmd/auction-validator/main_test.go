package main

import (
	"testing"

	"github.com/peterldowns/testy/assert"
	"github.com/peterldowns/testy/check"

	"github.com/cloudx-io/openauction/core"
)

func TestExtractValidationInput_Deals(t *testing.T) {
	bidResponse := []byte(`{"seatbid":[{"bid":[{"id":"bid-1","price":0}]}]}`)
	notification := []byte(`{"clearing_price":0,"is_winner":true,"attestation_cose_gzip_base64":"H4sI"}`)

	tests := []struct {
		name       string
		bidRequest string
		deals      []core.Deal
	}{
		{
			name:       "deals with and without a floor",
			bidRequest: `{"imp":[{"bidfloor":1.5,"pmp":{"private_auction":1,"deals":[{"id":"deal-1","bidfloor":0.25},{"id":"deal-2"}]}}]}`,
			deals:      []core.Deal{{ID: "deal-1", BidFloor: 0.25}, {ID: "deal-2", BidFloor: 0}},
		},
		{
			name:       "entries without a non-empty string id are skipped",
			bidRequest: `{"imp":[{"bidfloor":1.5,"pmp":{"deals":[{"bidfloor":1},{"id":123},{"id":""},{"id":"deal-1"}]}}]}`,
			deals:      []core.Deal{{ID: "deal-1", BidFloor: 0}},
		},
		{
			name:       "no pmp",
			bidRequest: `{"imp":[{"bidfloor":1.5}]}`,
		},
		{
			name:       "pmp without deals",
			bidRequest: `{"imp":[{"bidfloor":1.5,"pmp":{"private_auction":0}}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := extractValidationInput([]byte(tt.bidRequest), bidResponse, notification)
			assert.NoError(t, err)

			check.Equal(t, 1.5, input.BidFloor)
			check.Equal(t, tt.deals, input.Deals)
		})
	}
}

func TestExtractValidationInput_BidDealID(t *testing.T) {
	bidRequest := []byte(`{"imp":[{"bidfloor":0,"pmp":{"deals":[{"id":"deal-1","bidfloor":0}]}}]}`)
	notification := []byte(`{"clearing_price":0,"is_winner":true,"attestation_cose_gzip_base64":"H4sI"}`)

	input, err := extractValidationInput(bidRequest, []byte(`{"seatbid":[{"bid":[{"id":"bid-1","price":0,"dealid":"deal-1"}]}]}`), notification)
	assert.NoError(t, err)
	check.Equal(t, "deal-1", input.DealID)

	input, err = extractValidationInput(bidRequest, []byte(`{"seatbid":[{"bid":[{"id":"bid-1","price":1.5}]}]}`), notification)
	assert.NoError(t, err)
	check.Equal(t, "", input.DealID)
}
