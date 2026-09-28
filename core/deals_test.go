package core

import (
	"math"
	"testing"

	"github.com/peterldowns/testy/check"
)

func TestValidateDeals(t *testing.T) {
	tests := []struct {
		name    string
		deals   []Deal
		wantErr string // empty when the list is valid
	}{
		{name: "nil list", deals: nil},
		{name: "empty list", deals: []Deal{}},
		{name: "valid list", deals: []Deal{{ID: "d1", BidFloor: 0}, {ID: "d2", BidFloor: 1.50}}},
		{name: "empty ID", deals: []Deal{{ID: "d1"}, {ID: ""}}, wantErr: "deal 1 has an empty id"},
		{name: "negative floor", deals: []Deal{{ID: "d1", BidFloor: -0.50}}, wantErr: `deal "d1" has negative floor -0.5000`},
		{name: "negative zero floor", deals: []Deal{{ID: "d1", BidFloor: math.Copysign(0, -1)}}, wantErr: `deal "d1" has negative floor -0.0000`},
		{name: "NaN floor", deals: []Deal{{ID: "d1", BidFloor: math.NaN()}}, wantErr: `deal "d1" has non-finite floor NaN`},
		{name: "infinite floor", deals: []Deal{{ID: "d1", BidFloor: math.Inf(1)}}, wantErr: `deal "d1" has non-finite floor +Inf`},
		{name: "hash separator in ID", deals: []Deal{{ID: "d1|x"}}, wantErr: `deal "d1|x" has a "|" in its id`},
		{name: "repeated ID", deals: []Deal{{ID: "d1"}, {ID: "d1"}}, wantErr: `deal "d1" is listed twice`},
		{name: "repeated ID with different floors", deals: []Deal{{ID: "d1"}, {ID: "d1", BidFloor: 2}}, wantErr: `deal "d1" is listed twice`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDeals(tt.deals)
			if tt.wantErr == "" {
				check.NoError(t, err)
			} else if check.Error(t, err) {
				check.Equal(t, tt.wantErr, err.Error())
			}
		})
	}
}
