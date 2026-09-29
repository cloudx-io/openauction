package core

import (
	"fmt"
	"math"
	"strings"
)

// ValidateDeals reports the first malformed entry in a round's deal list: an
// empty ID, an ID containing "|" (the bid hash separator), a non-finite floor,
// a negative floor (including -0), or an ID listed twice. The enclave rejects a
// request whose deal list fails it.
func ValidateDeals(deals []Deal) error {
	seen := make(map[string]bool, len(deals))
	for i, deal := range deals {
		switch {
		case deal.ID == "":
			return fmt.Errorf("deal %d has an empty id", i)
		case strings.Contains(deal.ID, "|"):
			return fmt.Errorf("deal %q has a \"|\" in its id", deal.ID)
		case math.IsNaN(deal.BidFloor) || math.IsInf(deal.BidFloor, 0):
			return fmt.Errorf("deal %q has non-finite floor %v", deal.ID, deal.BidFloor)
		case math.Signbit(deal.BidFloor):
			return fmt.Errorf("deal %q has negative floor %.4f", deal.ID, deal.BidFloor)
		case seen[deal.ID]:
			return fmt.Errorf("deal %q is listed twice", deal.ID)
		}
		seen[deal.ID] = true
	}
	return nil
}

// findDeal returns the listed deal that dealID names. An empty dealID names
// no deal, even in a list that holds an entry with an empty ID.
func findDeal(deals []Deal, dealID string) (Deal, bool) {
	if dealID == "" {
		return Deal{}, false
	}
	for _, deal := range deals {
		if deal.ID == dealID {
			return deal, true
		}
	}
	return Deal{}, false
}
