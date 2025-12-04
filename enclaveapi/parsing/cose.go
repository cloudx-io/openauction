package parsing

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ExtractCOSEPayload extracts the payload from a COSE_Sign1 4-element array
// COSE_Sign1 structure: [protected, unprotected, payload, signature]
// Returns the payload bytes (element 2)
func ExtractCOSEPayload(coseBytes []byte) ([]byte, error) {
	var coseArray []any
	err := cbor.Unmarshal(coseBytes, &coseArray)
	if err != nil {
		return nil, fmt.Errorf("parse COSE array: %w", err)
	}

	if len(coseArray) != 4 {
		return nil, fmt.Errorf("invalid COSE_Sign1 structure: expected 4 elements, got %d", len(coseArray))
	}

	payload, ok := coseArray[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload in COSE structure")
	}

	return payload, nil
}
