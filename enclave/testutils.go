package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"
	"github.com/fxamacker/cbor/v2"

	"github.com/cloudx-io/openauction/enclaveapi"
)

// MockEnclaveHandle implements the Attest method for testing
type MockEnclaveHandle struct {
	AttestFunc func(options enclave.AttestationOptions) ([]byte, error)
}

func (m *MockEnclaveHandle) Attest(options enclave.AttestationOptions) ([]byte, error) {
	if m.AttestFunc != nil {
		return m.AttestFunc(options)
	}
	return nil, fmt.Errorf("mock not configured")
}

// mustDecodeHex is a helper function to decode hex strings to actual hash bytes for testing
func mustDecodeHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Sprintf("invalid hex string: %s", hexStr))
	}
	return bytes
}

// CreateMockEnclave creates a mock enclave handle for testing with realistic attestation data
func CreateMockEnclave(t *testing.T) *MockEnclaveHandle {
	t.Helper()
	return &MockEnclaveHandle{
		AttestFunc: func(options enclave.AttestationOptions) ([]byte, error) {
			// Create a minimal nested attestation document
			nestedDoc := map[string]any{
				"module_id": "test-enclave-12345",
				"digest":    "SHA384",
				"timestamp": uint64(1234567890),
				"pcrs": map[uint64][]byte{
					0: mustDecodeHex(t, "3b4cef27e672fdbcc808960a88ddfe7329dd2e367b6850c9a8d910315f0b47e4224d6db361b75e010c87691d86ca9c57"),
					1: mustDecodeHex(t, "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"),
					2: mustDecodeHex(t, "2bdd28c1d85bb3872da3617a29a6bfeb50c65750c995f92e7dac6b5f2c4c72e0f9976bdee62a0b25864d10dffb535e11"),
					3: mustDecodeHex(t, "12a333ab2d5a07bcca664f08190faae4594bb354e6ed710fa9c0d52c269a0f5eb6d9031cb821500171850778aee86c17"),
					4: mustDecodeHex(t, "f88f75c5b8234dcad266767d156ebeff821ce572ed63ecf744e0f23f838a40974927fae0cb0ee9905e306ac3c1e0e777"),
				},
				"certificate": []byte("test-certificate-data"),
				"cabundle":    [][]byte{[]byte("test-ca-cert")},
				"public_key":  []byte("test-public-key-data"),
				"user_data":   options.UserData,
				"nonce":       options.Nonce,
			}

			// Encode nested document as CBOR
			nestedBytes, _ := cbor.Marshal(nestedDoc)

			// Create AWS Nitro 4-element array format: [header, metadata, nested_doc, signature]
			result := []any{
				[]byte{0x01, 0x02, 0x03}, // Header
				map[string]any{},         // Metadata
				nestedBytes,              // Nested attestation document
				[]byte{0x04, 0x05, 0x06}, // Signature
			}

			return cbor.Marshal(result) // Proper CBOR encoding
		},
	}
}

// parseAuctionAttestationFromCOSE is a shared test helper that parses COSE attestation bytes
// and returns an AuctionAttestationDoc with parsed user data
func parseAuctionAttestationFromCOSE(t *testing.T, coseBytes enclaveapi.AttestationCOSE) *enclaveapi.AuctionAttestationDoc {
	t.Helper()

	// Parse attestation document and user data
	attestationDoc, userDataBytes, err := coseBytes.ParseAttestationDoc()
	if err != nil {
		t.Fatalf("Failed to parse attestation: %v", err)
	}

	// Parse the UserData JSON into AttestationUserData
	var userData enclaveapi.AuctionAttestationUserData
	if err := json.Unmarshal(userDataBytes, &userData); err != nil {
		t.Fatalf("Failed to unmarshal user data: %v", err)
	}

	return &enclaveapi.AuctionAttestationDoc{
		AttestationDoc: attestationDoc,
		UserData:       &userData,
	}
}
