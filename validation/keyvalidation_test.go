package validation

import (
	"testing"

	"github.com/peterldowns/testy/check"
)

// TestValidateKeyAttestation_UserData: an attestation without user data parses
// with nil UserData and validates as a missing public key.
func TestValidateKeyAttestation_UserData(t *testing.T) {
	for name, userData := range map[string][]byte{"absent": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			att, err := parseKeyAttestationFromCOSE(fakeAttestationCOSE(t, userData))
			if !check.NoError(t, err) {
				return
			}
			check.Nil(t, att.UserData)

			result, err := ValidateKeyAttestation(fakeAttestationCOSE(t, userData), "key")
			if !check.NoError(t, err) {
				return
			}
			check.False(t, result.PublicKeyMatch)
			check.In(t, "Public key missing from attestation", result.ValidationDetails)
		})
	}

	t.Run("present", func(t *testing.T) {
		result, err := ValidateKeyAttestation(fakeAttestationCOSE(t, []byte(`{"public_key":"key\n"}`)), "key")
		if !check.NoError(t, err) {
			return
		}
		check.True(t, result.PublicKeyMatch)
		check.In(t, "Public key matches attestation", result.ValidationDetails)
	})
}
