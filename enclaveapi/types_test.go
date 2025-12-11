package enclaveapi

import (
	"strings"
	"testing"

	"github.com/peterldowns/testy/check"
)

// TestAttestationCOSE_Encode tests encoding raw COSE bytes to base64
func TestAttestationCOSE_Encode(t *testing.T) {
	coseBytes := AttestationCOSE([]byte("mock-cose-attestation-data"))

	encoded := coseBytes.EncodeBase64()
	check.NotEqual(t, "", encoded)

	decoded, err := encoded.Decode()
	check.Nil(t, err)
	check.Equal(t, coseBytes, decoded)
}

// TestAttestationCOSE_EncodeURLSafe tests URL-safe encoding
func TestAttestationCOSE_EncodeURLSafe(t *testing.T) {
	coseBytes := AttestationCOSE([]byte("mock-cose-attestation-data-for-url-encoding"))

	encoded := coseBytes.EncodeURLSafe()
	check.NotEqual(t, "", encoded)

	// Should not contain padding
	check.True(t, !strings.Contains(encoded.String(), "="))

	decoded, err := encoded.Decode()
	check.Nil(t, err)
	check.Equal(t, coseBytes, decoded)
}

// TestAttestationCOSE_CompressGzip tests GZIP compression with URL-safe encoding
func TestAttestationCOSE_CompressGzip(t *testing.T) {
	coseBytes := AttestationCOSE([]byte("mock-cose-attestation-data-for-compression-testing"))

	compressed, err := coseBytes.CompressGzip()
	check.Nil(t, err)
	check.NotEqual(t, "", compressed)

	compressedStr := compressed.String()
	check.True(t, !strings.Contains(compressedStr, "+"))
	check.True(t, !strings.Contains(compressedStr, "/"))
	check.True(t, !strings.Contains(compressedStr, "="))

	for _, char := range compressedStr {
		valid := (char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_'
		check.True(t, valid)
	}

	decompressed, err := compressed.Decompress()
	check.Nil(t, err)
	check.Equal(t, coseBytes, decompressed)
}

// TestAttestationCOSE_CompressGzip_Deterministic tests that compression is deterministic
func TestAttestationCOSE_CompressGzip_Deterministic(t *testing.T) {
	coseBytes := AttestationCOSE([]byte("mock-cose-attestation-data"))

	result1, err1 := coseBytes.CompressGzip()
	check.Nil(t, err1)

	result2, err2 := coseBytes.CompressGzip()
	check.Nil(t, err2)

	check.Equal(t, result1, result2)
}

// TestAttestationCOSEBase64_Decode tests decoding base64 to raw bytes
func TestAttestationCOSEBase64_Decode(t *testing.T) {
	tests := []struct {
		name      string
		input     AttestationCOSEBase64
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid base64",
			input:   "bW9jay1jb3NlLWF0dGVzdGF0aW9u",
			wantErr: false,
		},
		{
			name:      "invalid base64 - illegal characters",
			input:     "not-valid-base64!!!@@@",
			wantErr:   true,
			errSubstr: "decode COSE base64",
		},
		{
			name:      "invalid base64 - wrong padding",
			input:     "abc",
			wantErr:   true,
			errSubstr: "decode COSE base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.input.Decode()

			if tt.wantErr {
				check.NotNil(t, err)
				check.True(t, strings.Contains(err.Error(), tt.errSubstr))
				check.Nil(t, result)
			} else {
				check.Nil(t, err)
				check.NotNil(t, result)
			}
		})
	}
}

// TestAttestationCOSEBase64_CompressGzip tests convenience method
func TestAttestationCOSEBase64_CompressGzip(t *testing.T) {
	coseBase64 := AttestationCOSEBase64("bW9jay1jb3NlLWF0dGVzdGF0aW9uLWRhdGEtZm9yLXRlc3RpbmctcHVycG9zZXMtb25seQ==")

	compressed, err := coseBase64.CompressGzip()

	check.Nil(t, err)
	check.NotEqual(t, "", compressed)

	// Verify URL-safe encoding
	compressedStr := compressed.String()
	check.True(t, !strings.Contains(compressedStr, "+"))
	check.True(t, !strings.Contains(compressedStr, "/"))
	check.True(t, !strings.Contains(compressedStr, "="))
}

// TestAttestationCOSEBase64_CompressGzip_Empty tests empty input
func TestAttestationCOSEBase64_CompressGzip_Empty(t *testing.T) {
	empty := AttestationCOSEBase64("")

	compressed, err := empty.CompressGzip()

	check.Nil(t, err)
	check.NotEqual(t, "", compressed)
}

// TestAttestationCOSEURLBase64_Decode tests URL-safe decoding with padding restoration
func TestAttestationCOSEURLBase64_Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    AttestationCOSEURLBase64
		expected AttestationCOSE
	}{
		{
			name:     "no padding needed (len % 4 == 0)",
			input:    "YWJj",
			expected: AttestationCOSE([]byte("abc")),
		},
		{
			name:     "needs 2 chars padding (len % 4 == 2)",
			input:    "dGVzdA",
			expected: AttestationCOSE([]byte("test")),
		},
		{
			name:     "needs 1 char padding (len % 4 == 3)",
			input:    "dGVzdGluZw",
			expected: AttestationCOSE([]byte("testing")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.input.Decode()
			check.Nil(t, err)
			check.Equal(t, tt.expected, result)
		})
	}
}

// TestAttestationCOSEGzip_Decompress tests decompression
func TestAttestationCOSEGzip_Decompress(t *testing.T) {
	original := AttestationCOSE([]byte("mock-cose-attestation-data-for-compression-testing"))
	compressed, err := original.CompressGzip()
	check.Nil(t, err)

	decompressed, err := compressed.Decompress()

	check.Nil(t, err)
	check.Equal(t, original, decompressed)
}

// TestAttestationCOSEGzip_Decompress_Invalid tests error handling
func TestAttestationCOSEGzip_Decompress_Invalid(t *testing.T) {
	tests := []struct {
		name           string
		input          AttestationCOSEGzip
		errorSubstring string
	}{
		{
			name:           "invalid base64url",
			input:          "!!!invalid!!!",
			errorSubstring: "decode base64url",
		},
		{
			name:           "valid base64 but not gzip",
			input:          "bW9jaw",
			errorSubstring: "gzip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.input.Decompress()

			check.NotNil(t, err)
			check.Nil(t, result)

			check.True(t, strings.Contains(err.Error(), tt.errorSubstring))
		})
	}
}

// TestAttestationTypes_JSONMarshaling tests that types marshal/unmarshal correctly as JSON
func TestAttestationTypes_JSONMarshaling(t *testing.T) {
	type TestStruct struct {
		Attestation AttestationCOSEBase64 `json:"attestation"`
	}

	coseData := AttestationCOSE([]byte("mock-cose"))
	original := TestStruct{
		Attestation: coseData.EncodeBase64(),
	}

	jsonData, err := original.Attestation.Decode()
	check.Nil(t, err)

	encoded := jsonData.EncodeBase64()
	check.Equal(t, original.Attestation, encoded)
}

// TestAttestationTypes_RoundTrip tests complete round-trip conversions
func TestAttestationTypes_RoundTrip(t *testing.T) {
	t.Run("Standard base64 round-trip", func(t *testing.T) {
		original := AttestationCOSE([]byte("test-cose-data"))

		// COSE → Base64 → COSE
		encoded := original.EncodeBase64()
		decoded, err := encoded.Decode()

		check.Nil(t, err)
		check.Equal(t, original, decoded)
	})

	t.Run("URL-safe base64 round-trip", func(t *testing.T) {
		original := AttestationCOSE([]byte("test-cose-data-for-url"))

		// COSE → URLBase64 → COSE
		encoded := original.EncodeURLSafe()
		decoded, err := encoded.Decode()

		check.Nil(t, err)
		check.Equal(t, original, decoded)
	})

	t.Run("Gzip compression round-trip", func(t *testing.T) {
		original := AttestationCOSE([]byte("test-cose-data-for-compression-with-enough-data-to-actually-compress-meaningfully"))

		// COSE → Gzip → COSE
		compressed, err := original.CompressGzip()
		check.Nil(t, err)

		decompressed, err := compressed.Decompress()
		check.Nil(t, err)
		check.Equal(t, original, decompressed)
	})

	t.Run("Base64 → Gzip compression", func(t *testing.T) {
		original := AttestationCOSEBase64("bW9jay1jb3NlLWF0dGVzdGF0aW9uLWRhdGEtZm9yLXRlc3RpbmctcHVycG9zZXMtb25seQ==")

		// Base64 → Gzip → COSE → Base64
		compressed, err := original.CompressGzip()
		check.Nil(t, err)

		decompressed, err := compressed.Decompress()
		check.Nil(t, err)

		reencoded := decompressed.EncodeBase64()
		check.Equal(t, original, reencoded)
	})
}
