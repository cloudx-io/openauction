package validation

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// awsNitroRootCA is the root certificate for AWS Nitro Enclaves
// Valid until 2049-10-28, P-384 self-signed certificate
// Source: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
// Download: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// This certificate is extracted from AWS Nitro attestation CA bundles
const awsNitroRootCA = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

// ValidateCertificateChain verifies the certificate chain using AWS Nitro root CA
func ValidateCertificateChain(certB64 string, caBundleB64 []string) error {
	// Decode signing certificate
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// Build intermediate certificate pool from CA bundle
	intermediates := x509.NewCertPool()
	for _, caB64 := range caBundleB64 {
		caDER, err := base64.StdEncoding.DecodeString(caB64)
		if err != nil {
			return fmt.Errorf("decode CA certificate: %w", err)
		}
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			return fmt.Errorf("parse CA certificate: %w", err)
		}
		intermediates.AddCert(caCert)
	}

	// AWS Nitro root certificate pool
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(awsNitroRootCA)) {
		return fmt.Errorf("failed to parse AWS Nitro root CA")
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}
