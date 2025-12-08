package parsing

import (
	"encoding/base64"
	"fmt"

	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
)

// NitroAttestationDocument represents the raw CBOR structure from AWS Nitro Enclaves
type NitroAttestationDocument struct {
	ModuleID    string            `cbor:"module_id"`
	Digest      string            `cbor:"digest"`
	Timestamp   uint64            `cbor:"timestamp"`
	PCRs        map[uint64][]byte `cbor:"pcrs"`
	Certificate []byte            `cbor:"certificate"`
	CABundle    [][]byte          `cbor:"cabundle"`
	PublicKey   []byte            `cbor:"public_key"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
}

// FormatPCR formats PCR bytes as hex string
func FormatPCR(pcrData []byte) string {
	if len(pcrData) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", pcrData)
}

// EncodeCertificateBundle converts certificate bundle to base64 strings
func EncodeCertificateBundle(bundle [][]byte) []string {
	result := make([]string, len(bundle))
	for i, cert := range bundle {
		result[i] = base64.StdEncoding.EncodeToString(cert)
	}
	return result
}

// ExtractPCRs extracts and formats PCR values from the raw CBOR PCR map
func ExtractPCRs(rawPCRs map[uint64][]byte) enclaveapi.PCRs {
	return enclaveapi.PCRs{
		ImageFileHash:   FormatPCR(rawPCRs[0]),
		KernelHash:      FormatPCR(rawPCRs[1]),
		ApplicationHash: FormatPCR(rawPCRs[2]),
		IAMRoleHash:     FormatPCR(rawPCRs[3]),
		InstanceIDHash:  FormatPCR(rawPCRs[4]),
		SigningCertHash: FormatPCR(rawPCRs[8]),
	}
}
