package validation

// BaseValidationResult contains common validation results for all attestation types
type BaseValidationResult struct {
	PCRsValid         bool
	CertificateValid  bool
	SignatureValid    bool
	ValidationDetails []string
}

// KeyValidationResult contains validation results specific to key attestations
type KeyValidationResult struct {
	BaseValidationResult
	PublicKeyMatch bool
}

// IsValid returns true if all key validation checks passed
func (r *KeyValidationResult) IsValid() bool {
	return r.PCRsValid && r.CertificateValid && r.SignatureValid && r.PublicKeyMatch
}

// PCRSet represents a known-good set of PCR measurements
type PCRSet struct {
	PCR0       string `json:"pcr0"`
	PCR1       string `json:"pcr1"`
	PCR2       string `json:"pcr2"`
	CommitHash string `json:"commit_hash"` // openauction repo commit used to build the enclave image
}

// PCRConfig represents the PCR configuration file structure
type PCRConfig struct {
	PCRSets []PCRSet `json:"pcr_sets"`
}
