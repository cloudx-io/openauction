package validation

// BaseValidationResult contains common validation results for all attestation types
type BaseValidationResult struct {
	PCRsValid         bool
	CertificateValid  bool
	SignatureValid    bool
	ValidationDetails []string
}

// IsValid returns true if all base validation checks passed
func (r *BaseValidationResult) IsValid() bool {
	return r.PCRsValid && r.CertificateValid && r.SignatureValid
}

// KeyValidationResult contains validation results specific to key attestations
type KeyValidationResult struct {
	BaseValidationResult
	PublicKeyMatch bool
}

// IsValid returns true if all key validation checks passed
func (r *KeyValidationResult) IsValid() bool {
	return r.BaseValidationResult.IsValid() && r.PublicKeyMatch
}

// AuctionValidationResult contains validation results specific to auction attestations
type AuctionValidationResult struct {
	BaseValidationResult
	BidHashValid        bool
	ClearingPriceValid  bool
	BidFloorValid       bool
	AdjustmentHashValid bool
	WinnerValid         bool
}

// IsValid returns true if all auction validation checks passed
func (r *AuctionValidationResult) IsValid() bool {
	return r.BaseValidationResult.IsValid() &&
		r.BidHashValid &&
		r.ClearingPriceValid &&
		r.BidFloorValid &&
		r.AdjustmentHashValid &&
		r.WinnerValid
}

// PCRSet represents a known-good set of PCR measurements
type PCRSet struct {
	PCR0      string `json:"pcr0"`
	PCR1      string `json:"pcr1"`
	PCR2      string `json:"pcr2"`
	CommitSHA string `json:"commit_sha"` // openauction repo commit SHA used to build the enclave image
	Timestamp string `json:"timestamp"`  // ISO 8601 timestamp when the EIF was built
}

// PCRConfig represents the PCR configuration file structure
type PCRConfig struct {
	PCRSets []PCRSet `json:"pcr_sets"`
}
