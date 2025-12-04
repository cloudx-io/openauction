package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	enclaveapi "github.com/cloudx-io/openauction/enclaveapi"
)

// DefaultPCRConfigPath returns the default path to the PCR configuration file
func DefaultPCRConfigPath() string {
	// Get the path to this file at runtime
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	return filepath.Join(dir, "pcrs.json")
}

// LoadPCRsFromFile loads known PCR sets from a JSON file
func LoadPCRsFromFile(path string) ([]PCRSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCR config file: %w", err)
	}

	var config PCRConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse PCR config: %w", err)
	}

	if len(config.PCRSets) == 0 {
		return nil, fmt.Errorf("no PCR sets found in config file")
	}

	return config.PCRSets, nil
}

// ValidatePCRs checks if PCRs match any known valid set
// Returns: (match bool, matched set index)
// If no match, returns (false, -1)
func ValidatePCRs(pcrs enclaveapi.PCRs, knownSets []PCRSet) (bool, int) {
	for i, knownSet := range knownSets {
		if pcrs.ImageFileHash == knownSet.PCR0 &&
			pcrs.KernelHash == knownSet.PCR1 &&
			pcrs.ApplicationHash == knownSet.PCR2 {
			return true, i
		}
	}
	return false, -1
}
