package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/peterldowns/testy/assert"
	"github.com/peterldowns/testy/check"

	"github.com/cloudx-io/openauction/validation"
)

// TestMissingInputExitCode runs main in a child process, because main calls os.Exit.
func TestMissingInputExitCode(t *testing.T) {
	if os.Getenv("KEY_VALIDATOR_RUN_MAIN") == "1" {
		i := slices.Index(os.Args, "--")
		os.Args = append([]string{"key-validator"}, os.Args[i+1:]...)
		main()
		return
	}

	for name, args := range map[string][]string{
		"no arguments":      nil,
		"flags but no JSON": {"--format", "json"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestMissingInputExitCode$", "--"}, args...)...)
			cmd.Env = append(os.Environ(), "KEY_VALIDATOR_RUN_MAIN=1")
			var exitErr *exec.ExitError
			assert.True(t, errors.As(cmd.Run(), &exitErr))
			check.Equal(t, 2, exitErr.ExitCode())
		})
	}
}

func TestOutputTextPrintsDetails(t *testing.T) {
	result := &validation.KeyValidationResult{
		BaseValidationResult: validation.BaseValidationResult{
			ValidationDetails: []string{"Missing certificate", "Public key mismatch: provided key does not match attested key"},
		},
	}

	r, w, err := os.Pipe()
	assert.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	stdout := os.Stdout
	t.Cleanup(func() { os.Stdout = stdout })
	os.Stdout = w
	outputText(result)
	os.Stdout = stdout
	assert.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	assert.NoError(t, err)

	want := "Details:\n  - Missing certificate\n  - Public key mismatch: provided key does not match attested key\n"
	if !check.True(t, strings.Contains(string(out), want)) {
		t.Logf("output:\n%s", out)
	}
}
