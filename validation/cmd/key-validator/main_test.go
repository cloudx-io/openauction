package main

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/peterldowns/testy/assert"
	"github.com/peterldowns/testy/check"
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
