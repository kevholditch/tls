package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseModeValidModes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Mode
	}{
		{"auto", "auto", ModeAuto},
		{"AUTO", "AUTO", ModeAuto},
		{"Auto", "Auto", ModeAuto},
		{" auto ", " auto ", ModeAuto},
		{"file", "file", ModeFile},
		{"FILE", "FILE", ModeFile},
		{"File", "File", ModeFile},
		{" file ", " file ", ModeFile},
		{"server", "server", ModeServer},
		{"SERVER", "SERVER", ModeServer},
		{"Server", "Server", ModeServer},
		{" server ", " server ", ModeServer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseMode(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseModeInvalidModes(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"invalid", "invalid"},
		{"unknown", "unknown"},
		{"mixed", "AutoFile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseMode(tt.input)
			assert.Error(t, err)
			assert.Equal(t, Mode(""), result)
			assert.Contains(t, err.Error(), "invalid mode")
			assert.Contains(t, err.Error(), "must be auto, file, or server")
		})
	}
}
