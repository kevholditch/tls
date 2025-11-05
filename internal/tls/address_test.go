package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAddress_StandardHostWithDefaultPort(t *testing.T) {
	address, err := GetAddress("example.com", 443)

	assert.NoError(t, err)
	assert.Equal(t, "example.com:443", address)
}

func TestGetAddress_StandardHostWithPortProvided(t *testing.T) {
	address, err := GetAddress("example.com:8443", 443)

	assert.NoError(t, err)
	assert.Equal(t, "example.com:8443", address)
}

func TestGetAddress_NoHostProvided(t *testing.T) {
	address, err := GetAddress("", 443)

	assert.Equal(t, ErrNoHostProvided, err)
	assert.Equal(t, "", address)
}

func TestGetAddress_ColonWithEmptyPortShouldReturnError(t *testing.T) {
	address, err := GetAddress("example.com:", 443)

	assert.Equal(t, NewErrInvalidHost("example.com:"), err)
	assert.Equal(t, "", address)
}

func TestGetAddress_PortNotANumberShouldReturnError(t *testing.T) {
	address, err := GetAddress("example.com:fff", 443)

	assert.Equal(t, NewErrInvalidHost("example.com:fff"), err)
	assert.Equal(t, "", address)
}

