package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectsFileMode(t *testing.T) {
	assert.Equal(t, ModeFile, DetectMode("cert.pem"))
	assert.Equal(t, ModeFile, DetectMode("./foo.crt"))
	assert.Equal(t, ModeFile, DetectMode("./foo"))
	assert.Equal(t, ModeFile, DetectMode("/foo/bar"))
}

func TestDetectsServerMode(t *testing.T) {
	assert.Equal(t, ModeServer, DetectMode("example.com:8443"))
	assert.Equal(t, ModeServer, DetectMode("https://bar"))
	assert.Equal(t, ModeServer, DetectMode("https://bar:443"))
}
