package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAddress(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		defaultPort int
		want        string
		wantErr     error
	}{
		{
			name:        "standard host with default port",
			host:        "example.com",
			defaultPort: 443,
			want:        "example.com:443",
			wantErr:     nil,
		},
		{
			name:        "standard host with port provided",
			host:        "example.com:8443",
			defaultPort: 443,
			want:        "example.com:8443",
			wantErr:     nil,
		},
		{
			name:        "no host provided",
			host:        "",
			defaultPort: 443,
			want:        "",
			wantErr:     ErrNoHostProvided,
		},
		{
			name:        "colon with empty port should return error",
			host:        "example.com:",
			defaultPort: 443,
			want:        "",
			wantErr:     NewErrInvalidHost("example.com:"),
		},
		{
			name:        "port not a number should return error",
			host:        "example.com:fff",
			defaultPort: 443,
			want:        "",
			wantErr:     NewErrInvalidHost("example.com:fff"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address, err := GetAddress(tt.host, tt.defaultPort)

			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, address)
		})
	}
}
