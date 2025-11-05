package tls

import (
	"fmt"
	"strings"
)

const defaultPort = 443

type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeFile   Mode = "file"
	ModeServer Mode = "server"
)

func ParseMode(s string) (Mode, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mode := Mode(s)
	switch mode {
	case ModeAuto, ModeFile, ModeServer:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid mode: %s (must be auto, file, or server)", s)
	}
}

func DetectMode(arg string) Mode {
	a := strings.ToLower(arg)

	if strings.HasPrefix(a, "https://") || strings.HasPrefix(a, "http://") {
		return ModeServer
	}

	if strings.Contains(a, "/") {
		return ModeFile
	}

	if strings.HasSuffix(a, ".pem") {
		return ModeFile
	}

	if strings.Contains(a, ":") {
		return ModeServer
	}

	return ModeServer
}

