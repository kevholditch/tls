package util

import (
	"fmt"
	"strconv"
	"strings"
)

var ErrNoHostProvided = fmt.Errorf("no host provided")

type ErrInvalidHost struct {
	Host string
}

func NewErrInvalidHost(host string) *ErrInvalidHost {
	return &ErrInvalidHost{
		Host: host,
	}
}

func (e *ErrInvalidHost) Error() string {
	return fmt.Sprintf("invalid host: %s", e.Host)
}

func GetAddress(host string, defaultPort int) (string, error) {
	if host == "" {
		return "", ErrNoHostProvided
	}
	index := strings.LastIndex(host, ":")
	if index < 0 {
		return fmt.Sprintf("%s:%d", host, defaultPort), nil
	}

	strPort := host[index+1:]
	_, err := strconv.Atoi(strPort)
	if err != nil {
		return "", NewErrInvalidHost(host)
	}

	return host, nil
}
