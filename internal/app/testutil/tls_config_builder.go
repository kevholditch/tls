package testutil

import (
	"crypto/tls"
)

type TlsConfigBuilder struct {
	tlsConfig *tls.Config
}

func NewTlsConfigBuilder() *TlsConfigBuilder {
	return &TlsConfigBuilder{
		tlsConfig: &tls.Config{},
	}
}
func (tcb *TlsConfigBuilder) WithCerts(certs ...tls.Certificate) *TlsConfigBuilder {
	tcb.tlsConfig.Certificates = append(tcb.tlsConfig.Certificates, certs...)
	return tcb
}

func (tcb *TlsConfigBuilder) WithCert(build func(b CertBuilder) tls.Certificate) *TlsConfigBuilder {
	tcb.tlsConfig.Certificates = append(tcb.tlsConfig.Certificates, build(CertBuilder{}))
	return tcb
}

func (tcb *TlsConfigBuilder) WithMinimumTLSVersion(version uint16) *TlsConfigBuilder {
	tcb.tlsConfig.MinVersion = version
	return tcb
}

func (tcb *TlsConfigBuilder) WithMaximumTLSVersion(version uint16) *TlsConfigBuilder {
	tcb.tlsConfig.MaxVersion = version
	return tcb
}

func (tcb *TlsConfigBuilder) Build() *tls.Config {
	return tcb.tlsConfig
}
