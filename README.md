
# TLS

Simple command line utility that puts the joy back into working with TLS.

Most engineers have spent more time than they care to remember googling how to do simple operations with `openssl` e.g. to view a server certificate you need 

```bash
openssl s_client -connect example.com:443 | openssl x509 -text -noout
```

Like wtf!  The fact I can now remember that tells me I need help.  Anyway TLS enables you to view a server cert using:

```bash
tls read example.com
```

No complex command chaining, no googling, simples! You don't even _need_ to provide the port, tls assumes if you don't specify you mean 443!

# Commands

## Read

The read command is for reading a certificate.  It works automatically with a server certificate or file.  

Example reading from a server:

```bash
tls read example.com

Subject:      CN=*.example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
DNS Names:    [
                *.example.com,
                example.com
              ]

Not Before:   2025-01-15T00:00:00Z
Not After:    2026-01-15T23:59:59Z
Expires In:   ✅ 71 Days 4 Hours

Issuer:       CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
Serial:       0a:d8:93:ba:fa:68:b0:b7:fb:7a:40:4f:06:ec:af:9a
Signature Algorithm:  ECDSA-SHA384
Public Key:           ECDSA (P-256, 256 bits)

Key Usage:            Digital Signature
Extended Key Usage:   Server Auth, Client Auth

Trust chain:
✅ *.example.com
✅ DigiCert Global G3 TLS ECC SHA384 2020 CA1
✅ DigiCert Global Root G3
```


Example reading from a file:

```bash
tls read ./examples/example-com.crt

Subject:      CN=*.example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
DNS Names:    [
                *.example.com,
                example.com
              ]

Not Before:   2025-01-15T00:00:00Z
Not After:    2026-01-15T23:59:59Z
Expires In:   ✅ 71 Days 4 Hours

Issuer:       CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
Serial:       0a:d8:93:ba:fa:68:b0:b7:fb:7a:40:4f:06:ec:af:9a
Signature Algorithm:  ECDSA-SHA384
Public Key:           ECDSA (P-256, 256 bits)

Key Usage:            Digital Signature
Extended Key Usage:   Server Auth, Client Auth

Trust chain:
✅ *.example.com
✅ DigiCert Global G3 TLS ECC SHA384 2020 CA1
✅ DigiCert Global Root G3
```

Notice `tls` was smart enough to figure out in the second case we were reading a file and not a server.  To force `tls` into either file mode use `--mode file` or for server mode use `--mode server`.  Normally you don't need to worry about this, so try to forget this insignificant detail and save brain cycles for important matters. 

## Explain

The explain command gives a structured breakdown of a live TLS connection, including DNS resolution, protocol negotiation, certificate validation, revocation signals, HTTP security headers, and an overall grade.

```bash
tls explain example.com
tls explain https://example.com
tls explain example.com:8443
```

`explain` only supports live server targets (host, host:port, or URL). For local certificate files use `tls read <file>`.

Example output:

```bash
tls explain example.com

────────────────────────────────────────────────────────────
 TLS CONNECTION EXPLANATION
────────────────────────────────────────────────────────────

Target:      example.com
IP Address:  93.184.216.34
Port:        443
Protocol:    https

DNS
✅ A record resolved
  example.com -> 93.184.216.34

Connection
✅ TCP connection established (22 ms)
✅ Server supports HTTP/2

TLS NEGOTIATION
Client offered: TLS 1.3, TLS 1.2
Server selected: TLS 1.3 ✅ (most secure available)

Cipher Suite
Selected:  TLS_AES_256_GCM_SHA384
Why this?
- Forward secrecy enabled
Security:  STRONG

CERTIFICATE
Subject:      CN=*.example.com,O=Example Corp,C=US
DNS Names:    [
                *.example.com,
                example.com
              ]
Not Before:   2025-01-15T00:00:00Z
Not After:    2026-01-15T23:59:59Z
Expires In:   ✅ 71 Days 4 Hours

Trust chain:
✅ *.example.com
✅ Example Intermediate CA
✅ Example Root CA

SECURITY FEATURES
✅ HSTS enabled
❌ OCSP stapling
✅ ALPN negotiation

HTTP LAYER
Protocol:     HTTP/2.0
Compression:  none
Server:       nginx

OVERALL SECURITY RATING
Grade: A
```
