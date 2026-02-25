
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
