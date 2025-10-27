
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

