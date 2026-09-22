# Certificates the tests use

Issued once by `make-pki.sh` and kept here, so a test can reach for whatever
shape it needs without provisioning anything. They are throwaway certificates
for a loopback suite; the private keys sit beside them on purpose.

Every PKCS#12 opens with the password `stunnel-test`.

| | root | leaves | where the key was made |
|---|---|---|---|
| GOST | `gost_ca` | `gost_server`, `gost_client` | CryptoPro CSP |
| RSA | `rsa_ca` | `rsa_cpro_server`, `rsa_cpro_client` | CryptoPro CSP |
| RSA | `rsa_ca` | `rsa_ossl_server`, `rsa_ossl_client` | OpenSSL |

Both RSA families share one root, so a chain built by either stack verifies
against the same `rsa_ca.cer` whichever end made the key.

Each leaf comes as a certificate and as a PKCS#12; the OpenSSL-made ones also
keep their key in PEM, which is what an OpenSSL peer wants. The RSA root keeps
its key so that more leaves can be issued without a CSP at hand. The GOST root
does not: issuing under it needs a CSP anyway, and `make-pki.sh` reissues the
whole set.

The server certificates are `CN=127.0.0.1` with `subjectAltName` for the
loopback address and the name `localhost`, and carry serverAuth; the client
ones carry clientAuth.

## Installing one

The msspi side takes its certificate from the CSP store, so a leaf goes in once
as a container and is named in the configuration by its thumbprint, never by a
file or a password:

```sh
certmgr -install -pfx -silent -file gost_server.pfx -pin stunnel-test -newpin ''
```

The `rsa_cpro_*` pair needs `-provtype 24` on that line. The import is what tags
the container with a provider type, and an RSA key left under the GOST default
is taken for a GOST one and refused when it is first used. `tests/msspi/run.py`
installs what its scenarios need this way; the `rsa_ossl_*` keys stay in PEM and
PKCS#12, which is what an OpenSSL peer reads.

## Validity

Everything runs to 2068, forty-two years. Longer was available for RSA but not
for GOST: the CSP wraps a validity over about 24700 days - 25000 comes back as
1959, while 24700 still lands in 2094 - and this keeps well clear of that edge.

## Reissuing

```sh
EXTERNAL_CSP_LICENSE=<licence> ./make-pki.sh
```

Inside a container with the CryptoPro CSP, writing over what is here. It is the
only step that needs a CSP: the tests take the artefacts as they are.
