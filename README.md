<p align="center">
  <img width="460" src="https://raw.githubusercontent.com/rustls/upki/main/admin/upki.svg">
</p>

**upki** implements platform-independent browser-grade certificate infrastructure.

The first goal of this project is to provide reliable, privacy-preserving
and efficient certificate revocation building on foundational work by Mozilla.

Later goals include intermediate preloading, certificate transparency enforcement,
replicating common root distrust processes, and supporting deployment of
Merkle Tree Certificates.

## Revocation

This is for checking revocation status for certificates issued by publicly-trusted
authorities.  It uses [crlite-clubcard](https://eprint.iacr.org/2025/610).  This requires
a data set that updates several times per day.  `upki` therefore includes a synchronization
component, which fetches updated data.  You can run `upki fetch` to do this at any time,
but ideally it is run system-wide as [arranged by packagers](PACKAGING.md).

There are a number of interfaces available:

### Command-line interface

This is useful for monitoring, testing and alerting purposes.

```shell
$ curl -w '%{certs}' https://google.com | upki revocation check
(...)
NotRevoked
```

### C-FFI interface

This is a simple C interface to checking revocation status.  The simplest use is this
sequence of calls:

1. `upki_config_new(NULL, ..)` - finding and loading upki's configuration from a file.
   The first parameter may be used to specify where the configuration file should be found.

2. `upki_check_revocation(config, certs, certs_count)` - checking revocation status.
   `certs` is a sequence of certificates represented by `upki_certificate_der` structs,
   and is `certs_count` elements long.   This returns `UPKI_REVOCATION_REVOKED` if the
   certificate is revoked, `UPKI_REVOCATION_NOT_REVOKED` if it is OK, or another error.

3. `upki_config_free(config)`.

See [the header](https://github.com/rustls/upki/blob/main/upki/upki.h) for further
documentation, or [a minimal example](https://github.com/rustls/upki/blob/main/upki/ffi-example/).

### OpenSSL integration

The `upki-openssl` library provides `upki_openssl_verify_callback()` which is an OpenSSL verification callback
(it matches the [`SSL_verify_cb`][ssl-verify] type) that performs revocation checking. You can pass this to
[`SSL_CTX_set_verify()`][ssl-verify] or [`SSL_set_verify()`][ssl-verify].
See [the header](https://github.com/rustls/upki/blob/main/upki-openssl/upki-openssl.h) for further documentation.

[ssl-verify]: https://docs.openssl.org/3.3/man3/SSL_CTX_set_verify/

### [Rustls](https://crates.io/crates/rustls/) integration

The [`rustls-upki`](https://crates.io/crates/rustls-upki) crate provides a rustls
server certificate verifier that checks the server certificate's revocation status.

See the [documentation](http://docs.rs/rustls-upki) or [example code](https://github.com/rustls/upki/blob/main/rustls-upki/examples/simpleclient.rs):

```shell
~/src/upki/rustls-upki$ cargo -q run --example simpleclient revoked.r6.roots.globalsign.com
Error: Custom { kind: InvalidData, error: InvalidCertificate(Revoked) }
```

### Consuming cached data directly

The revocation data provided by `upki fetch` can also be consumed
directly by processing the revocation cache directory `index.bin`, and
accompanying serialized clubcard data, as described by the [C2SP upki-revocation
specification](https://c2sp.org/upki-revocation@v1.0.0).

# Certificate store

`upki::cert_store::CertificateStore` provides an experimental independent
snapshot for storing, looking up, and exporting certificates by SHA-256
fingerprint. On Debian/Ubuntu, run `sync` after `update-ca-certificates`; on
Fedora/RHEL-family systems, run it after `update-ca-trust extract`.
The distro is autodetected when possible:

```shell
upki cert-store sync --store /var/lib/upki/certificates.store
# Or specify the adapter:
upki cert-store sync --distro ubuntu --store /var/lib/upki/certificates.store
upki cert-store sync --distro fedora --store /var/lib/upki/certificates.store
upki cert-store list --store /var/lib/upki/certificates.store
upki cert-store export --store /var/lib/upki/certificates.store --fingerprint <sha256>
```

Administrator certificates can be imported from PEM on standard input with
`upki cert-store import --store ...`; they take precedence over distro-managed
entries and survive later syncs. Sync and import check certificates against
the configured local revocation data and skip revoked certificates unless
`--allow-revoked` is explicitly supplied. The commands require usable
revocation data and issuer certificates in the supplied set.

This store does not yet verify certificate chains or reproduce distro
trust/distrust policy, and certificate presentation is not implemented.
See [CERTIFICATE-STORE.md](CERTIFICATE-STORE.md) and the
[Debian/Ubuntu adapter specification](upki/src/cert_store/distro/README.md)
and [Fedora/RHEL specification](upki/src/cert_store/distro/FEDORA.md) for
assumptions, shared distro families, and limitations. Fedora/RHEL uses p11-kit
to select server-authentication CA anchors rather than reading a raw bundle;
it does not accept `--bundle`.

# Packaging

See [PACKAGING.md](PACKAGING.md).

# License

upki is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively. You
may use this software under the terms of any of these licenses, at your
option.
