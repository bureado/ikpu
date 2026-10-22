# upki-cli

The `upki` command-line tool: browser-grade certificate revocation checking for
monitoring, testing and alerting, with an experimental local certificate-store
snapshot.

It uses [upki](https://github.com/rustls/upki)'s
[crlite-clubcard](https://eprint.iacr.org/2025/610) revocation data, which
updates several times per day. The CLI both synchronizes that data and checks
certificates against it.

## Usage

```
Platform-independent browser-grade certificate infrastructure

Usage: upki [OPTIONS] <COMMAND>

Commands:
  fetch             Update the local cache of crlite filters, downloading them as needed
  verify            Verifies the local cache of crlite filters
  revocation        Checks the revocation status of a certificate
  cert-store        Maintain and query the independent certificate store
  show-config-path  Print the location of the configuration file
  show-config       Print the configuration that will be used
  help              Print this message or the help of the given subcommand(s)

Options:
      --config-file <CONFIG_FILE>  Use this specific configuration file.  This must exist
      --verbose                    Emit logging output
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

For example, sync from the Debian/Ubuntu system bundle after its normal
certificate update, then list or export certificates by SHA-256 fingerprint.
`--distro` is optional when the current distribution can be autodetected:

```sh
update-ca-certificates
upki cert-store sync --store /var/lib/upki/certificates.store
upki cert-store sync --distro ubuntu --store /var/lib/upki/certificates.store
upki cert-store list --store /var/lib/upki/certificates.store
upki cert-store list --show-source --store /var/lib/upki/certificates.store
upki cert-store export --store /var/lib/upki/certificates.store --fingerprint <sha256> > certificate.der
```

Administrator-managed certificates can be imported from PEM standard input:

```sh
upki cert-store import --store /var/lib/upki/certificates.store < administrator-cas.pem
```

Sync and import require the configured local revocation data, skip certificates
known to be revoked, and accept `--allow-revoked` as an explicit override.
Manual entries take precedence over distro entries and survive authoritative
syncs. The Debian/Ubuntu strategy is documented in
[its specification](../upki/src/cert_store/distro/README.md).

The store preserves certificate bytes and provenance; it does not perform
certificate-chain verification or reproduce distro trust/distrust attributes.

## License

This crate is distributed under the terms of both the Apache License (Version
2.0) and the MIT license, at your option. See [LICENSE-APACHE] and [LICENSE-MIT]
in the repository root for details.

[LICENSE-APACHE]: https://github.com/rustls/upki/blob/main/LICENSE-APACHE
[LICENSE-MIT]: https://github.com/rustls/upki/blob/main/LICENSE-MIT
