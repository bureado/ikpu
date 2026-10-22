# Alpine certificate-store strategy

Alpine's `ca-certificates` package generates
`/etc/ssl/certs/ca-certificates.crt`, the concatenated PEM bundle used as the
authoritative certificate snapshot. This is the same path and format used by
the Debian/Ubuntu bundle strategy. The `ca-certificates-bundle` subpackage
ships the pre-generated bundle at this path and provides `/etc/ssl/cert.pem`
as a symlink to it. Upki reads the generated bundle directly; it does not scan
the source directories or select the compatibility symlink separately.

The bundle includes enabled certificates from `/usr/share/ca-certificates`
and `.crt` files from `/usr/local/share/ca-certificates`. Run sync after
`update-ca-certificates` completes:

```sh
update-ca-certificates
upki cert-store sync --distro alpine --store /var/lib/upki/certificates.store
```

The Alpine package trigger also runs `update-ca-certificates` after relevant
certificate changes. A package integration may run the same sync after that
trigger has refreshed the bundle. `--bundle` can select a nonstandard PEM
bundle path for testing or customized installations.

Sync imports the complete bundle as a distro-managed snapshot, removes
distro-managed entries missing from a later bundle, and preserves manually
imported certificates. Revocation filtering, manual precedence, and snapshot
limitations are described in the [Debian/Ubuntu bundle strategy](README.md).
