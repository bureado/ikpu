# Debian/Ubuntu certificate-store strategy

Debian and Ubuntu share the `ca-certificates` layout and generated bundle, so
they use one ingestion strategy. The adapter treats
`/etc/ssl/certs/ca-certificates.crt` as the authoritative certificate snapshot.
An explicit `--bundle` path can be supplied for testing or nonstandard
installations.

## Ingestion and package hooks

Run the sync after the distro has regenerated its trust bundle. This can be
called from a package post-install script:

```sh
update-ca-certificates
upki cert-store sync --distro debian --store /var/lib/upki/certificates.store
```

For Ubuntu, use `--distro ubuntu`. Alternatively, install a script in
`/etc/ca-certificates/update.d`; `update-ca-certificates` invokes those scripts
after updating the generated bundle. The hook may ignore its added/removed path
arguments and call the same `upki cert-store sync` command to reload the full
snapshot. Sync is idempotent, skips cloning known fingerprints, and removes
distro-managed entries absent from the newly generated bundle.

When `--distro` is omitted, the CLI uses `whatadistro` to inspect
`/etc/os-release`. Debian and Ubuntu use this bundle strategy. Alpine uses the
same bundle path and format but is documented separately in
[ALPINE.md](ALPINE.md). Fedora and the RHEL family use a separate
[p11-kit strategy](FEDORA.md). The `--bundle` option is intended for the same
PEM bundle format and is not accepted by the Fedora/RHEL strategy.

## Administrator certificates and revocation

Certificates in the generated distro bundle are tracked as distro-managed.
To retain an administrator-managed certificate independently of that bundle,
import it explicitly:

```sh
upki cert-store import --store /var/lib/upki/certificates.store < local-ca.pem
```

Manual entries take precedence over a distro entry with the same fingerprint
and survive distro syncs. `list --show-source` reports each entry's provenance.
The bundle itself does not identify which certificates originated from
`/usr/local/share/ca-certificates`, so certificates there are treated as part of
the distro snapshot unless also imported explicitly.

Sync and import check each certificate against upki's configured local
revocation data. Known-revoked certificates are skipped unless
`--allow-revoked` is passed. Revocation data must be available, and the issuer
must be present in the supplied certificate set for the check to run. This is
not chain validation and does not establish that a certificate is trusted.

## Presentation and consumer compatibility

OpenSSL on Debian/Ubuntu normally reads the generated PEM bundle and hashed
certificate directory under `/etc/ssl/certs`. This experimental store does not
replace or modify either path; applications continue to use the distro store.
The shared presentation-strategy interface currently returns an unsupported
result. Future strategies may provide conventional PEM/hash-directory exports,
FUSE views, or fs-verity-backed files without changing ingestion.
A future `upki cert-store serve` command would own that replacement/presentation
step; `sync` remains an import into the independent snapshot.

The distro bundle's PEM blocks are stored as DER bytes. Trust purpose,
distrust attributes, and local-versus-package origin are not recoverable from
the bundle alone. The [Fedora/RHEL p11-kit strategy](FEDORA.md) instead delegates
policy selection to the system tool and snapshots only server-authentication
anchors.
