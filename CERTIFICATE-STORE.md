# Certificate store: research and implementation plan

## Goal

Maintain a local, queryable snapshot of the certificates trusted by the
operating system, with a stable `upki` API and a small CLI suitable for
package-maintainer hooks. Keep this separate from revocation data: the trust
store answers which roots are trusted, while the existing CRLite store answers
whether an issued certificate is revoked.

## Distro integration research

- **Debian and Ubuntu:** `update-ca-certificates` consolidates enabled
  distribution certificates and local certificates into
  `/etc/ssl/certs/ca-certificates.crt`. It invokes scripts in
  `/etc/ca-certificates/update.d` with added/removed certificate paths.
  Re-reading the generated bundle after the update is preferable to applying
  those deltas independently: it provides a complete snapshot and naturally
  handles removals. References:
  [Ubuntu update-ca-certificates manual](https://manpages.ubuntu.com/manpages/noble/man8/update-ca-certificates.8.html),
  [Debian manual](https://manpages.debian.org/stable/ca-certificates/update-ca-certificates.8.en.html).
- **Fedora and RHEL family:** system-wide trust is managed with `p11-kit` and
  `update-ca-trust`, with administrator sources under `/etc/pki/ca-trust` and
  generated, application-oriented outputs. This needs a distinct adapter;
  treating an OpenSSL bundle as the authoritative source may lose trust
  attributes and distrust policy.
  Reference: [Fedora shared system certificates](https://docs.fedoraproject.org/en-US/quick-docs/using-shared-system-certificates/).
- **Alpine:** `update-ca-certificates` builds the familiar PEM bundle from
  `/usr/share/ca-certificates` and `/usr/local/share/ca-certificates`; minimal
  images may only include the static `ca-certificates-bundle` package.
  Reference: [Alpine update-ca-certificates manual](https://github.com/alpinelinux/ca-certificates/blob/master/update-ca-certificates.8).

The Debian/Ubuntu bundle is a useful first adapter because package hooks can
run `upki` after the distro's own update command and do not need to duplicate
its trust-policy interpretation. The CLI was exercised in an Ubuntu 26.04
container after installing `ca-certificates`: it ingested the generated bundle,
and the full set of 123 store fingerprints matched an independent SHA-256
calculation over every PEM certificate. This manual sync does not yet validate
package upgrade hook behavior.

## Initial implementation

The `upki::cert_store::CertificateStore` API stores DER certificates by
SHA-256 fingerprint, keeps the complete index in memory, and supports lookup,
iteration, addition, removal, and an atomic snapshot write. Its versioned
binary file contains a count, fingerprint/length/data records, and a trailing
SHA-256 checksum. The checksum and per-entry fingerprints detect accidental
corruption and malformed snapshots; they are **not** signatures and do not
authenticate the file against an attacker who can rewrite it. File ownership
and permissions remain part of the system security boundary.

`upki cert-store sync-ubuntu` replaces the snapshot from
`/etc/ssl/certs/ca-certificates.crt` (or an explicit `--bundle` path).
`list` prints fingerprints and `export` writes the matching DER certificate to
stdout. A package integration can invoke the sync command after
`update-ca-certificates`; for example:

```sh
update-ca-certificates
upki cert-store sync-ubuntu --store /var/lib/upki/certificates.store
```

This first slice deliberately does not yet build or validate certificate
chains against the trust store, validate the X.509 structure of each DER value,
retain per-certificate provenance/trust attributes, invoke distro commands
itself, or install package hooks. The Ubuntu adapter ingests PEM certificate
blocks as opaque DER records and should not be mistaken for a complete
trust-policy model.

## Proposed roadmap

1. **Harden the core model.** Decide whether records represent certificates
   only or trust decisions as well; define CA/basic-constraints validation,
   duplicate and distrust semantics, source/provenance metadata, version
   migration, and limits appropriate to real distribution stores.
2. **Build a distro adapter interface.** Model adapters as explicit snapshot
   discovery/import providers, initially with Ubuntu/Debian bundle ingestion.
   Add fixture-based tests for hook invocation, additions, removals, malformed
   input, and package upgrades. Add a `p11-kit` adapter for Fedora/RHEL rather
   than assuming identical semantics. Evaluate Alpine's bundle-only case.
3. **Provide useful queries.** Add a CLI verification operation that validates
   a presented chain and name against the loaded roots, plus certificate
   lookup/export by stable fingerprint. Define policy for missing, malformed,
   expired, or distrusted roots before wiring it into TLS consumers.
4. **Integrate TLS libraries.** Add a Rustls root-store/verifier adapter and
   an OpenSSL trust-store integration. Keep existing OpenSSL revocation
   callback behavior distinct from trust-anchor selection; test that the new
   path never weakens ordinary chain, hostname, or signature verification.
5. **Offer compatibility views.** Generate conventional PEM/hash-directory
   exports first. Only then assess a read-only FUSE projection and container
   runtime mount support. Prefer explicit host-generated snapshots or mounts
   over requiring FUSE inside containers, which is commonly unavailable or
   restricted.
6. **Operationalize.** Specify package locations, ownership, atomic updates,
   service reload behavior, rollback, and the supported distro/release matrix.
   Add postinst/scriptlet examples and CI or VM coverage for Ubuntu 26.04 and
   each subsequently supported adapter.

## Validation still needed

- Exercise the package-hook path on actual package upgrades, including a
  removed CA, not only a manually invoked import.
- Confirm the chosen store location, ownership, and permissions with the
  intended package/runtime model.
