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
binary file contains a count, fingerprint/provenance/length/data records, and a
trailing SHA-256 checksum. Version 1 snapshots had no provenance field and are
treated as distro-managed during migration. The checksum and per-entry
fingerprints detect accidental corruption and malformed snapshots; they are
**not** signatures and do not authenticate the file against an attacker who can
rewrite it. File ownership and permissions remain part of the system security
boundary.

The shared Debian/Ubuntu adapter is selected with `--distro debian` or
`--distro ubuntu`; when omitted, `whatadistro` reads `/etc/os-release` and
selects a supported adapter when possible. `sync` reads
`/etc/ssl/certs/ca-certificates.crt` by default (or an explicit `--bundle`
path). A package integration can invoke it after `update-ca-certificates`; for
example:

```sh
update-ca-certificates
upki cert-store sync --distro ubuntu --store /var/lib/upki/certificates.store
```

The Debian/Ubuntu ingestion strategy reloads the generated bundle as the
authoritative distro snapshot. It hashes every certificate, avoids copying
known fingerprints again, and removes distro-managed fingerprints absent from
the new snapshot. `upki cert-store import --store ... < file.pem` records an
administrator-managed certificate; manual records take precedence over a
distro record with the same fingerprint and are not removed by sync. Use
`list --show-source` to inspect provenance.

Before sync or import, every certificate is checked against the configured
local revocation data. Certificates known to be revoked are skipped; the
explicit `--allow-revoked` flag permits them. The revocation data must be
available, and each certificate's issuer must be present in the supplied
certificate set. This checks revocation only; it does not validate a chain or
trust decision.

The distro adapter and presentation strategy interfaces live in
`upki::cert_store::distro`. Certificate presentation is currently an explicit
unsupported stub. The Debian/Ubuntu assumptions, package-hook contract,
system paths, and OpenSSL compatibility notes are specified in
[`upki/src/cert_store/distro/README.md`](upki/src/cert_store/distro/README.md).
The CLI does not invoke `update-ca-certificates` itself or install package
hooks.

## Experimental verification interfaces

The feature prototype separates selecting anchors from verifying a particular
certificate purpose:

- `CertificateStore::verify_chain` uses webpki with caller-supplied signature
  algorithms and an explicit EKU validator. It returns the selected anchor
  fingerprint and verified intermediates. It does not check identity, signed
  application content, or revocation.
- `rustls_upki::root_store_from_cert_store` supplies roots to rustls server or
  client verifiers. `load_root_store` discovers the snapshot through the
  optional `cert-store` configuration key. Use `ServerVerifier` separately to
  retain upki's existing revocation checks.
- The C API opens snapshots, enumerates borrowed DER certificates for loading
  into a caller's verifier, and checks membership in an already-verified chain.
  It adds no signature-verification backend, matching the existing separation
  in `upki_check_revocation`. Membership is not chain verification: never pass
  a peer-presented chain, which can contain arbitrary appended certificates.
- `upki_openssl_load_cert_store` adds anchors to an `X509_STORE`, leaving
  verification and purpose policy to OpenSSL. The separate constraining
  callback rejects otherwise valid chains that do not reach the upki store.
  It does not rescue failed verification or enable hostname checking; callers
  must configure identity checks. The existing revocation callback is separate.

For discovery, an upki configuration file can include:

```toml
cert-store = "/var/lib/upki/certificates.store"
```

Snapshots are loaded into memory; recreate consumers to observe updates.
The store currently records certificate provenance, not per-purpose trust,
explicit distrust, or intermediate-blocking policy. Treating every stored
certificate as an anchor is therefore experimental, not an implementation of
the distro's complete trust policy. Parsing failures are skipped by the anchor
adapters; a loader may produce an empty usable anchor set. OpenSSL loading is
additive and can partially modify its destination before returning an error;
use a fresh store and discard it on failure.

### Coverage and remaining investigation

Explicit library integration reaches applications that use these APIs, not
every process on the machine. A generic EKU check is not complete code-signing,
CMS, S/MIME, or timestamp verification: each consumer must retain its own
identity, content-signature, time, and policy checks.

TLS interception changes where verification happens, not automatically which
store it uses. An eBPF observation tool such as Beyla should not be assumed to
perform or control peer verification. A terminating MITM proxy verifies the
upstream peer using its own stack, while the client separately verifies the
proxy certificate. Squid peek/splice does not necessarily terminate the TLS
connection. Both verification endpoints need explicit configuration where
termination occurs. Proxy-routing tools such as emBarrass exercise the tested
application's trust decisions rather than automatically enrolling this store.
No interception mechanism or universal process hook is implemented here.

Further work includes stronger malformed-input and ownership coverage,
consistent handling of unusable anchors, purpose-specific trust/distrust
semantics, and verified deployment recipes for individual consumers. The
filesystem-based compatibility fallback remains separate future work.

## Proposed roadmap

1. **Harden the core model.** Decide whether records represent certificates
   only or trust decisions as well; define CA/basic-constraints validation,
   duplicate and distrust semantics, and limits appropriate to real
   distribution stores.
2. **Expand distro adapters.** Add fixture-based package-hook and upgrade
   coverage for Debian/Ubuntu, then add a `p11-kit` adapter for Fedora/RHEL
   rather than assuming identical semantics. Evaluate Alpine's bundle-only case.
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
