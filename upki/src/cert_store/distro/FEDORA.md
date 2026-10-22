# Fedora/RHEL certificate-store strategy

## Research and distro families

Fedora's shared system trust store uses `p11-kit` and `update-ca-trust`, not
Debian's `update-ca-certificates` layout. Administrator policy under
`/etc/pki/ca-trust/source/` takes precedence over package policy under
`/usr/share/pki/ca-trust-source/`. Sources can contain anchors, distrusted
certificates, and purpose-specific trust attributes. Generated files under
`/etc/pki/ca-trust/extracted/` are compatibility outputs, not the complete
authoritative policy.

This strategy is shared by **Fedora and the RHEL family**: RHEL, CentOS
(including Stream), Rocky Linux, AlmaLinux, and Oracle Linux, provided their
shared system trust module and `/usr/bin/trust` are installed and enabled.
The CLI recognizes their os-release IDs (`fedora`, `rhel`, `centos`, `rocky`,
`almalinux`, `ol`). These are compatibility targets, not a tested release
matrix. Minimal images may need `ca-certificates` and `p11-kit-trust` installed.
Fedora variants with the same ID and trust configuration use the same adapter.

Arch and openSUSE also use p11-kit in some configurations, but their packaging,
source paths, and update integration need separate validation; they are not
autodetected by this adapter. Debian/Ubuntu retain their separate generated
PEM-bundle strategy. Alpine is not enabled by either family's detection.
We deliberately do not infer compatibility from `ID_LIKE` alone.

References:

- [Fedora shared system certificates](https://docs.fedoraproject.org/en-US/quick-docs/using-shared-system-certificates/)
- [RHEL shared system certificates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/securing_networks/using-shared-system-certificates_securing-networks)
- [Upstream trust command manual](https://p11-glue.github.io/p11-glue/p11-kit/manual/trust.html)
- [Upstream trust module paths and precedence](https://p11-glue.github.io/p11-glue/p11-kit/manual/trust-module.html)

The upstream manual and implementation were consulted directly: `trust extract`
accepts a destination filename, `ca-anchors` selects anchors, and `--purpose`
limits their usage. `pem-bundle` cannot represent arbitrary trust policy;
`trust-policy` or `certificates` must not be used as a substitute for anchors.

## Assumptions and design choices

The initial store holds only DER bytes and manual/distro provenance. Therefore
this adapter produces an explicitly **TLS server-authentication CA-anchor
projection**, using:

```sh
/usr/bin/trust extract --filter=ca-anchors --purpose=server-auth --format=pem-bundle <temporary-file>
```

The system p11-kit trust module resolves local precedence, anchor selection,
distrust, and purpose filtering before upki reads the result. We do not parse
raw policy files, scrape human-readable `trust list` output, or reinterpret
OpenSSL `TRUSTED CERTIFICATE` auxiliary data. The absolute executable path
avoids selecting a different `trust` from a package hook's `PATH`.
`source_path()` identifies this executable, not a PEM input file.
Extraction uses the invoking account's effective p11-kit module configuration;
system package integration should run under the intended system identity.

Each load extracts into a new private temporary directory (mode 0700 on Unix),
without modifying system outputs. Spawn errors, unsuccessful exit status (including stderr),
missing output, malformed PEM, and empty bundles fail before reconciliation
or saving; there is no fallback to a potentially stale compatibility bundle.
As with Debian/Ubuntu, an entirely empty anchor set is rejected rather than
silently clearing the store. This is a deliberate safety limitation.
`--bundle` is rejected for this adapter because an arbitrary PEM bundle cannot
prove that p11-kit applied the required policy.

Sync uses the existing revocation checks and atomic store write. It replaces
the full distro-managed set, removes missing anchors, deduplicates by SHA-256,
and preserves explicit manual imports. Local anchors selected by p11-kit
are distro-managed unless separately imported. Manual imports can deliberately
retain a certificate removed or distrusted by the distro; this store is not a
replacement for the system's policy evaluator.

The snapshot does not retain other purposes, distrust objects (including
issuer/serial-only distrust), trust attributes, or package-versus-local origin.
It cannot enforce every negative trust assertion against arbitrary chains.
Do not treat it as a general-purpose trust-policy replica or chain verifier.
`--allow-revoked` affects only upki's revocation filter, never p11-kit selection.
Using one snapshot for different adapters/purposes replaces its distro set;
there is no per-family partition or purpose metadata in the file format.

## Sync and package integration

Run after the distro's successful trust update:

```sh
update-ca-trust extract &&
    upki cert-store sync --distro fedora --store /var/lib/upki/certificates.store
```

The parent directory must already exist and have appropriate ownership.
Use `--distro rhel`, `centos`, `rocky`, `almalinux`, or `oracle-linux` for those
systems, or omit `--distro` for detection through `whatadistro`.
The sync command neither runs `update-ca-trust` nor installs a hook.

An RPM integration can invoke this sequence from its ordered post-transaction
integration after all trust source changes have completed. Unlike Debian,
there is no assumed `/etc/ca-certificates/update.d` hook here: the packager must
arrange ordering, failure reporting, and reruns after later trust updates.
Do not invoke upki recursively from a `trust extract-compat` replacement.
Revocation data and the issuers needed by the existing revocation checker
must be available, just as for Debian/Ubuntu.

## Presentation and validation boundary

The existing `UnsupportedPresentation` is the presentation stub for this
adapter. It returns an explicit error and writes no compatibility files.
Existing OpenSSL, NSS, GnuTLS, and Java consumers keep using distro-provided
bundles or PKCS#11 policy; no system paths or modules are replaced.
Future presentation must carry purpose and distrust semantics explicitly
rather than export these roots as universally trusted.

Unit fixtures cover extraction arguments, command failures, invalid/empty
output, reconciliation, and manual precedence. CLI coverage checks family
selection and prevents raw-bundle overrides.

A manual Fedora 44 container exercise with `p11-kit-trust` 0.26.5 verified
autodetection and compared every stored SHA-256 fingerprint against an
independent PEM decode of the same p11-kit server-auth extraction. All 148
baseline fingerprints matched (the count reflects that image and this test
environment, not a fixed expected Fedora root count). Repeated syncs produced
identical snapshots. Generated self-signed fixture CAs additionally verified
local anchor addition/removal, exclusion of a client-auth-only trusted
certificate, blocklist precedence over an anchor, and preservation of an
explicit manual import after removing its system anchor. An existing empty
revocation manifest/index fixture supplied usable local data; this exercise
does not establish live CRLite coverage.

The environment bind-mounted Fedora's generated TLS bundle, so
`update-ca-trust extract` could not atomically replace that file. The policy
tests used direct extraction from the live p11-kit sources and did not claim
to validate compatibility-output regeneration. Actual RPM upgrade ordering,
successful post-update hook execution, and the release/variant matrix still
require distro integration coverage.
