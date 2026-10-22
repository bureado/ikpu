use core::error::Error as StdError;
use core::{fmt, ptr};

use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, PathBuilder};

use super::{CertificateStore, Fingerprint};
use crate::sha256;

impl CertificateStore {
    /// Return the stored certificates that can be used as trust anchors.
    ///
    /// Certificates that cannot be parsed as trust anchors are skipped. Every
    /// stored certificate is currently treated as an anchor for every purpose;
    /// see `CERTIFICATE-STORE.md` for the per-purpose trust limitation.
    pub fn trust_anchors(&self) -> Vec<(Fingerprint, TrustAnchor<'static>)> {
        self.iter()
            .filter_map(|(fingerprint, der)| {
                let der = CertificateDer::from(der);
                webpki::anchor_from_trusted_cert(&der)
                    .ok()
                    .map(|anchor| (fingerprint, anchor.to_owned()))
            })
            .collect()
    }

    /// Find where a chain that was **already verified** elsewhere meets this store.
    ///
    /// `verified_chain` is ordered from the end-entity certificate (depth 0)
    /// towards the trust anchor, as produced by another verifier such as
    /// OpenSSL's `X509_STORE_CTX_get0_chain()`. This performs no signature or
    /// name checks: it only reports whether a certificate in the chain is in the
    /// store, returning the match closest to the anchor.
    ///
    /// Never pass a peer-presented chain here: a peer can append any public
    /// certificate to the chain it sends. The result is only meaningful as a
    /// constraint applied after successful verification.
    pub fn find_anchor<'a>(
        &self,
        verified_chain: impl IntoIterator<Item = &'a [u8]>,
    ) -> Option<StoreMatch> {
        let mut found = None;
        for (depth, der) in verified_chain.into_iter().enumerate() {
            let fingerprint = Fingerprint(sha256::Digest::from(&[der][..]).0);
            if self.get(&fingerprint) == Some(der) {
                found = Some(StoreMatch { depth, fingerprint });
            }
        }
        found
    }

    /// Verify that `end_entity` chains back to a certificate in this store.
    ///
    /// Path building and signature verification use `rustls-webpki`. The
    /// caller supplies the signature algorithms, so this crate does not choose
    /// a cryptography provider. `usage` selects the purpose being verified, for
    /// example `webpki::ExtendedKeyUsage::SERVER_AUTH` for TLS servers or
    /// `ExtendedKeyUsage::required(..)` with a code-signing OID.
    ///
    /// This verifies the certificate path only. Callers must still verify any
    /// purpose-specific identity, such as a TLS server name.
    pub fn verify_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        usage: &dyn ExtendedKeyUsageValidator,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
        now: UnixTime,
    ) -> Result<VerifiedChain, VerifyError> {
        let (fingerprints, anchors): (Vec<_>, Vec<_>) = self.trust_anchors().into_iter().unzip();
        if anchors.is_empty() {
            return Err(VerifyError::NoTrustAnchors);
        }

        let end_entity = EndEntityCert::try_from(end_entity).map_err(VerifyError::Webpki)?;
        let path = PathBuilder::new(intermediates, None, usage, algorithms, &anchors)
            .build(&end_entity, now)
            .map_err(VerifyError::Webpki)?;

        let anchor = anchors
            .iter()
            .position(|anchor| ptr::eq(anchor, path.anchor()))
            .map(|index| fingerprints[index])
            .ok_or(VerifyError::AnchorNotFound)?;
        let intermediates = path
            .intermediate_certificates()
            .map(|cert| cert.der().into_owned())
            .collect();

        Ok(VerifiedChain {
            anchor,
            intermediates,
        })
    }
}

/// The store certificate found in an already-verified chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreMatch {
    /// Position in the chain, where the end-entity certificate is depth 0.
    pub depth: usize,
    /// Fingerprint of the matching store certificate.
    pub fingerprint: Fingerprint,
}

/// A certificate path verified against a [`CertificateStore`].
#[derive(Debug)]
pub struct VerifiedChain {
    anchor: Fingerprint,
    intermediates: Vec<CertificateDer<'static>>,
}

impl VerifiedChain {
    /// The fingerprint of the store certificate used as the trust anchor.
    pub fn anchor(&self) -> Fingerprint {
        self.anchor
    }

    /// The intermediate certificates in the verified path, ordered from the
    /// end-entity issuer towards the anchor.
    ///
    /// Policy that is not expressed by the store, such as distrusting a
    /// specific compromised intermediate, can be applied to this path.
    pub fn intermediates(&self) -> &[CertificateDer<'static>] {
        &self.intermediates
    }
}

/// Errors returned by [`CertificateStore::verify_chain`].
#[derive(Debug)]
#[non_exhaustive]
pub enum VerifyError {
    /// The store contains no certificates usable as trust anchors.
    NoTrustAnchors,
    /// Path building or certificate validation failed.
    Webpki(webpki::Error),
    /// The verified anchor could not be mapped back to a store certificate.
    AnchorNotFound,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustAnchors => write!(f, "certificate store has no usable trust anchors"),
            Self::Webpki(error) => write!(f, "certificate chain verification failed: {error}"),
            Self::AnchorNotFound => write!(f, "verified anchor is not in the certificate store"),
        }
    }
}

impl StdError for VerifyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Webpki(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use rustls::crypto::aws_lc_rs::default_provider;
    use webpki::ExtendedKeyUsage;

    use super::*;

    const ROOT: &[u8] = include_bytes!("../../tests/data/cert-store-chain/root.der");
    const OTHER_ROOT: &[u8] = include_bytes!("../../tests/data/cert-store-chain/other-root.der");
    const INTERMEDIATE: &[u8] = include_bytes!("../../tests/data/cert-store-chain/inter.der");
    const LEAF: &[u8] = include_bytes!("../../tests/data/cert-store-chain/leaf.der");
    // 2030-01-01T00:00:00Z, inside the fixtures' validity period.
    const NOW: UnixTime = UnixTime::since_unix_epoch(Duration::from_secs(1_893_456_000));
    // id-kp-codeSigning, 1.3.6.1.5.5.7.3.3
    const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

    fn verify(
        store: &CertificateStore,
        usage: &dyn ExtendedKeyUsageValidator,
    ) -> Result<VerifiedChain, VerifyError> {
        store.verify_chain(
            &CertificateDer::from(LEAF),
            &[CertificateDer::from(INTERMEDIATE)],
            usage,
            default_provider()
                .signature_verification_algorithms
                .all,
            NOW,
        )
    }

    #[test]
    fn verifies_chain_to_store_anchor() {
        let mut store = CertificateStore::new();
        store.add(OTHER_ROOT).unwrap();
        let root = store.add(ROOT).unwrap();

        let chain = verify(&store, &ExtendedKeyUsage::SERVER_AUTH).unwrap();
        assert_eq!(chain.anchor(), root);
        assert_eq!(chain.intermediates(), &[CertificateDer::from(INTERMEDIATE)]);
    }

    #[test]
    fn rejects_chain_without_store_anchor() {
        let mut store = CertificateStore::new();
        store.add(OTHER_ROOT).unwrap();

        assert!(matches!(
            verify(&store, &ExtendedKeyUsage::SERVER_AUTH),
            Err(VerifyError::Webpki(webpki::Error::UnknownIssuer))
        ));
        assert!(matches!(
            verify(&CertificateStore::new(), &ExtendedKeyUsage::SERVER_AUTH),
            Err(VerifyError::NoTrustAnchors)
        ));
    }

    #[test]
    fn enforces_requested_purpose() {
        let mut store = CertificateStore::new();
        store.add(ROOT).unwrap();

        assert!(matches!(
            verify(&store, &ExtendedKeyUsage::required(CODE_SIGNING)),
            Err(VerifyError::Webpki(webpki::Error::RequiredEkuNotFound(_)))
        ));
    }

    #[test]
    fn skips_unparsable_anchors() {
        let mut store = CertificateStore::new();
        store.add(b"not a certificate").unwrap();
        let root = store.add(ROOT).unwrap();

        let anchors = store.trust_anchors();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].0, root);
    }

    #[test]
    fn finds_store_certificate_in_verified_chain() {
        let mut store = CertificateStore::new();
        let root = store.add(ROOT).unwrap();

        let chain = [LEAF, INTERMEDIATE, ROOT];
        assert_eq!(
            store.find_anchor(chain),
            Some(StoreMatch {
                depth: 2,
                fingerprint: root,
            })
        );
        assert_eq!(store.find_anchor([LEAF, INTERMEDIATE]), None);

        let intermediate = store.add(INTERMEDIATE).unwrap();
        assert_eq!(
            store.find_anchor([LEAF, INTERMEDIATE]),
            Some(StoreMatch {
                depth: 1,
                fingerprint: intermediate,
            })
        );
    }
}
