//! Distro-specific ingestion and certificate-presentation strategies.

use core::error::Error as StdError;
use core::fmt;
use std::fs::File;
use std::io::{self, BufReader};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use super::{CertificateStore, Error as StoreError};

/// Ubuntu and Debian use the shared `ca-certificates` bundle strategy.
pub struct DebianUbuntu {
    bundle: PathBuf,
}

impl DebianUbuntu {
    /// Create the strategy for the generated system CA bundle.
    pub fn new(bundle: Option<PathBuf>) -> Self {
        Self {
            bundle: bundle.unwrap_or_else(|| PathBuf::from("/etc/ssl/certs/ca-certificates.crt")),
        }
    }
}

/// Fedora and the RHEL family use p11-kit to select server-auth CA anchors.
pub struct FedoraRhel;

impl FedoraRhel {
    /// Create the strategy using the system p11-kit trust executable.
    pub fn new() -> Self {
        Self
    }

    fn extract(&self, executable: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
        let mut directory = tempfile::Builder::new();
        directory.prefix("upki-anchors-");
        #[cfg(target_family = "unix")]
        directory.permissions(std::fs::Permissions::from_mode(0o700));
        let directory = directory.tempdir()?;
        let bundle = directory.path().join("anchors.pem");
        let output = Command::new(executable)
            .args([
                "extract",
                "--filter=ca-anchors",
                "--purpose=server-auth",
                "--format=pem-bundle",
            ])
            .arg(&bundle)
            .output()?;
        if !output.status.success() {
            return Err(Error::ExtractionFailed {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        load_pem_bundle(&bundle)
    }
}

/// A strategy for importing certificates from a distro-maintained source.
pub trait IngestionStrategy {
    /// Return the authoritative source or policy-extraction executable.
    fn source_path(&self) -> &Path;

    /// Read the current source snapshot.
    fn load(&self) -> Result<Vec<CertificateDer<'static>>, Error>;

    /// Replace distro-managed store entries with a verified snapshot.
    fn reconcile(
        &self,
        store: &mut CertificateStore,
        certificates: &[CertificateDer<'_>],
    ) -> Result<(), StoreError>;
}

impl IngestionStrategy for DebianUbuntu {
    fn source_path(&self) -> &Path {
        &self.bundle
    }

    fn load(&self) -> Result<Vec<CertificateDer<'static>>, Error> {
        load_pem_bundle(&self.bundle)
    }

    fn reconcile(
        &self,
        store: &mut CertificateStore,
        certificates: &[CertificateDer<'_>],
    ) -> Result<(), StoreError> {
        store.sync_distro(certificates.iter().map(AsRef::as_ref))
    }
}

impl IngestionStrategy for FedoraRhel {
    fn source_path(&self) -> &Path {
        Path::new("/usr/bin/trust")
    }

    fn load(&self) -> Result<Vec<CertificateDer<'static>>, Error> {
        self.extract(self.source_path())
    }

    fn reconcile(
        &self,
        store: &mut CertificateStore,
        certificates: &[CertificateDer<'_>],
    ) -> Result<(), StoreError> {
        store.sync_distro(certificates.iter().map(AsRef::as_ref))
    }
}

fn load_pem_bundle(bundle: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let file = File::open(bundle)?;
    let mut reader = BufReader::new(file);
    let certificates = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Error::Pem(Box::new(error)))?;
    if certificates.is_empty() {
        return Err(Error::EmptyBundle);
    }
    Ok(certificates)
}

/// A strategy for presenting stored certificates to applications.
pub trait PresentationStrategy {
    /// Present certificates at `destination`.
    fn present(&self, store: &CertificateStore, destination: &Path) -> Result<(), Error>;
}

/// Placeholder presentation strategy for integrations not implemented yet.
pub struct UnsupportedPresentation;

impl PresentationStrategy for UnsupportedPresentation {
    fn present(&self, _store: &CertificateStore, _destination: &Path) -> Result<(), Error> {
        Err(Error::PresentationUnavailable)
    }
}

/// Errors returned by distro strategies.
#[derive(Debug)]
pub enum Error {
    /// Reading the distro source failed.
    Io(io::Error),
    /// The source did not contain any PEM certificates.
    EmptyBundle,
    /// A PEM certificate could not be parsed.
    Pem(Box<dyn StdError + Send + Sync>),
    /// p11-kit failed to extract the requested trust projection.
    ExtractionFailed {
        /// Exit status of the extraction process.
        status: ExitStatus,
        /// Diagnostic output from the extraction process.
        stderr: String,
    },
    /// Certificate presentation is not implemented for this strategy.
    PresentationUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "certificate source I/O error: {error}"),
            Self::EmptyBundle => write!(f, "certificate bundle contains no certificates"),
            Self::Pem(error) => write!(f, "cannot parse certificate bundle: {error}"),
            Self::ExtractionFailed { status, stderr } => {
                write!(
                    f,
                    "p11-kit trust extraction failed ({status}): {}",
                    stderr.trim()
                )
            }
            Self::PresentationUnavailable => {
                write!(f, "certificate presentation is not implemented")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Pem(error) => Some(&**error),
            Self::EmptyBundle | Self::ExtractionFailed { .. } | Self::PresentationUnavailable => {
                None
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_ubuntu_reads_a_generated_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory
            .path()
            .join("ca-certificates.crt");
        std::fs::write(
            &bundle,
            b"-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let strategy = DebianUbuntu::new(Some(bundle));
        let certificates = strategy.load().unwrap();
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].as_ref(), b"cert");
    }

    #[test]
    fn debian_ubuntu_rejects_an_empty_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory
            .path()
            .join("ca-certificates.crt");
        std::fs::write(&bundle, b"").unwrap();

        let strategy = DebianUbuntu::new(Some(bundle));
        assert!(matches!(strategy.load(), Err(Error::EmptyBundle)));
    }

    #[cfg(unix)]
    fn trust_fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("trust");
        std::fs::write(&executable, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        (directory, executable)
    }

    #[cfg(unix)]
    #[test]
    fn fedora_rhel_extracts_server_auth_anchors_and_reconciles() {
        let (_directory, executable) = trust_fixture(
            r#"
test "$#" -eq 5
test "$1" = extract
test "$2" = --filter=ca-anchors
test "$3" = --purpose=server-auth
test "$4" = --format=pem-bundle
test ! -e "$5"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'Y2VydA==' '-----END CERTIFICATE-----' > "$5"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'Y2VydA==' '-----END CERTIFICATE-----' >> "$5"
"#,
        );
        let strategy = FedoraRhel::new();
        let certificates = strategy.extract(&executable).unwrap();
        assert_eq!(certificates.len(), 2);
        assert_eq!(certificates[0].as_ref(), b"cert");

        let mut store = CertificateStore::new();
        store
            .sync_distro([b"removed".as_slice()])
            .unwrap();
        let manual = store.add(b"manual").unwrap();
        strategy
            .reconcile(&mut store, &certificates)
            .unwrap();
        strategy
            .reconcile(&mut store, &certificates)
            .unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.get(&manual).is_some());
        let fingerprint = CertificateStore::new()
            .add(b"cert")
            .unwrap();
        assert_eq!(
            store.source(&fingerprint),
            Some(super::super::CertificateSource::Distro)
        );
        let shared = store.add(b"cert").unwrap();
        assert_eq!(
            store.source(&shared),
            Some(super::super::CertificateSource::Manual)
        );
        strategy
            .reconcile(&mut store, &[])
            .unwrap();
        assert_eq!(store.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn fedora_rhel_reports_extraction_failure_even_with_partial_output() {
        let (_directory, executable) = trust_fixture(
            r#"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'Y2VydA==' '-----END CERTIFICATE-----' > "$5"
echo 'policy unavailable' >&2
exit 7
"#,
        );
        match FedoraRhel::new().extract(&executable) {
            Err(Error::ExtractionFailed { status, stderr }) => {
                assert_eq!(status.code(), Some(7));
                assert!(stderr.contains("policy unavailable"));
            }
            result => panic!("expected extraction failure, got {result:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn fedora_rhel_rejects_missing_empty_and_malformed_output() {
        for body in [
            "exit 0",
            r#": > "$5""#,
            r#"echo 'not a certificate' > "$5""#,
        ] {
            let (_directory, executable) = trust_fixture(body);
            assert!(
                FedoraRhel::new()
                    .extract(&executable)
                    .is_err()
            );
        }
        let (_directory, executable) = trust_fixture(
            r#"printf '%s\n' '-----BEGIN CERTIFICATE-----' '!!!' '-----END CERTIFICATE-----' > "$5""#,
        );
        assert!(matches!(
            FedoraRhel::new().extract(&executable),
            Err(Error::Pem(_))
        ));
    }

    #[test]
    fn fedora_rhel_reports_a_missing_executable() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            FedoraRhel::new().extract(&directory.path().join("missing-trust")),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn presentation_remains_explicitly_unsupported() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("presentation");
        assert!(matches!(
            UnsupportedPresentation.present(&CertificateStore::new(), &destination),
            Err(Error::PresentationUnavailable)
        ));
        assert!(!destination.exists());
    }
}
