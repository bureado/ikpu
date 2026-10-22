//! Distro-specific ingestion and certificate-presentation strategies.

use core::error::Error as StdError;
use core::fmt;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

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

/// A strategy for importing certificates from a distro-maintained source.
pub trait IngestionStrategy {
    /// Return the authoritative on-disk source used by this strategy.
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
        let file = File::open(&self.bundle)?;
        let mut reader = BufReader::new(file);
        let certificates = CertificateDer::pem_reader_iter(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Error::Pem(Box::new(error)))?;
        if certificates.is_empty() {
            return Err(Error::EmptyBundle);
        }
        Ok(certificates)
    }

    fn reconcile(
        &self,
        store: &mut CertificateStore,
        certificates: &[CertificateDer<'_>],
    ) -> Result<(), StoreError> {
        store.sync_distro(certificates.iter().map(AsRef::as_ref))
    }
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
    /// Certificate presentation is not implemented for this strategy.
    PresentationUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "certificate source I/O error: {error}"),
            Self::EmptyBundle => write!(f, "certificate bundle contains no certificates"),
            Self::Pem(error) => write!(f, "cannot parse certificate bundle: {error}"),
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
            Self::EmptyBundle | Self::PresentationUnavailable => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
