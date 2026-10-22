//! An indexed, checksummed certificate store.

use core::error::Error as StdError;
use core::fmt;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::sha256;

const MAGIC: &[u8; 8] = b"upkics01";
const CHECKSUM_SIZE: usize = 32;
const MAX_STORE_SIZE: usize = 64 * 1024 * 1024;

/// A SHA-256 fingerprint identifying a certificate by its DER encoding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Return the fingerprint bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the fingerprint as lowercase hexadecimal.
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    /// Parse a lowercase or uppercase hexadecimal fingerprint.
    pub fn from_hex(value: &str) -> Result<Self, Error> {
        if value.len() != 64 {
            return Err(Error::InvalidFingerprint);
        }

        let mut bytes = [0u8; 32];
        for (i, pair) in value
            .as_bytes()
            .chunks_exact(2)
            .enumerate()
        {
            bytes[i] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

/// A certificate store that keeps its contents in memory for lookup.
///
/// The on-disk representation is a versioned binary snapshot. Each entry is
/// indexed by the SHA-256 fingerprint of its DER bytes, and the complete file
/// has a trailing SHA-256 checksum to detect accidental corruption.
#[derive(Debug, Default)]
pub struct CertificateStore {
    certificates: BTreeMap<Fingerprint, Vec<u8>>,
}

impl CertificateStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load and validate a store snapshot from `path`.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take((MAX_STORE_SIZE + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STORE_SIZE {
            return Err(Error::StoreTooLarge);
        }
        Self::decode(&bytes)
    }

    /// Add a DER-encoded certificate to the store.
    ///
    /// Adding the same certificate more than once is harmless. The returned
    /// fingerprint can be used to retrieve or remove the certificate.
    pub fn add(&mut self, der: &[u8]) -> Result<Fingerprint, Error> {
        let fingerprint = Fingerprint(sha256::Digest::from(&[der][..]).0);
        if let Some(existing) = self.certificates.get(&fingerprint) {
            if existing != der {
                return Err(Error::FingerprintCollision);
            }
        } else {
            self.certificates
                .insert(fingerprint, der.to_vec());
        }
        Ok(fingerprint)
    }

    /// Remove the certificate identified by `fingerprint`.
    pub fn remove(&mut self, fingerprint: &Fingerprint) -> bool {
        self.certificates
            .remove(fingerprint)
            .is_some()
    }

    /// Return the DER bytes of the certificate identified by `fingerprint`.
    pub fn get(&self, fingerprint: &Fingerprint) -> Option<&[u8]> {
        self.certificates
            .get(fingerprint)
            .map(Vec::as_slice)
    }

    /// Iterate over certificates in fingerprint order.
    pub fn iter(&self) -> impl Iterator<Item = (Fingerprint, &[u8])> {
        self.certificates
            .iter()
            .map(|(fingerprint, der)| (*fingerprint, der.as_slice()))
    }

    /// Return the number of certificates in the store.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Return whether the store contains no certificates.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Atomically write the store snapshot to `path`.
    ///
    /// The parent directory must already exist. On Unix, the resulting file is
    /// readable by all users and writable only by its owner.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let parent = path
            .parent()
            .ok_or(Error::InvalidStorePath)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let bytes = self.encode()?;

        #[cfg(target_family = "unix")]
        let mut temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o644))
            .tempfile_in(parent)?;
        #[cfg(not(target_family = "unix"))]
        let mut temp = tempfile::Builder::new().tempfile_in(parent)?;

        use std::io::Write;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(path)
            .map_err(|error| Error::Io(error.error))?;
        #[cfg(target_family = "unix")]
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        let count = u32::try_from(self.certificates.len()).map_err(|_| Error::StoreTooLarge)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&count.to_be_bytes());

        for (fingerprint, der) in &self.certificates {
            let len = u32::try_from(der.len()).map_err(|_| Error::StoreTooLarge)?;
            bytes.extend_from_slice(&fingerprint.0);
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(der);
            if bytes.len() > MAX_STORE_SIZE - CHECKSUM_SIZE {
                return Err(Error::StoreTooLarge);
            }
        }

        let checksum = sha256::Digest::from(&[bytes.as_slice()][..]);
        bytes.extend_from_slice(&checksum.0);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < MAGIC.len() + 4 + CHECKSUM_SIZE {
            return Err(Error::InvalidStore);
        }
        let payload_len = bytes.len() - CHECKSUM_SIZE;
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(Error::InvalidStore);
        }
        let checksum = sha256::Digest::from(&[&bytes[..payload_len]][..]);
        if checksum.as_ref() != &bytes[payload_len..] {
            return Err(Error::ChecksumMismatch);
        }

        let count = u32::from_be_bytes(
            bytes[MAGIC.len()..MAGIC.len() + 4]
                .try_into()
                .map_err(|_| Error::InvalidStore)?,
        ) as usize;
        let mut cursor = MAGIC.len() + 4;
        let mut certificates = BTreeMap::new();

        for _ in 0..count {
            let fingerprint_bytes = take(bytes, &mut cursor, 32, payload_len)?;
            let fingerprint = Fingerprint(
                fingerprint_bytes
                    .try_into()
                    .map_err(|_| Error::InvalidStore)?,
            );
            let len_bytes = take(bytes, &mut cursor, 4, payload_len)?;
            let len = u32::from_be_bytes(
                len_bytes
                    .try_into()
                    .map_err(|_| Error::InvalidStore)?,
            ) as usize;
            let der = take(bytes, &mut cursor, len, payload_len)?.to_vec();

            if sha256::Digest::from(&[der.as_slice()][..]).as_ref() != fingerprint.as_bytes() {
                return Err(Error::FingerprintMismatch);
            }
            if certificates
                .insert(fingerprint, der)
                .is_some()
            {
                return Err(Error::DuplicateFingerprint);
            }
        }

        if cursor != payload_len {
            return Err(Error::InvalidStore);
        }
        Ok(Self { certificates })
    }
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    count: usize,
    limit: usize,
) -> Result<&'a [u8], Error> {
    let end = cursor
        .checked_add(count)
        .ok_or(Error::InvalidStore)?;
    if end > limit {
        return Err(Error::InvalidStore);
    }
    let result = bytes
        .get(*cursor..end)
        .ok_or(Error::InvalidStore)?;
    *cursor = end;
    Ok(result)
}

fn hex_value(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidFingerprint),
    }
}

/// Errors returned by certificate-store operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An I/O operation failed.
    Io(io::Error),
    /// The snapshot has an invalid encoding or unsupported version.
    InvalidStore,
    /// The snapshot checksum does not match its contents.
    ChecksumMismatch,
    /// A stored certificate does not match its fingerprint.
    FingerprintMismatch,
    /// A snapshot contains a duplicate fingerprint.
    DuplicateFingerprint,
    /// A SHA-256 collision was found while adding a certificate.
    FingerprintCollision,
    /// The snapshot exceeds the supported size limit.
    StoreTooLarge,
    /// The fingerprint is not 64 hexadecimal characters.
    InvalidFingerprint,
    /// The destination path has no parent directory.
    InvalidStorePath,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "certificate store I/O error: {error}"),
            Self::InvalidStore => write!(f, "invalid certificate store snapshot"),
            Self::ChecksumMismatch => write!(f, "certificate store checksum mismatch"),
            Self::FingerprintMismatch => {
                write!(f, "certificate does not match its stored fingerprint")
            }
            Self::DuplicateFingerprint => write!(f, "duplicate certificate fingerprint"),
            Self::FingerprintCollision => write!(f, "SHA-256 fingerprint collision"),
            Self::StoreTooLarge => write!(f, "certificate store exceeds the size limit"),
            Self::InvalidFingerprint => write!(f, "invalid SHA-256 fingerprint"),
            Self::InvalidStorePath => write!(f, "certificate store path must have a parent"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
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
    fn round_trip_and_lookup() {
        let mut store = CertificateStore::new();
        let fingerprint = store.add(b"certificate").unwrap();
        assert_eq!(store.add(b"certificate").unwrap(), fingerprint);

        let bytes = store.encode().unwrap();
        let loaded = CertificateStore::decode(&bytes).unwrap();
        assert_eq!(loaded.get(&fingerprint), Some(b"certificate".as_slice()));
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn detects_corruption() {
        let mut store = CertificateStore::new();
        store.add(b"certificate").unwrap();
        let mut bytes = store.encode().unwrap();
        bytes[12] ^= 1;

        assert!(matches!(
            CertificateStore::decode(&bytes),
            Err(Error::ChecksumMismatch)
        ));
    }

    #[test]
    fn removes_certificates() {
        let mut store = CertificateStore::new();
        let fingerprint = store.add(b"certificate").unwrap();

        assert!(store.remove(&fingerprint));
        assert!(!store.remove(&fingerprint));
        assert!(store.is_empty());
    }

    #[test]
    fn parses_fingerprints() {
        let fingerprint = Fingerprint([0xab; 32]);
        assert_eq!(fingerprint.to_hex(), "ab".repeat(32));
        assert_eq!(
            Fingerprint::from_hex(&fingerprint.to_hex()).unwrap(),
            fingerprint
        );
        assert!(Fingerprint::from_hex("xyz").is_err());
    }

    #[test]
    fn writes_and_reopens_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("certificates.store");
        let mut store = CertificateStore::new();
        let fingerprint = store.add(b"certificate").unwrap();

        store.save(&path).unwrap();

        let loaded = CertificateStore::open(&path).unwrap();
        assert_eq!(loaded.get(&fingerprint), Some(b"certificate".as_slice()));

        let mut replacement = CertificateStore::new();
        let replacement_fingerprint = replacement.add(b"replacement").unwrap();
        replacement.save(&path).unwrap();
        let loaded = CertificateStore::open(&path).unwrap();
        assert_eq!(
            loaded.get(&replacement_fingerprint),
            Some(b"replacement".as_slice())
        );
        assert!(loaded.get(&fingerprint).is_none());
    }
}
