#![allow(non_camel_case_types)]

use core::ffi::c_char;
use std::ffi::CStr;
use std::panic::catch_unwind;
use std::path::Path;
use std::slice;

use rustls_pki_types::CertificateDer;

use crate::cert_store::{self, CertificateStore, Fingerprint};
use crate::revocation::{self, RevocationCheckInput, RevocationStatus, Store};
use crate::{Config, ConfigPath, Error};

/// Check the revocation status of a certificate.
///
/// The `certificates` array should contain the end-entity certificate first,
/// followed by any intermediate certificates needed to find the issuer.
///
/// Returns a `upki_result` indicating success (with revocation status) or an error.
///
/// # Safety
///
/// - `config` must be a valid pointer returned by `upki_config_new`.
/// - `certificates` must point to `certificates_len` `upki_certificate` values.
/// - Each `upki_certificate` must have a valid `data` pointer to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_check_revocation(
    config: *const upki_config,
    certificates: *const upki_certificate_der,
    certificates_len: usize,
) -> upki_result {
    catch_unwind(|| {
        if config.is_null() || certificates.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let config = unsafe { &(*config).0 };
        let certificates = unsafe { slice::from_raw_parts(certificates, certificates_len) };

        let certs = certificates
            .iter()
            .map(|c| CertificateDer::from(unsafe { slice::from_raw_parts(c.data, c.len) }))
            .collect::<Vec<_>>();

        let input = match RevocationCheckInput::from_certificates(&certs) {
            Ok(input) => input,
            Err(err) => return Error::Revocation(err).into(),
        };

        let store = Store::from_config(config);
        match store.check(&input) {
            Ok(status) => match status {
                RevocationStatus::NotCoveredByRevocationData => {
                    upki_result::UPKI_REVOCATION_NOT_COVERED
                }
                RevocationStatus::CertainlyRevoked => upki_result::UPKI_REVOCATION_REVOKED,
                RevocationStatus::NotRevoked => upki_result::UPKI_REVOCATION_NOT_REVOKED,
            },
            Err(err) => Error::Revocation(err).into(),
        }
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

/// Opaque type representing a `upki::Config`.
pub struct upki_config(Config);

/// Create a new `upki_config` by loading it from the file at `path`.
///
/// If `path` is `NULL`, the file is found by searching for a configuration
/// file in a series of places (depending on the platform.) This is
/// exposed by the `upki` command-line tool: run `upki show-config-path`
/// so see where the current configuration file is being found.
///
/// On success, writes the config pointer to `out` and returns `UPKI_OK`.
/// The caller is responsible for freeing the config with `upki_config_free`.
///
/// # Safety
///
/// - `out` must be a pointer to writable, properly-aligned storage for a pointer.
///   Returns `UPKI_ERR_NULL_POINTER` if `out` is `NULL`.
/// - `path` must be a valid pointer to a null-terminated UTF-8 string, or `NULL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_config_new(
    path: *const c_char,
    out: *mut *mut upki_config,
) -> upki_result {
    catch_unwind(|| {
        if out.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let path = match path.is_null() {
            true => match ConfigPath::new(None) {
                Ok(path) => path,
                Err(e) => return e.into(),
            },
            false => {
                let path = unsafe { CStr::from_ptr(path) };
                let Ok(path) = path.to_str() else {
                    return upki_result::UPKI_ERR_CONFIG_PATH;
                };
                ConfigPath::Specified(Path::new(path).to_owned())
            }
        };

        match Config::from_file_or_user_default(&path) {
            Ok(config) => {
                unsafe { *out = Box::into_raw(Box::new(upki_config(config))) };
                upki_result::UPKI_OK
            }
            Err(err) => err.into(),
        }
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

/// Free a `upki_config` created by `upki_config_new`.
///
/// # Safety
///
/// `config` must be a valid pointer returned by `upki_config_new`,
/// or null (in which case this is a no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_config_free(config: *mut upki_config) {
    if !config.is_null() {
        drop(unsafe { Box::from_raw(config) });
    }
}

/// Opaque type representing a loaded upki certificate store snapshot.
///
/// The snapshot is read once when opened; later changes to the file are not
/// observed. Open it again to pick up updates.
pub struct upki_cert_store {
    store: CertificateStore,
    order: Vec<Fingerprint>,
}

impl upki_cert_store {
    fn new(store: CertificateStore) -> Self {
        let order = store
            .iter()
            .map(|(fingerprint, _)| fingerprint)
            .collect();
        Self { store, order }
    }
}

/// Open the certificate store snapshot at `path`.
///
/// On success, writes the store pointer to `out` and returns `UPKI_OK`.
/// The caller is responsible for freeing the store with `upki_cert_store_free`.
///
/// # Safety
///
/// - `path` must be a valid pointer to a null-terminated UTF-8 string.
/// - `out` must be a pointer to writable, properly-aligned storage for a pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_cert_store_open(
    path: *const c_char,
    out: *mut *mut upki_cert_store,
) -> upki_result {
    catch_unwind(|| {
        if path.is_null() || out.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let path = unsafe { CStr::from_ptr(path) };
        let Ok(path) = path.to_str() else {
            return upki_result::UPKI_ERR_CONFIG_PATH;
        };
        unsafe { open_cert_store(Path::new(path), out) }
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

/// Open the certificate store snapshot named by the `cert-store` key of `config`.
///
/// This lets integrations find the system store without being given a path.
/// Returns `UPKI_ERR_CERT_STORE_NOT_CONFIGURED` if the key is absent.
///
/// On success, writes the store pointer to `out` and returns `UPKI_OK`.
/// The caller is responsible for freeing the store with `upki_cert_store_free`.
///
/// # Safety
///
/// - `config` must be a valid pointer returned by `upki_config_new`.
/// - `out` must be a pointer to writable, properly-aligned storage for a pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_cert_store_open_from_config(
    config: *const upki_config,
    out: *mut *mut upki_cert_store,
) -> upki_result {
    catch_unwind(|| {
        if config.is_null() || out.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let config = unsafe { &(*config).0 };
        match config.cert_store_path() {
            Some(path) => unsafe { open_cert_store(path, out) },
            None => upki_result::UPKI_ERR_CERT_STORE_NOT_CONFIGURED,
        }
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

unsafe fn open_cert_store(path: &Path, out: *mut *mut upki_cert_store) -> upki_result {
    match CertificateStore::open(path) {
        Ok(store) => {
            unsafe { *out = Box::into_raw(Box::new(upki_cert_store::new(store))) };
            upki_result::UPKI_OK
        }
        Err(err) => err.into(),
    }
}

/// Free a `upki_cert_store` created by `upki_cert_store_open` or
/// `upki_cert_store_open_from_config`.
///
/// # Safety
///
/// `store` must be a valid pointer returned by one of those functions,
/// or null (in which case this is a no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_cert_store_free(store: *mut upki_cert_store) {
    if !store.is_null() {
        drop(unsafe { Box::from_raw(store) });
    }
}

/// Return the number of certificates in `store`, or 0 if `store` is NULL.
///
/// # Safety
///
/// `store` must be a valid pointer returned by `upki_cert_store_open`, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_cert_store_len(store: *const upki_cert_store) -> usize {
    match unsafe { store.as_ref() } {
        Some(store) => store.order.len(),
        None => 0,
    }
}

/// Borrow the DER encoding of the certificate at `index` in `store`.
///
/// Certificates are ordered by SHA-256 fingerprint. This is intended for
/// loading the store's certificates as trust anchors into another TLS or
/// X.509 implementation (for example GnuTLS, NSS, or mbedTLS).
///
/// On success, fills `out` and returns `UPKI_OK`. The data pointer remains
/// valid until `store` is freed.
///
/// # Safety
///
/// - `store` must be a valid pointer returned by `upki_cert_store_open`.
/// - `out` must point to writable storage for a `upki_certificate_der`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_cert_store_get(
    store: *const upki_cert_store,
    index: usize,
    out: *mut upki_certificate_der,
) -> upki_result {
    catch_unwind(|| {
        if store.is_null() || out.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let store = unsafe { &*store };
        let Some(der) = store
            .order
            .get(index)
            .and_then(|fingerprint| store.store.get(fingerprint))
        else {
            return upki_result::UPKI_ERR_CERT_STORE_INDEX_OUT_OF_RANGE;
        };

        unsafe {
            *out = upki_certificate_der {
                data: der.as_ptr(),
                len: der.len(),
            }
        };
        upki_result::UPKI_OK
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

/// Check whether a chain **already verified by the caller** reaches a certificate in `store`.
///
/// `certificates` must be the chain built by the caller's verifier, ordered
/// from the end-entity certificate (depth 0) towards its trust anchor; for
/// example the result of OpenSSL's `X509_STORE_CTX_get0_chain()` after
/// successful verification.
///
/// This performs no cryptographic or name checks of its own, in the same way
/// that `upki_check_revocation` relies on prior verification. It only checks
/// whether any certificate in the chain is in the store. **Do not** pass a
/// chain exactly as presented by a peer: a peer can append any certificate.
///
/// Returns `UPKI_CERT_STORE_ANCHORED` and writes the depth of the matching
/// certificate closest to the anchor to `depth` (if `depth` is not NULL), or
/// `UPKI_CERT_STORE_NOT_ANCHORED`, or an error.
///
/// # Safety
///
/// - `store` must be a valid pointer returned by `upki_cert_store_open`.
/// - `certificates` must point to `certificates_len` `upki_certificate_der` values.
/// - Each `upki_certificate_der` must have a valid `data` pointer to `len` bytes.
/// - `depth` must be NULL or point to writable storage for a `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_cert_store_check_verified_chain(
    store: *const upki_cert_store,
    certificates: *const upki_certificate_der,
    certificates_len: usize,
    depth: *mut usize,
) -> upki_result {
    catch_unwind(|| {
        if store.is_null() || certificates.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }
        if certificates_len == 0 {
            return upki_result::UPKI_ERR_CERT_STORE_EMPTY_CHAIN;
        }

        let store = unsafe { &(*store).store };
        let certificates = unsafe { slice::from_raw_parts(certificates, certificates_len) };
        if certificates
            .iter()
            .any(|c| c.data.is_null())
        {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let chain = certificates
            .iter()
            .map(|c| unsafe { slice::from_raw_parts(c.data, c.len) });
        match store.find_anchor(chain) {
            Some(found) => {
                if !depth.is_null() {
                    unsafe { *depth = found.depth };
                }
                upki_result::UPKI_CERT_STORE_ANCHORED
            }
            None => upki_result::UPKI_CERT_STORE_NOT_ANCHORED,
        }
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

/// A DER-encoded certificate.
#[repr(C)]
pub struct upki_certificate_der {
    /// Pointer to the DER-encoded certificate data.
    pub data: *const u8,
    /// Length of the certificate data in bytes.
    pub len: usize,
}

/// Result type for upki C API functions.
///
/// Values 0-15 indicate success (with specific status information).
/// Values 16 and above indicate errors.
#[derive(Clone, Copy)]
#[repr(C)]
pub enum upki_result {
    /// Operation succeeded.
    UPKI_OK = 0,
    /// The certificate is not covered by the revocation data.
    UPKI_REVOCATION_NOT_COVERED = 1,
    /// The certificate has been revoked.
    UPKI_REVOCATION_REVOKED = 2,
    /// The certificate is not revoked.
    UPKI_REVOCATION_NOT_REVOKED = 3,
    /// The verified chain contains a certificate from the certificate store.
    UPKI_CERT_STORE_ANCHORED = 4,
    /// The verified chain contains no certificate from the certificate store.
    UPKI_CERT_STORE_NOT_ANCHORED = 5,

    /// A null pointer was passed where a valid pointer was required.
    UPKI_ERR_NULL_POINTER = 16,
    /// The config path is not valid UTF-8.
    UPKI_ERR_CONFIG_PATH = 17,
    /// An unknown error variant was added to the library.
    UPKI_ERR_UNKNOWN = 18,
    /// An unexpected panic occurred in the library.
    UPKI_ERR_PANICKED = 19,

    // Errors from upki::Error
    /// Failed to decode configuration file.
    UPKI_ERR_CONFIG_DECODE = 32,
    /// Failed to read configuration file.
    UPKI_ERR_CONFIG_READ = 33,
    /// No cache directory could be found.
    UPKI_ERR_NO_CACHE_DIR = 34,
    /// No configuration directory could be found.
    UPKI_ERR_NO_CONFIG_DIR = 35,
    /// The user's home directory could not be determined.
    UPKI_ERR_NO_HOME_DIR = 36,

    // Errors from upki::revocation::Error
    /// Failed to decode a file.
    UPKI_ERR_REVOCATION_FILE_DECODE = 64,
    /// Failed to read a file.
    UPKI_ERR_REVOCATION_FILE_READ = 65,
    /// Invalid base64 encoding.
    UPKI_ERR_REVOCATION_INVALID_BASE64 = 66,
    /// The end-entity certificate was invalid.
    UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT = 67,
    /// An intermediate certificate was invalid.
    UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT = 68,
    /// A base64-decoded value did not have the expected length.
    UPKI_ERR_REVOCATION_INVALID_LENGTH = 69,
    /// Invalid SCT encoding.
    UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING = 70,
    /// An SCT in the end-entity certificate could not be parsed.
    UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT = 71,
    /// A timestamp could not be parsed.
    UPKI_ERR_REVOCATION_INVALID_TIMESTAMP = 72,
    /// No issuer found for the end-entity certificate.
    UPKI_ERR_REVOCATION_NO_ISSUER = 73,
    /// Certificate chain must contain at least 2 certificates.
    UPKI_ERR_REVOCATION_TOO_FEW_CERTS = 74,
    /// Failed to decode the index file.
    UPKI_ERR_REVOCATION_INDEX_DECODE = 75,
    /// No revocation data is present in the cache.
    UPKI_ERR_REVOCATION_NO_DATA = 76,

    // Errors from upki::cert_store
    /// Failed to read the certificate store.
    UPKI_ERR_CERT_STORE_READ = 96,
    /// The certificate store snapshot is invalid or corrupt.
    UPKI_ERR_CERT_STORE_INVALID = 97,
    /// No certificate store is configured.
    UPKI_ERR_CERT_STORE_NOT_CONFIGURED = 98,
    /// The certificate index is out of range.
    UPKI_ERR_CERT_STORE_INDEX_OUT_OF_RANGE = 99,
    /// The certificate chain is empty.
    UPKI_ERR_CERT_STORE_EMPTY_CHAIN = 100,
}

impl upki_result {
    /// Convert an error into a static C string
    pub const fn c_str(&self) -> &'static CStr {
        match self {
            Self::UPKI_OK => c"operation succeeded",
            Self::UPKI_REVOCATION_NOT_COVERED => {
                c"the certificate is not covered by the revocation data"
            }
            Self::UPKI_REVOCATION_REVOKED => c"the certificate has been revoked",
            Self::UPKI_REVOCATION_NOT_REVOKED => c"the certificate is not revoked",
            Self::UPKI_CERT_STORE_ANCHORED => {
                c"the verified chain contains a certificate from the certificate store"
            }
            Self::UPKI_CERT_STORE_NOT_ANCHORED => {
                c"the verified chain contains no certificate from the certificate store"
            }
            Self::UPKI_ERR_NULL_POINTER => {
                c"a null pointer was passed where a valid pointer was required"
            }
            Self::UPKI_ERR_CONFIG_PATH => c"the config path is not valid utf-8",
            Self::UPKI_ERR_UNKNOWN => c"an unknown error variant was added to the library",
            Self::UPKI_ERR_PANICKED => c"an unexpected panic occurred in the library",
            Self::UPKI_ERR_CONFIG_DECODE => c"failed to decode configuration file",
            Self::UPKI_ERR_CONFIG_READ => c"failed to read configuration file",
            Self::UPKI_ERR_NO_CACHE_DIR => c"no cache directory could be found",
            Self::UPKI_ERR_NO_CONFIG_DIR => c"no configuration directory could be found",
            Self::UPKI_ERR_NO_HOME_DIR => c"the user's home directory could not be determined",
            Self::UPKI_ERR_REVOCATION_FILE_DECODE => c"failed to decode a file",
            Self::UPKI_ERR_REVOCATION_FILE_READ => c"failed to read a file",
            Self::UPKI_ERR_REVOCATION_INVALID_BASE64 => c"invalid base64 encoding",
            Self::UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT => {
                c"the end-entity certificate was invalid"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT => {
                c"an intermediate certificate was invalid"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_LENGTH => {
                c"a base64-decoded value did not have the expected length"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING => c"invalid sct encoding",
            Self::UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT => {
                c"an sct in the end-entity certificate could not be parsed"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_TIMESTAMP => c"a timestamp could not be parsed",
            Self::UPKI_ERR_REVOCATION_NO_ISSUER => {
                c"no issuer found for the end-entity certificate"
            }
            Self::UPKI_ERR_REVOCATION_TOO_FEW_CERTS => {
                c"certificate chain must contain at least 2 certificates"
            }
            Self::UPKI_ERR_REVOCATION_INDEX_DECODE => c"failed to decode the index file",
            Self::UPKI_ERR_REVOCATION_NO_DATA => c"no revocation data is present in the cache",
            Self::UPKI_ERR_CERT_STORE_READ => c"failed to read the certificate store",
            Self::UPKI_ERR_CERT_STORE_INVALID => {
                c"the certificate store snapshot is invalid or corrupt"
            }
            Self::UPKI_ERR_CERT_STORE_NOT_CONFIGURED => c"no certificate store is configured",
            Self::UPKI_ERR_CERT_STORE_INDEX_OUT_OF_RANGE => {
                c"the certificate index is out of range"
            }
            Self::UPKI_ERR_CERT_STORE_EMPTY_CHAIN => c"the certificate chain is empty",
        }
    }

    /// All known error values.
    pub const ALL: &[Self] = &[
        Self::UPKI_OK,
        Self::UPKI_REVOCATION_NOT_COVERED,
        Self::UPKI_REVOCATION_REVOKED,
        Self::UPKI_REVOCATION_NOT_REVOKED,
        Self::UPKI_CERT_STORE_ANCHORED,
        Self::UPKI_CERT_STORE_NOT_ANCHORED,
        Self::UPKI_ERR_NULL_POINTER,
        Self::UPKI_ERR_CONFIG_PATH,
        Self::UPKI_ERR_UNKNOWN,
        Self::UPKI_ERR_PANICKED,
        Self::UPKI_ERR_CONFIG_DECODE,
        Self::UPKI_ERR_CONFIG_READ,
        Self::UPKI_ERR_NO_CACHE_DIR,
        Self::UPKI_ERR_NO_CONFIG_DIR,
        Self::UPKI_ERR_NO_HOME_DIR,
        Self::UPKI_ERR_REVOCATION_FILE_DECODE,
        Self::UPKI_ERR_REVOCATION_FILE_READ,
        Self::UPKI_ERR_REVOCATION_INVALID_BASE64,
        Self::UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT,
        Self::UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT,
        Self::UPKI_ERR_REVOCATION_INVALID_LENGTH,
        Self::UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING,
        Self::UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT,
        Self::UPKI_ERR_REVOCATION_INVALID_TIMESTAMP,
        Self::UPKI_ERR_REVOCATION_NO_ISSUER,
        Self::UPKI_ERR_REVOCATION_TOO_FEW_CERTS,
        Self::UPKI_ERR_REVOCATION_INDEX_DECODE,
        Self::UPKI_ERR_REVOCATION_NO_DATA,
        Self::UPKI_ERR_CERT_STORE_READ,
        Self::UPKI_ERR_CERT_STORE_INVALID,
        Self::UPKI_ERR_CERT_STORE_NOT_CONFIGURED,
        Self::UPKI_ERR_CERT_STORE_INDEX_OUT_OF_RANGE,
        Self::UPKI_ERR_CERT_STORE_EMPTY_CHAIN,
    ];
}

impl From<Error> for upki_result {
    fn from(err: Error) -> Self {
        match err {
            Error::ConfigError { .. } => Self::UPKI_ERR_CONFIG_DECODE,
            Error::FileRead { .. } => Self::UPKI_ERR_CONFIG_READ,
            Error::NoCacheDirectoryFound => Self::UPKI_ERR_NO_CACHE_DIR,
            Error::NoConfigDirectoryFound => Self::UPKI_ERR_NO_CONFIG_DIR,
            Error::NoValidHomeDirectory => Self::UPKI_ERR_NO_HOME_DIR,
            Error::Revocation(revocation::Error::FileDecode { .. }) => {
                Self::UPKI_ERR_REVOCATION_FILE_DECODE
            }
            Error::Revocation(revocation::Error::FileRead { .. }) => {
                Self::UPKI_ERR_REVOCATION_FILE_READ
            }
            Error::Revocation(revocation::Error::InvalidBase64 { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_BASE64
            }
            Error::Revocation(revocation::Error::InvalidEndEntityCertificate(_)) => {
                Self::UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT
            }
            Error::Revocation(revocation::Error::InvalidIntermediateCertificate { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT
            }
            Error::Revocation(revocation::Error::InvalidLength { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_LENGTH
            }
            Error::Revocation(revocation::Error::InvalidSctEncoding) => {
                Self::UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING
            }
            Error::Revocation(revocation::Error::InvalidSctInCertificate(_)) => {
                Self::UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT
            }
            Error::Revocation(revocation::Error::InvalidTimestamp { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_TIMESTAMP
            }
            Error::Revocation(revocation::Error::NoIssuer) => Self::UPKI_ERR_REVOCATION_NO_ISSUER,
            Error::Revocation(revocation::Error::TooFewCertificates) => {
                Self::UPKI_ERR_REVOCATION_TOO_FEW_CERTS
            }
            Error::Revocation(revocation::Error::IndexDecode(_)) => {
                Self::UPKI_ERR_REVOCATION_INDEX_DECODE
            }
            Error::Revocation(revocation::Error::NoData { .. }) => {
                Self::UPKI_ERR_REVOCATION_NO_DATA
            }
        }
    }
}

impl From<cert_store::Error> for upki_result {
    fn from(err: cert_store::Error) -> Self {
        use cert_store::Error::*;
        match err {
            Io(_) => Self::UPKI_ERR_CERT_STORE_READ,
            InvalidStore | ChecksumMismatch | FingerprintMismatch | DuplicateFingerprint
            | StoreTooLarge => Self::UPKI_ERR_CERT_STORE_INVALID,
            FingerprintCollision | InvalidFingerprint | InvalidStorePath => Self::UPKI_ERR_UNKNOWN,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;
    use std::ffi::CString;

    use super::*;

    const ROOT: &[u8] = include_bytes!("../tests/data/cert-store-chain/root.der");
    const INTERMEDIATE: &[u8] = include_bytes!("../tests/data/cert-store-chain/inter.der");
    const LEAF: &[u8] = include_bytes!("../tests/data/cert-store-chain/leaf.der");

    fn der(bytes: &[u8]) -> upki_certificate_der {
        upki_certificate_der {
            data: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    #[test]
    fn cert_store_open_enumerate_and_check() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("certificates.store");
        let mut store = CertificateStore::new();
        store.add(ROOT).unwrap();
        store.save(&path).unwrap();
        let path = CString::new(path.to_str().unwrap()).unwrap();

        unsafe {
            let mut store = ptr::null_mut();
            assert!(matches!(
                upki_cert_store_open(path.as_ptr(), &mut store),
                upki_result::UPKI_OK
            ));
            assert_eq!(upki_cert_store_len(store), 1);

            let mut cert = der(&[]);
            assert!(matches!(
                upki_cert_store_get(store, 0, &mut cert),
                upki_result::UPKI_OK
            ));
            assert_eq!(slice::from_raw_parts(cert.data, cert.len), ROOT);
            assert!(matches!(
                upki_cert_store_get(store, 1, &mut cert),
                upki_result::UPKI_ERR_CERT_STORE_INDEX_OUT_OF_RANGE
            ));

            let chain = [der(LEAF), der(INTERMEDIATE), der(ROOT)];
            let mut depth = usize::MAX;
            assert!(matches!(
                upki_cert_store_check_verified_chain(
                    store,
                    chain.as_ptr(),
                    chain.len(),
                    &mut depth
                ),
                upki_result::UPKI_CERT_STORE_ANCHORED
            ));
            assert_eq!(depth, 2);
            assert!(matches!(
                upki_cert_store_check_verified_chain(store, chain.as_ptr(), 2, ptr::null_mut()),
                upki_result::UPKI_CERT_STORE_NOT_ANCHORED
            ));
            assert!(matches!(
                upki_cert_store_check_verified_chain(store, chain.as_ptr(), 0, ptr::null_mut()),
                upki_result::UPKI_ERR_CERT_STORE_EMPTY_CHAIN
            ));

            upki_cert_store_free(store);
        }
    }

    #[test]
    fn cert_store_open_errors() {
        let missing = CString::new("/nonexistent/upki/certificates.store").unwrap();
        let mut store = ptr::null_mut();
        unsafe {
            assert!(matches!(
                upki_cert_store_open(missing.as_ptr(), &mut store),
                upki_result::UPKI_ERR_CERT_STORE_READ
            ));
            assert!(matches!(
                upki_cert_store_open(ptr::null(), &mut store),
                upki_result::UPKI_ERR_NULL_POINTER
            ));
            assert_eq!(upki_cert_store_len(ptr::null()), 0);
        }
        assert!(store.is_null());

        let config = upki_config(Config::try_default().unwrap());
        unsafe {
            assert!(matches!(
                upki_cert_store_open_from_config(&config, &mut store),
                upki_result::UPKI_ERR_CERT_STORE_NOT_CONFIGURED
            ));
        }
    }
}
