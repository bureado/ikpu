#ifndef UPKI_H
#define UPKI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Result type for upki C API functions.
 *
 * Values 0-15 indicate success (with specific status information).
 * Values 16 and above indicate errors.
 */
typedef enum upki_result {
  /**
   * Operation succeeded.
   */
  UPKI_OK = 0,
  /**
   * The certificate is not covered by the revocation data.
   */
  UPKI_REVOCATION_NOT_COVERED = 1,
  /**
   * The certificate has been revoked.
   */
  UPKI_REVOCATION_REVOKED = 2,
  /**
   * The certificate is not revoked.
   */
  UPKI_REVOCATION_NOT_REVOKED = 3,
  /**
   * The verified chain contains a certificate from the certificate store.
   */
  UPKI_CERT_STORE_ANCHORED = 4,
  /**
   * The verified chain contains no certificate from the certificate store.
   */
  UPKI_CERT_STORE_NOT_ANCHORED = 5,
  /**
   * A null pointer was passed where a valid pointer was required.
   */
  UPKI_ERR_NULL_POINTER = 16,
  /**
   * The config path is not valid UTF-8.
   */
  UPKI_ERR_CONFIG_PATH = 17,
  /**
   * An unknown error variant was added to the library.
   */
  UPKI_ERR_UNKNOWN = 18,
  /**
   * An unexpected panic occurred in the library.
   */
  UPKI_ERR_PANICKED = 19,
  /**
   * Failed to decode configuration file.
   */
  UPKI_ERR_CONFIG_DECODE = 32,
  /**
   * Failed to read configuration file.
   */
  UPKI_ERR_CONFIG_READ = 33,
  /**
   * No cache directory could be found.
   */
  UPKI_ERR_NO_CACHE_DIR = 34,
  /**
   * No configuration directory could be found.
   */
  UPKI_ERR_NO_CONFIG_DIR = 35,
  /**
   * The user's home directory could not be determined.
   */
  UPKI_ERR_NO_HOME_DIR = 36,
  /**
   * Failed to decode a file.
   */
  UPKI_ERR_REVOCATION_FILE_DECODE = 64,
  /**
   * Failed to read a file.
   */
  UPKI_ERR_REVOCATION_FILE_READ = 65,
  /**
   * Invalid base64 encoding.
   */
  UPKI_ERR_REVOCATION_INVALID_BASE64 = 66,
  /**
   * The end-entity certificate was invalid.
   */
  UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT = 67,
  /**
   * An intermediate certificate was invalid.
   */
  UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT = 68,
  /**
   * A base64-decoded value did not have the expected length.
   */
  UPKI_ERR_REVOCATION_INVALID_LENGTH = 69,
  /**
   * Invalid SCT encoding.
   */
  UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING = 70,
  /**
   * An SCT in the end-entity certificate could not be parsed.
   */
  UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT = 71,
  /**
   * A timestamp could not be parsed.
   */
  UPKI_ERR_REVOCATION_INVALID_TIMESTAMP = 72,
  /**
   * No issuer found for the end-entity certificate.
   */
  UPKI_ERR_REVOCATION_NO_ISSUER = 73,
  /**
   * Certificate chain must contain at least 2 certificates.
   */
  UPKI_ERR_REVOCATION_TOO_FEW_CERTS = 74,
  /**
   * Failed to decode the index file.
   */
  UPKI_ERR_REVOCATION_INDEX_DECODE = 75,
  /**
   * No revocation data is present in the cache.
   */
  UPKI_ERR_REVOCATION_NO_DATA = 76,
  /**
   * Failed to read the certificate store.
   */
  UPKI_ERR_CERT_STORE_READ = 96,
  /**
   * The certificate store snapshot is invalid or corrupt.
   */
  UPKI_ERR_CERT_STORE_INVALID = 97,
  /**
   * No certificate store is configured.
   */
  UPKI_ERR_CERT_STORE_NOT_CONFIGURED = 98,
  /**
   * The certificate index is out of range.
   */
  UPKI_ERR_CERT_STORE_INDEX_OUT_OF_RANGE = 99,
  /**
   * The certificate chain is empty.
   */
  UPKI_ERR_CERT_STORE_EMPTY_CHAIN = 100,
} upki_result;

/**
 * Opaque type representing a loaded upki certificate store snapshot.
 *
 * The snapshot is read once when opened; later changes to the file are not
 * observed. Open it again to pick up updates.
 */
typedef struct upki_cert_store upki_cert_store;

/**
 * Opaque type representing a `upki::Config`.
 */
typedef struct upki_config upki_config;

/**
 * A DER-encoded certificate.
 */
typedef struct upki_certificate_der {
  /**
   * Pointer to the DER-encoded certificate data.
   */
  const uint8_t *data;
  /**
   * Length of the certificate data in bytes.
   */
  uintptr_t len;
} upki_certificate_der;

/**
 * Check the revocation status of a certificate.
 *
 * The `certificates` array should contain the end-entity certificate first,
 * followed by any intermediate certificates needed to find the issuer.
 *
 * Returns a `upki_result` indicating success (with revocation status) or an error.
 *
 * # Safety
 *
 * - `config` must be a valid pointer returned by `upki_config_new`.
 * - `certificates` must point to `certificates_len` `upki_certificate` values.
 * - Each `upki_certificate` must have a valid `data` pointer to `len` bytes.
 */
enum upki_result upki_check_revocation(const struct upki_config *config,
                                       const struct upki_certificate_der *certificates,
                                       uintptr_t certificates_len);

/**
 * Create a new `upki_config` by loading it from the file at `path`.
 *
 * If `path` is `NULL`, the file is found by searching for a configuration
 * file in a series of places (depending on the platform.) This is
 * exposed by the `upki` command-line tool: run `upki show-config-path`
 * so see where the current configuration file is being found.
 *
 * On success, writes the config pointer to `out` and returns `UPKI_OK`.
 * The caller is responsible for freeing the config with `upki_config_free`.
 *
 * # Safety
 *
 * - `out` must be a pointer to writable, properly-aligned storage for a pointer.
 *   Returns `UPKI_ERR_NULL_POINTER` if `out` is `NULL`.
 * - `path` must be a valid pointer to a null-terminated UTF-8 string, or `NULL`.
 */
enum upki_result upki_config_new(const char *path, struct upki_config **out);

/**
 * Free a `upki_config` created by `upki_config_new`.
 *
 * # Safety
 *
 * `config` must be a valid pointer returned by `upki_config_new`,
 * or null (in which case this is a no-op).
 */
void upki_config_free(struct upki_config *config);

/**
 * Open the certificate store snapshot at `path`.
 *
 * On success, writes the store pointer to `out` and returns `UPKI_OK`.
 * The caller is responsible for freeing the store with `upki_cert_store_free`.
 *
 * # Safety
 *
 * - `path` must be a valid pointer to a null-terminated UTF-8 string.
 * - `out` must be a pointer to writable, properly-aligned storage for a pointer.
 */
enum upki_result upki_cert_store_open(const char *path, struct upki_cert_store **out);

/**
 * Open the certificate store snapshot named by the `cert-store` key of `config`.
 *
 * This lets integrations find the system store without being given a path.
 * Returns `UPKI_ERR_CERT_STORE_NOT_CONFIGURED` if the key is absent.
 *
 * On success, writes the store pointer to `out` and returns `UPKI_OK`.
 * The caller is responsible for freeing the store with `upki_cert_store_free`.
 *
 * # Safety
 *
 * - `config` must be a valid pointer returned by `upki_config_new`.
 * - `out` must be a pointer to writable, properly-aligned storage for a pointer.
 */
enum upki_result upki_cert_store_open_from_config(const struct upki_config *config,
                                                  struct upki_cert_store **out);

/**
 * Free a `upki_cert_store` created by `upki_cert_store_open` or
 * `upki_cert_store_open_from_config`.
 *
 * # Safety
 *
 * `store` must be a valid pointer returned by one of those functions,
 * or null (in which case this is a no-op).
 */
void upki_cert_store_free(struct upki_cert_store *store);

/**
 * Return the number of certificates in `store`, or 0 if `store` is NULL.
 *
 * # Safety
 *
 * `store` must be a valid pointer returned by `upki_cert_store_open`, or NULL.
 */
uintptr_t upki_cert_store_len(const struct upki_cert_store *store);

/**
 * Borrow the DER encoding of the certificate at `index` in `store`.
 *
 * Certificates are ordered by SHA-256 fingerprint. This is intended for
 * loading the store's certificates as trust anchors into another TLS or
 * X.509 implementation (for example GnuTLS, NSS, or mbedTLS).
 *
 * On success, fills `out` and returns `UPKI_OK`. The data pointer remains
 * valid until `store` is freed.
 *
 * # Safety
 *
 * - `store` must be a valid pointer returned by `upki_cert_store_open`.
 * - `out` must point to writable storage for a `upki_certificate_der`.
 */
enum upki_result upki_cert_store_get(const struct upki_cert_store *store,
                                     uintptr_t index,
                                     struct upki_certificate_der *out);

/**
 * Check whether a chain **already verified by the caller** reaches a certificate in `store`.
 *
 * `certificates` must be the chain built by the caller's verifier, ordered
 * from the end-entity certificate (depth 0) towards its trust anchor; for
 * example the result of OpenSSL's `X509_STORE_CTX_get0_chain()` after
 * successful verification.
 *
 * This performs no cryptographic or name checks of its own, in the same way
 * that `upki_check_revocation` relies on prior verification. It only checks
 * whether any certificate in the chain is in the store. **Do not** pass a
 * chain exactly as presented by a peer: a peer can append any certificate.
 *
 * Returns `UPKI_CERT_STORE_ANCHORED` and writes the depth of the matching
 * certificate closest to the anchor to `depth` (if `depth` is not NULL), or
 * `UPKI_CERT_STORE_NOT_ANCHORED`, or an error.
 *
 * # Safety
 *
 * - `store` must be a valid pointer returned by `upki_cert_store_open`.
 * - `certificates` must point to `certificates_len` `upki_certificate_der` values.
 * - Each `upki_certificate_der` must have a valid `data` pointer to `len` bytes.
 * - `depth` must be NULL or point to writable storage for a `size_t`.
 */
enum upki_result upki_cert_store_check_verified_chain(const struct upki_cert_store *store,
                                                      const struct upki_certificate_der *certificates,
                                                      uintptr_t certificates_len,
                                                      uintptr_t *depth);

#endif  /* UPKI_H */
