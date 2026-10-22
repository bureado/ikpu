#ifndef UPKI_OPENSSL_H
#define UPKI_OPENSSL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/x509_vfy.h>
#include "upki.h"

/**
 * Sets the upki config to use for connections based upon `ctx`.
 *
 * `config` becomes owned by `SSL_CTX`.  If `config` is NULL the previous configuration is
 * freed.
 *
 * # Thread safety
 *
 * This inherits the property of the OpenSSL API, whereby a single `SSL_CTX` cannot be shared
 * between threads.
 *
 * # Safety
 *
 * This does nothing if `ctx` is NULL.  `config` is required to be a valid `upki_config` pointer,
 * or NULL.
 */
void upki_openssl_set_config(SSL_CTX *ctx, const upki_config *config);

/**
 * Checks certificate revocation using upki, matching OpenSSL's `SSL_verify_cb` interface.
 *
 * This function returns 0 if called with 0 for the `preverify_ok` parameter.
 * As a result, it never allows a verification to pass if the previous verification
 * step has failed.
 *
 * If the certificate chain obtained from `x509_ctx` is not included in the revocation data,
 * this function returns `preverify_ok`.
 *
 * # Configuration
 *
 * If ``upki_openssl_set_config()` was previously called against the `SSL_CTX` available
 * from `X509_STORE_CTX`, this configuration is used.
 *
 * Otherwise, if that function wasn't called, or no `SSL_CTX` can be obtained from `X509_STORE_CTX`,
 * the configuration file and data location is found automatically based on defaults.
 *
 * # Errors
 *
 * If the certificate chain obtained from `x509_ctx` is revoked, this function returns 0
 * and sets the `X509_V_ERR_CERT_REVOKED` error on `x509_ctx` (using
 * `X509_STORE_CTX_set_error(3SSL)`).
 *
 * If the revocation status cannot be determined, this function returns 0 and sets
 * the `X509_V_ERR_APPLICATION_VERIFICATION` error on `x509_ctx` (using
 * `X509_STORE_CTX_set_error(3SSL)`).
 *
 * On unexpected/unrecoverable errors, this function returns 0 and may add a report
 * to the OpenSSL error stack giving more detail.
 *
 * # Safety
 *
 * This function requires that `x509_ctx` is a valid pointer, or NULL.
 */
int upki_openssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

/**
 * Adds every certificate in `certs` to `store` as a trust anchor.
 *
 * This is the broadest OpenSSL integration: anything that verifies against
 * the `X509_STORE` (TLS via `SSL_CTX_get_cert_store()`, CMS/S/MIME, timestamp
 * and other `X509_verify_cert()` users) can then build chains to the upki
 * store, for whatever purpose it is verifying. It augments, rather than
 * replaces, anchors already in `store`; use a fresh `X509_STORE` to make the
 * upki store the only source of trust.
 *
 * Certificates are copied, so `certs` may be freed afterwards. Certificates
 * OpenSSL cannot parse are skipped.
 *
 * Returns the number of certificates added, or -1 if an argument is NULL or
 * OpenSSL fails to add a certificate.
 *
 * # Safety
 *
 * `store` must be a valid `X509_STORE` pointer or NULL. `certs` must be a valid
 * `upki_cert_store` pointer or NULL.
 */
int upki_openssl_load_cert_store(X509_STORE *store, const upki_cert_store *certs);

/**
 * Sets the upki certificate store to use for connections based upon `ctx`.
 *
 * This is consulted by `upki_openssl_cert_store_verify_callback()`.
 *
 * `certs` becomes owned by `SSL_CTX`.  If `certs` is NULL the previous store is
 * freed.
 *
 * # Safety
 *
 * This does nothing if `ctx` is NULL.  `certs` is required to be a valid
 * `upki_cert_store` pointer, or NULL.
 */
void upki_openssl_set_cert_store(SSL_CTX *ctx, const upki_cert_store *certs);

/**
 * Requires the verified chain to reach the upki certificate store, matching
 * OpenSSL's `SSL_verify_cb` interface.
 *
 * This *constrains* OpenSSL's own verification: OpenSSL still builds and
 * verifies the chain against its `X509_STORE` (signatures, validity, purpose
 * and hostname checks), and this callback then rejects the result unless a
 * certificate in that verified chain is in the upki store. Combine it with
 * `upki_openssl_load_cert_store()` to make the upki store both the source and
 * the constraint of trust. It never turns a failed verification into success.
 *
 * Only one verify callback can be installed; to also check revocation, call
 * this and `upki_openssl_verify_callback()` from your own callback and
 * require both to succeed.
 *
 * This function returns 0 if called with 0 for the `preverify_ok` parameter.
 *
 * # Store selection
 *
 * If `upki_openssl_set_cert_store()` was previously called against the `SSL_CTX`
 * available from `X509_STORE_CTX`, that store is used.  Otherwise the store named
 * by the `cert-store` key of the default upki configuration file is opened.
 *
 * # Errors
 *
 * If the verified chain does not reach the upki store, this function returns 0
 * and sets the `X509_V_ERR_CERT_UNTRUSTED` error on `x509_ctx`.
 *
 * If no store can be loaded, this function returns 0, sets the
 * `X509_V_ERR_APPLICATION_VERIFICATION` error on `x509_ctx`, and adds a report to
 * the OpenSSL error stack.
 *
 * # Safety
 *
 * This function requires that `x509_ctx` is a valid pointer, or NULL.
 */
int upki_openssl_cert_store_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

#endif  /* UPKI_OPENSSL_H */
