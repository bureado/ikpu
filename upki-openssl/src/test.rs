#![allow(clippy::undocumented_unsafe_blocks)]

use core::{mem, ptr};
use std::os::raw::c_int;

use openssl_sys::{
    OPENSSL_STACK, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, SSL_CTX_free,
    SSL_CTX_new, TLS_client_method, X509_STORE_CTX, X509_STORE_CTX_free, X509_STORE_CTX_get_error,
    X509_STORE_CTX_new, X509_STORE_CTX_set_error, X509_V_ERR_APPLICATION_VERIFICATION,
    stack_st_X509,
};
use std::ffi::CString;

use openssl_sys::{
    SSL_free, SSL_get_ex_data_X509_STORE_CTX_idx, SSL_new, X509, X509_STORE_CTX_init,
    X509_STORE_free, X509_STORE_new, X509_V_ERR_CERT_UNTRUSTED, X509_V_OK, X509_free,
    X509_verify_cert, d2i_X509,
};
use upki::cert_store::CertificateStore;
use upki::ffi::{upki_cert_store, upki_cert_store_open, upki_config_new};

use super::upki_openssl_verify_callback;
use crate::{
    upki_openssl_cert_store_verify_callback, upki_openssl_load_cert_store,
    upki_openssl_set_cert_store, upki_openssl_set_config,
};

#[test]
fn preverify_zero_returns_zero() {
    assert_eq!(
        unsafe { upki_openssl_verify_callback(0, ptr::null_mut()) },
        0
    );
}

#[test]
fn null_ctx_returns_zero() {
    assert_eq!(
        unsafe { upki_openssl_verify_callback(1, ptr::null_mut()) },
        0
    );
}

#[test]
fn preverify_ok_zero_valid_ctx_returns_zero() {
    let ctx = StoreCtx::new();
    assert_eq!(unsafe { upki_openssl_verify_callback(0, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn preverify_ok_zero_nonzero_depth_returns_zero() {
    let mut ctx = StoreCtx::new();
    ctx.set_error_depth(3);

    assert_eq!(unsafe { upki_openssl_verify_callback(0, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn error_depth_various_nonzero_all_pass_through() {
    for depth in [-1, 1, 3, 5, 10, 100] {
        let mut ctx = StoreCtx::new();
        ctx.set_error_depth(depth);

        assert_eq!(
            unsafe { upki_openssl_verify_callback(1, ctx.0) },
            1,
            "expected preverify_ok pass-through at error_depth={depth}"
        );
        assert!(ctx.untouched_error());
    }
}

#[test]
fn error_depth_nonzero_preserves_arbitrary_preverify_ok_value() {
    for (depth, pv) in [(1, 2), (2, 42), (5, -1), (10, 100)] {
        let mut ctx = StoreCtx::new();
        ctx.set_error_depth(depth);

        assert_eq!(
            unsafe { upki_openssl_verify_callback(pv, ctx.0) },
            pv,
            "preverify_ok={pv} should be returned unchanged at error_depth={depth}"
        );
        assert!(ctx.untouched_error());
    }
}

#[test]
fn missing_chain_returns_zero() {
    let ctx = StoreCtx::new();
    assert_eq!(unsafe { upki_openssl_verify_callback(1, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn empty_chain_reports_error() {
    let mut ctx = StoreCtx::new();
    ctx.set_verified_chain(Chain::new());
    assert_eq!(unsafe { upki_openssl_verify_callback(1, ctx.0) }, 0);
    assert_eq!(ctx.error(), X509_V_ERR_APPLICATION_VERIFICATION);
}

#[test]
fn malformed_chain_returns_zero() {
    let mut chain = Chain::new();
    chain.push_null();
    let mut ctx = StoreCtx::new();
    ctx.set_verified_chain(chain);
    assert_eq!(unsafe { upki_openssl_verify_callback(1, ctx.0) }, 0);
    assert!(ctx.untouched_error());
}

#[test]
fn set_config_twice() {
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        let mut config = ptr::null_mut();

        upki_config_new(ptr::null(), &mut config);
        upki_openssl_set_config(ctx, config);

        upki_config_new(ptr::null(), &mut config);
        upki_openssl_set_config(ctx, config);

        SSL_CTX_free(ctx);
    }
}

#[test]
fn set_config_is_freed() {
    unsafe {
        let ctx = SSL_CTX_new(TLS_client_method());
        let mut config = ptr::null_mut();

        upki_config_new(ptr::null(), &mut config);
        upki_openssl_set_config(ctx, config); // takes ownership.

        // frees config for us.
        SSL_CTX_free(ctx);
    }
}

#[test]
fn load_cert_store_rejects_null() {
    assert_eq!(
        unsafe { upki_openssl_load_cert_store(ptr::null_mut(), ptr::null()) },
        -1
    );
}

#[test]
fn cert_store_callback_preverify_zero_returns_zero() {
    let ctx = StoreCtx::new();
    assert_eq!(
        unsafe { upki_openssl_cert_store_verify_callback(0, ctx.0) },
        0
    );
    assert!(ctx.untouched_error());
    assert_eq!(
        unsafe { upki_openssl_cert_store_verify_callback(1, ptr::null_mut()) },
        0
    );
}

#[test]
fn cert_store_callback_nonzero_depth_passes_through() {
    let mut ctx = StoreCtx::new();
    ctx.set_error_depth(1);
    assert_eq!(
        unsafe { upki_openssl_cert_store_verify_callback(1, ctx.0) },
        1
    );
    assert!(ctx.untouched_error());
}

#[test]
fn verifies_chain_anchored_in_cert_store() {
    let (ok, error) = verify_leaf(&[ROOT], &[ROOT]);
    assert_eq!(ok, 1);
    assert_eq!(error, X509_V_OK);
}

#[test]
fn rejects_chain_not_anchored_in_cert_store() {
    // OpenSSL itself trusts the root, but the upki store constrains trust to another root.
    let (ok, error) = verify_leaf(&[ROOT], &[OTHER_ROOT]);
    assert_eq!(ok, 0);
    assert_eq!(error, X509_V_ERR_CERT_UNTRUSTED);
}

/// Verify the leaf fixture with OpenSSL, loading `anchors` into the `X509_STORE`
/// and using a upki store of `constraint` in the verify callback.
fn verify_leaf(anchors: &[&[u8]], constraint: &[&[u8]]) -> (c_int, c_int) {
    let anchors = UpkiCertStore::with(anchors);
    let constraint = UpkiCertStore::with(constraint);
    unsafe {
        let store = X509_STORE_new();
        assert_eq!(upki_openssl_load_cert_store(store, anchors.0), 1);

        let ssl_ctx = SSL_CTX_new(TLS_client_method());
        let ssl = SSL_new(ssl_ctx);
        // The SSL_CTX takes ownership of the store pointer.
        upki_openssl_set_cert_store(ssl_ctx, constraint.into_raw());

        let leaf = parse(LEAF);
        let intermediates = OPENSSL_sk_new_null() as *mut stack_st_X509;
        let intermediate = parse(INTERMEDIATE);
        OPENSSL_sk_push(intermediates as *mut OPENSSL_STACK, intermediate.cast());

        let ctx = X509_STORE_CTX_new();
        assert_eq!(X509_STORE_CTX_init(ctx, store, leaf, intermediates), 1);
        X509_STORE_CTX_set_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx(), ssl.cast());
        X509_STORE_CTX_set_verify_cb(ctx, Some(upki_openssl_cert_store_verify_callback));

        let ok = X509_verify_cert(ctx);
        let error = X509_STORE_CTX_get_error(ctx);

        X509_STORE_CTX_free(ctx);
        X509_free(intermediate);
        OPENSSL_sk_free(intermediates as *mut OPENSSL_STACK);
        X509_free(leaf);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        X509_STORE_free(store);
        (ok, error)
    }
}

fn parse(der: &[u8]) -> *mut X509 {
    let mut data = der.as_ptr();
    let x509 = unsafe { d2i_X509(ptr::null_mut(), &mut data, der.len() as _) };
    assert!(!x509.is_null());
    x509
}

/// A upki certificate store opened through the C API.
struct UpkiCertStore(*mut upki_cert_store);

impl UpkiCertStore {
    fn into_raw(self) -> *mut upki_cert_store {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }

    fn with(certificates: &[&[u8]]) -> Self {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut store = CertificateStore::new();
        for certificate in certificates {
            store.add(certificate).unwrap();
        }
        store.save(file.path()).unwrap();

        let path = CString::new(file.path().to_str().unwrap()).unwrap();
        let mut ptr = ptr::null_mut();
        unsafe { upki_cert_store_open(path.as_ptr(), &mut ptr) };
        assert!(!ptr.is_null());
        Self(ptr)
    }
}

const ROOT: &[u8] = include_bytes!("../../upki/tests/data/cert-store-chain/root.der");
const OTHER_ROOT: &[u8] = include_bytes!("../../upki/tests/data/cert-store-chain/other-root.der");
const INTERMEDIATE: &[u8] = include_bytes!("../../upki/tests/data/cert-store-chain/inter.der");
const LEAF: &[u8] = include_bytes!("../../upki/tests/data/cert-store-chain/leaf.der");

struct StoreCtx(*mut X509_STORE_CTX);

impl StoreCtx {
    fn new() -> Self {
        let mut v = Self(unsafe { X509_STORE_CTX_new() });
        // we set a placeholder error here, which is intended to be unused
        // anywhere else, and allows detection of whether the error has been
        // set or preserved.
        assert!(!v.untouched_error());
        v.set_error(UNTOUCHED_ERROR);
        assert!(v.untouched_error());
        v
    }

    fn set_error_depth(&mut self, depth: i32) {
        unsafe { X509_STORE_CTX_set_error_depth(self.0, depth) };
    }

    fn error(&self) -> c_int {
        unsafe { X509_STORE_CTX_get_error(self.0) }
    }

    fn untouched_error(&self) -> bool {
        self.error() == UNTOUCHED_ERROR
    }

    fn set_error(&mut self, e: c_int) {
        unsafe { X509_STORE_CTX_set_error(self.0, e) }
    }

    fn set_verified_chain(&mut self, mut chain: Chain) {
        unsafe { X509_STORE_CTX_set0_verified_chain(self.0, chain.steal()) };
    }
}

impl Drop for StoreCtx {
    fn drop(&mut self) {
        unsafe { X509_STORE_CTX_free(self.0) }
    }
}

struct Chain(*mut stack_st_X509);

impl Chain {
    fn new() -> Self {
        Self(unsafe { OPENSSL_sk_new_null() as *mut stack_st_X509 })
    }

    fn push_null(&mut self) {
        unsafe { OPENSSL_sk_push(self.0 as *mut OPENSSL_STACK, ptr::null()) };
    }

    fn steal(&mut self) -> *mut stack_st_X509 {
        mem::replace(&mut self.0, ptr::null_mut())
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        unsafe { OPENSSL_sk_free(self.0 as *mut OPENSSL_STACK) }
    }
}

const UNTOUCHED_ERROR: c_int = 12345678;

unsafe extern "C" {
    fn X509_STORE_CTX_set_ex_data(
        ctx: *mut X509_STORE_CTX,
        idx: c_int,
        data: *mut core::ffi::c_void,
    ) -> c_int;
    fn X509_STORE_CTX_set_verify_cb(
        ctx: *mut X509_STORE_CTX,
        verify_cb: Option<unsafe extern "C" fn(c_int, *mut X509_STORE_CTX) -> c_int>,
    );
    fn X509_STORE_CTX_set_error_depth(ctx: *mut X509_STORE_CTX, depth: c_int);
    fn X509_STORE_CTX_set0_verified_chain(ctx: *mut X509_STORE_CTX, chain: *mut stack_st_X509);
}

impl Drop for UpkiCertStore {
    fn drop(&mut self) {
        unsafe { upki::ffi::upki_cert_store_free(self.0) }
    }
}
