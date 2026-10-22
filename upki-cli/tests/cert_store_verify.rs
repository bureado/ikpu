use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, date_time_ymd,
};
use tempfile::TempDir;
use upki::cert_store::CertificateStore;

struct Chain {
    root: CertifiedIssuer<'static, KeyPair>,
    intermediate: CertifiedIssuer<'static, KeyPair>,
    leaf: Certificate,
}

impl Chain {
    fn new() -> Self {
        let root =
            CertifiedIssuer::self_signed(ca_params("root"), KeyPair::generate().unwrap()).unwrap();
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("intermediate"),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let leaf = leaf_params()
            .signed_by(&KeyPair::generate().unwrap(), &intermediate)
            .unwrap();
        Self {
            root,
            intermediate,
            leaf,
        }
    }

    fn pem(&self) -> String {
        self.leaf.pem() + &self.intermediate.pem()
    }

    fn store(&self, path: &Path) {
        let mut store = CertificateStore::new();
        store.add(self.root.der()).unwrap();
        store.save(path).unwrap();
    }
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params
}

fn leaf_params() -> CertificateParams {
    let mut params =
        CertificateParams::new(vec!["example.com".into(), "127.0.0.1".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
}

fn verify(store: &Path, server_name: &str, pem: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_upki"))
        .args(["cert-store", "verify", "--store"])
        .arg(store)
        .args(["--server-name", server_name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(pem.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn assert_verified(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"Verified\n");
    assert!(output.stderr.is_empty());
}

fn assert_rejected(output: Output, message: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(message), "{stderr}");
}

#[test]
fn verifies_dns_and_ip_against_manual_and_distro_roots() {
    let chain = Chain::new();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    chain.store(&path);
    assert_verified(verify(&path, "example.com", &chain.pem()));
    assert_verified(verify(&path, "127.0.0.1", &chain.pem()));

    let mut store = CertificateStore::new();
    store
        .sync_distro([chain.root.der().as_ref()])
        .unwrap();
    store.save(&path).unwrap();
    // A root in the input chain is harmless, but trust still comes from the store.
    assert_verified(verify(
        &path,
        "example.com",
        &(chain.pem() + &chain.root.pem()),
    ));
}

#[test]
fn verifies_a_leaf_issued_directly_by_a_stored_root() {
    let chain = Chain::new();
    let leaf = leaf_params()
        .signed_by(&KeyPair::generate().unwrap(), &chain.root)
        .unwrap();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    chain.store(&path);
    assert_verified(verify(&path, "example.com", &leaf.pem()));
}

#[test]
fn rejects_untrusted_roots_even_when_supplied_on_stdin() {
    let chain = Chain::new();
    let unrelated = Chain::new();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    unrelated.store(&path);
    assert_rejected(
        verify(&path, "example.com", &(chain.pem() + &chain.root.pem())),
        "certificate verification failed",
    );
}

#[test]
fn rejects_wrong_names_and_missing_intermediates() {
    let chain = Chain::new();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    chain.store(&path);
    for name in ["wrong.example", "127.0.0.2"] {
        assert_rejected(verify(&path, name, &chain.pem()), "not valid for name");
    }
    assert_rejected(
        verify(&path, "example.com", &chain.leaf.pem()),
        "UnknownIssuer",
    );
    assert_rejected(
        verify(
            &path,
            "example.com",
            &(chain.intermediate.pem() + &chain.leaf.pem()),
        ),
        "certificate verification failed",
    );
}

#[test]
fn rejects_expired_future_and_client_only_certificates() {
    let chain = Chain::new();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    chain.store(&path);

    let mut expired = leaf_params();
    expired.not_before = date_time_ymd(2000, 1, 1);
    expired.not_after = date_time_ymd(2001, 1, 1);
    let mut future = leaf_params();
    future.not_before = date_time_ymd(3000, 1, 1);
    future.not_after = date_time_ymd(3001, 1, 1);
    let mut client_only = leaf_params();
    client_only.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    for (params, message) in [
        (expired, "certificate expired"),
        (future, "certificate not valid yet"),
        (client_only, "certificate does not allow extended key usage"),
    ] {
        let leaf = params
            .signed_by(&KeyPair::generate().unwrap(), &chain.intermediate)
            .unwrap();
        assert_rejected(
            verify(
                &path,
                "example.com",
                &(leaf.pem() + &chain.intermediate.pem()),
            ),
            message,
        );
    }
}

#[test]
fn rejects_a_signature_from_a_different_issuer_key() {
    let chain = Chain::new();
    let other = Chain::new();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    chain.store(&path);
    assert_rejected(
        verify(
            &path,
            "example.com",
            &(other.leaf.pem() + &chain.intermediate.pem()),
        ),
        "BadSignature",
    );
}

#[test]
fn rejects_empty_malformed_input_and_invalid_server_names() {
    let chain = Chain::new();
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    chain.store(&path);
    for input in ["", "not a certificate"] {
        assert_rejected(
            verify(&path, "example.com", input),
            "standard input contains no certificates",
        );
    }
    let malformed = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
    assert_rejected(
        verify(&path, "example.com", malformed),
        "cannot parse certificates from stdin",
    );
    assert_rejected(
        verify(&path, "example.com", &(chain.pem() + malformed)),
        "cannot parse certificates from stdin",
    );
    assert_rejected(
        verify(&path, "https://example.com", ""),
        "invalid server name",
    );
}

#[test]
fn rejects_missing_corrupt_empty_and_malformed_stores() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("certificates.store");
    assert_rejected(
        verify(&path, "example.com", ""),
        "cannot open certificate store",
    );
    std::fs::write(&path, b"corrupt").unwrap();
    assert_rejected(
        verify(&path, "example.com", ""),
        "cannot open certificate store",
    );
    let mut store = CertificateStore::new();
    store.save(&path).unwrap();
    assert_rejected(
        verify(&path, "example.com", ""),
        "cannot build certificate verifier",
    );
    store
        .add(b"not a DER certificate")
        .unwrap();
    store.save(&path).unwrap();
    assert_rejected(verify(&path, "example.com", ""), "invalid trust anchor:");
}

#[test]
fn requires_store_and_server_name_options() {
    for args in [
        vec!["cert-store", "verify", "--store", "unused"],
        vec!["cert-store", "verify", "--server-name", "example.com"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_upki"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("required arguments were not provided")
        );
    }
}
