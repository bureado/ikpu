use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use clubcard::builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon};
use clubcard_crlite::builder::CRLiteBuilderItem;
use clubcard_crlite::{CRLiteClubcard, CRLiteCoverage, CRLiteQuery, Encoding};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedIssuer, CustomExtension, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, date_time_ymd,
};
use tempfile::TempDir;
use upki::cert_store::CertificateStore;
use upki::revocation::RevocationCheckInput;

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
    let temp = TempDir::new().unwrap();
    verify_with_config(store, server_name, pem, &write_config(&temp))
}

fn write_config(temp: &TempDir) -> std::path::PathBuf {
    let path = temp.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "cache-dir = {}\n[revocation]\nfetch-url = \"\"\n",
            toml::Value::String(temp.path().to_str().unwrap().into())
        ),
    )
    .unwrap();
    path
}

fn verify_with_config(store: &Path, server_name: &str, pem: &str, config: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_upki"))
        .arg("--config-file")
        .arg(config)
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

fn logged_leaf(issuer: &CertifiedIssuer<'_, KeyPair>, serial: u64) -> Certificate {
    let mut params = leaf_params();
    params.serial_number = Some(serial.into());
    // A synthetic SCT: CRLite uses its log ID and timestamp, not its signature.
    let mut sct = vec![0];
    sct.extend_from_slice(&[0; 32]);
    sct.extend_from_slice(&1000u64.to_be_bytes());
    sct.extend_from_slice(&[0, 0, 4, 3, 0, 1, 0]);
    let mut extension = vec![4, 52, 0, 50, 0, 48];
    extension.extend_from_slice(&sct);
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
            extension,
        ));
    params
        .signed_by(&KeyPair::generate().unwrap(), issuer)
        .unwrap()
}

fn write_revocation_data(
    temp: &TempDir,
    revoked: &Certificate,
    issuer: &CertifiedIssuer<'_, KeyPair>,
) {
    let input =
        RevocationCheckInput::from_certificates(&[revoked.der().clone(), issuer.der().clone()])
            .unwrap();
    let mut builder = ClubcardBuilder::new();
    let mut approx = builder.new_approx_builder(&input.issuer_spki_hash.0);
    approx.insert(CRLiteBuilderItem::revoked(
        input.issuer_spki_hash,
        input.cert_serial.0.clone(),
    ));
    approx.set_universe_size(256);
    builder.collect_approx_ribbons(vec![ApproximateRibbon::from(approx)]);
    let mut exact = builder.new_exact_builder(&input.issuer_spki_hash.0);
    exact.insert(CRLiteBuilderItem::revoked(
        input.issuer_spki_hash,
        input.cert_serial.0,
    ));
    exact.insert(CRLiteBuilderItem::not_revoked(
        input.issuer_spki_hash,
        vec![2],
    ));
    for serial in 0u64..256 {
        exact.insert(CRLiteBuilderItem::not_revoked(
            input.issuer_spki_hash,
            serial.to_be_bytes().to_vec(),
        ));
    }
    builder.collect_exact_ribbons(vec![ExactRibbon::from(exact)]);
    let coverage = CRLiteCoverage::from_mozilla_ct_logs_json(
        br#"[{"LogID":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","MinTimestamp":0,"MaxTimestamp":2000,"MMD":0,"MinEntry":0}]"#
            .as_slice(),
    );
    let filter = CRLiteClubcard::from(builder.build::<CRLiteQuery<'_>>(coverage, ()));
    let dir = temp.path().join("revocation");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
        dir.join("test.filter"),
        filter.to_bytes(Encoding::V4).unwrap(),
    )
    .unwrap();

    // One filter, one log, one coverage interval, using the index's V1 encoding.
    let mut index = b"upkiidx1".to_vec();
    index.extend_from_slice(&1u16.to_be_bytes());
    index.extend_from_slice(&1u32.to_be_bytes());
    let mut filename = [0; 32];
    filename[..11].copy_from_slice(b"test.filter");
    index.extend_from_slice(&filename);
    index.extend_from_slice(&[0; 32]);
    index.extend_from_slice(&88u64.to_be_bytes());
    index.extend_from_slice(&1u16.to_be_bytes());
    index.extend_from_slice(&0u16.to_be_bytes());
    index.extend_from_slice(&0u64.to_be_bytes());
    index.extend_from_slice(&2000u64.to_be_bytes());
    std::fs::write(dir.join("index.bin"), index).unwrap();
}

#[test]
fn checks_loaded_revocation_data_for_intermediate_and_root_issued_leaves() {
    let chain = Chain::new();
    for (issuer, directly_issued) in [(&chain.intermediate, false), (&chain.root, true)] {
        let temp = TempDir::new().unwrap();
        let config = write_config(&temp);
        let path = temp.path().join("certificates.store");
        chain.store(&path);
        let revoked = logged_leaf(issuer, 1);
        let unrevoked = logged_leaf(issuer, 2);
        let pem = revoked.pem() + &issuer.pem();
        assert_verified(verify_with_config(&path, "example.com", &pem, &config));
        write_revocation_data(&temp, &revoked, issuer);
        assert_rejected(
            verify_with_config(&path, "example.com", &pem, &config),
            "Revoked",
        );
        if !directly_issued {
            let unrelated = Chain::new();
            assert_rejected(
                verify_with_config(
                    &path,
                    "example.com",
                    &(revoked.pem() + &unrelated.intermediate.pem() + &issuer.pem()),
                    &config,
                ),
                "Revoked",
            );
        }
        assert_verified(verify_with_config(
            &path,
            "example.com",
            &(unrevoked.pem() + &issuer.pem()),
            &config,
        ));
        // The root need not be supplied on stdin, even for revocation checking.
        let direct = logged_leaf(&chain.root, 1);
        let output = verify_with_config(&path, "example.com", &direct.pem(), &config);
        if directly_issued {
            assert_rejected(output, "Revoked");
        } else {
            assert_verified(output);
        }
        assert_verified(verify_with_config(
            &path,
            "example.com",
            &chain.pem(),
            &config,
        ));
    }
}

#[test]
fn rejects_corrupt_revocation_data_and_invalid_configuration() {
    let chain = Chain::new();
    let temp = TempDir::new().unwrap();
    let config = write_config(&temp);
    let path = temp.path().join("certificates.store");
    chain.store(&path);
    let leaf = logged_leaf(&chain.intermediate, 1);
    write_revocation_data(&temp, &leaf, &chain.intermediate);
    let pem = leaf.pem() + &chain.intermediate.pem();
    let filter = temp
        .path()
        .join("revocation/test.filter");
    std::fs::remove_file(&filter).unwrap();
    assert_rejected(
        verify_with_config(&path, "example.com", &pem, &config),
        "cannot read file",
    );
    std::fs::write(&filter, b"corrupt").unwrap();
    assert_rejected(
        verify_with_config(&path, "example.com", &pem, &config),
        "cannot decode file",
    );
    std::fs::write(temp.path().join("revocation/index.bin"), b"corrupt").unwrap();
    assert_rejected(
        verify_with_config(&path, "example.com", &pem, &config),
        "cannot decode index file",
    );
    std::fs::write(&config, b"not valid toml").unwrap();
    assert_rejected(
        verify_with_config(&path, "example.com", &chain.pem(), &config),
        "failed to parse config file",
    );
    std::fs::remove_file(&config).unwrap();
    assert_rejected(
        verify_with_config(&path, "example.com", &chain.pem(), &config),
        "failed to read config file",
    );
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
fn requires_server_name_option() {
    for args in [vec!["cert-store", "verify", "--store", "unused"]] {
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
