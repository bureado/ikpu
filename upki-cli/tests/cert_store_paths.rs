use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use tempfile::TempDir;
use upki::cert_store::CertificateStore;

fn run(command: &mut Command, pem: &str) -> Output {
    let mut child = command
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

fn assert_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn config(path: &Path, cache: &Path, store: Option<&Path>) {
    let mut value = format!(
        "cache-dir = {}\n",
        toml::Value::String(cache.to_str().unwrap().into())
    );
    if let Some(store) = store {
        value += &format!(
            "cert-store = {}\n",
            toml::Value::String(store.to_str().unwrap().into())
        );
    }
    value += "[revocation]\nfetch-url = \"\"\n";
    std::fs::write(path, value).unwrap();
}

#[test]
fn every_operation_uses_the_same_store_precedence() {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let leaf = CertificateParams::new(vec!["example.com".into()])
        .unwrap()
        .signed_by(&KeyPair::generate().unwrap(), &root)
        .unwrap();
    let mut expected = CertificateStore::new();
    let fingerprint = expected.add(root.der()).unwrap();

    for selection in ["fallback", "config", "environment", "explicit"] {
        let temp = TempDir::new().unwrap();
        let cache = temp.path().join("cache");
        let configured = temp
            .path()
            .join("configured/certificates.store");
        let environment = temp
            .path()
            .join("environment/certificates.store");
        let explicit = temp
            .path()
            .join("explicit/certificates.store");
        let fallback = cache.join("certificates.store");
        let config_path = temp.path().join("config.toml");
        let selected = match selection {
            "explicit" => &explicit,
            "environment" => &environment,
            "config" => &configured,
            _ => &fallback,
        };
        config(
            &config_path,
            &cache,
            (selection != "fallback").then_some(configured.as_path()),
        );
        std::fs::create_dir_all(cache.join("revocation")).unwrap();
        std::fs::write(cache.join("revocation/index.bin"), b"upkiidx1\0\0\0\0\0\0").unwrap();
        let bundle = temp.path().join("bundle.pem");
        std::fs::write(&bundle, root.pem()).unwrap();
        let command = |operation: &str| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_upki"));
            command
                .env_remove("UPKI_CERT_STORE")
                .arg("--config-file")
                .arg(&config_path)
                .args(["cert-store", operation]);
            if matches!(selection, "environment" | "explicit") {
                command.env("UPKI_CERT_STORE", &environment);
            }
            if selection == "explicit" {
                command.arg("--store").arg(&explicit);
            }
            command
        };
        let output = run(&mut command("list"), "");
        assert_eq!(output.status.code(), Some(1));
        assert!(!selected.exists());
        assert_success(run(&mut command("import"), &root.pem()));
        assert!(selected.exists());
        assert_eq!(
            assert_success(run(&mut command("list"), "")).stdout,
            format!("{}\n", fingerprint.to_hex()).as_bytes()
        );
        assert_eq!(
            assert_success(run(
                command("export").args(["--fingerprint", &fingerprint.to_hex()]),
                "",
            ))
            .stdout,
            root.der().as_ref()
        );
        assert_success(run(
            command("verify").args(["--server-name", "example.com"]),
            &leaf.pem(),
        ));
        assert_success(run(
            command("sync")
                .args(["--distro", "debian", "--bundle"])
                .arg(&bundle),
            "",
        ));
        assert_eq!(
            CertificateStore::open(selected)
                .unwrap()
                .len(),
            1
        );
        for unselected in [&fallback, &configured, &environment, &explicit] {
            if unselected != selected {
                assert!(!unselected.exists());
            }
        }
    }
}

#[test]
fn rejects_empty_overrides_but_explicit_store_wins_over_empty_environment() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("config.toml");
    config(&config_path, temp.path(), None);
    let store = temp.path().join("certificates.store");
    CertificateStore::new()
        .save(&store)
        .unwrap();
    for explicit in [None, Some(""), Some(store.to_str().unwrap())] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upki"));
        command
            .env("UPKI_CERT_STORE", "")
            .arg("--config-file")
            .arg(&config_path)
            .args(["cert-store", "list"]);
        if let Some(path) = explicit {
            command.args(["--store", path]);
        }
        let output = command.output().unwrap();
        if explicit == Some(store.to_str().unwrap()) {
            assert_success(output);
        } else if explicit == Some("") {
            assert_eq!(output.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&output.stderr).contains("--store"));
        } else {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("certificate store path must not be empty")
            );
        }
    }
}
