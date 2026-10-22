//! upki command-line entrypoint.

use core::fmt;
use std::io::{BufReader, Write, stdin};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use eyre::{Context, Report, bail};
use rustls::RootCertStore;
use rustls::client::danger::ServerCertVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use upki::cert_store::distro::{DebianUbuntu, FedoraRhel, IngestionStrategy};
use upki::cert_store::{CertificateStore, Fingerprint};
#[cfg(feature = "__fetch")]
use upki::fetch;
use upki::revocation::{RevocationCheckInput, RevocationStatus, Store};
use upki::{Config, ConfigPath};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<ExitCode, Report> {
    let Args {
        command,
        config_file,
        verbose,
    } = Args::parse();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive(
                    match verbose {
                        true => LevelFilter::TRACE,
                        false => LevelFilter::ERROR,
                    }
                    .into(),
                )
                .from_env()?,
        )
        .init();

    let command = match command {
        Command::CertStore(command) => return run_cert_store(command, config_file),
        command => command,
    };

    let config_path = ConfigPath::new(config_file).wrap_err("cannot find configuration path")?;

    if let Command::ShowConfigPath = command {
        println!("{}", config_path.as_ref().display());
        return Ok(ExitCode::SUCCESS);
    }

    let config = Config::from_file_or_user_default(&config_path)?;

    Ok(match command {
        #[cfg(feature = "__fetch")]
        Command::Fetch { dry_run } => {
            fetch(dry_run, &config).await?;
            ExitCode::SUCCESS
        }
        #[cfg(feature = "__fetch")]
        Command::Verify => {
            Store::from_config(&config).verify()?;
            ExitCode::SUCCESS
        }
        Command::ShowConfigPath => unreachable!(),
        Command::CertStore(_) => unreachable!(),
        Command::ShowConfig => {
            print!(
                "{}",
                toml::to_string_pretty(&config).wrap_err("cannot format configuration")?
            );
            ExitCode::SUCCESS
        }
        Command::Revocation(Revocation::Check) => {
            let mut certs = vec![];

            for cert in CertificateDer::pem_reader_iter(&mut BufReader::new(stdin())) {
                certs.push(cert.wrap_err("cannot read certificate from stdin")?);
            }

            let input = RevocationCheckInput::from_certificates(&certs)?;
            Store::from_config(&config)
                .check(&input)?
                .to_cli()
        }
    })
}

fn run_cert_store(
    command: CertStoreCommand,
    config_file: Option<PathBuf>,
) -> Result<ExitCode, Report> {
    let config_path =
        ConfigPath::new(config_file.clone()).wrap_err("cannot find configuration path")?;
    let config = Config::from_file_or_user_default(&config_path)?;
    match command {
        CertStoreCommand::Sync {
            store,
            bundle,
            distro,
            allow_revoked,
        } => {
            let store = store.resolve(&config)?;
            let distro = match distro {
                Some(distro) => distro,
                None => detect_distro()?,
            };
            let strategy = distro.strategy(bundle)?;
            let certificates = strategy.load()?;
            let revocation_store = Store::from_config(&config);
            let certificates = filter_revoked(certificates, &revocation_store, allow_revoked)?;
            let mut certificate_store = open_certificate_store(&store)?;
            strategy.reconcile(&mut certificate_store, &certificates)?;
            save_certificate_store(&certificate_store, &store)?;
            eprintln!(
                "Synchronized {} snapshot with {} certificates to {}",
                distro,
                certificates.len(),
                store.display()
            );
        }
        CertStoreCommand::Import {
            store,
            allow_revoked,
        } => {
            let store = store.resolve(&config)?;
            let mut reader = BufReader::new(stdin());
            let certificates = CertificateDer::pem_reader_iter(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .wrap_err("cannot parse certificates from stdin")?;
            if certificates.is_empty() {
                bail!("standard input contains no certificates");
            }
            let revocation_store = Store::from_config(&config);
            let certificates = filter_revoked(certificates, &revocation_store, allow_revoked)?;
            let mut certificate_store = open_certificate_store(&store)?;
            for certificate in &certificates {
                certificate_store.add(certificate.as_ref())?;
            }
            save_certificate_store(&certificate_store, &store)?;
            eprintln!(
                "Imported {} manual certificates to {}",
                certificates.len(),
                store.display()
            );
        }
        CertStoreCommand::List { store, show_source } => {
            let store = store.resolve(&config)?;
            let certificate_store = CertificateStore::open(&store)?;
            for (fingerprint, _) in certificate_store.iter() {
                if show_source {
                    let source = certificate_store
                        .source(&fingerprint)
                        .expect("iterated certificates have a source");
                    println!("{} {}", fingerprint.to_hex(), source_name(source));
                } else {
                    println!("{}", fingerprint.to_hex());
                }
            }
        }
        CertStoreCommand::Export { store, fingerprint } => {
            let store = store.resolve(&config)?;
            let certificate_store = CertificateStore::open(&store)?;
            let fingerprint = Fingerprint::from_hex(&fingerprint)?;
            let der = certificate_store
                .get(&fingerprint)
                .ok_or_else(|| eyre::eyre!("certificate not found: {}", fingerprint.to_hex()))?;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(der)?;
        }
        CertStoreCommand::Verify { store, server_name } => {
            let store = store.resolve(&config)?;
            let server_name = ServerName::try_from(server_name).wrap_err("invalid server name")?;
            let certificate_store =
                CertificateStore::open(&store).wrap_err("cannot open certificate store")?;
            let mut roots = RootCertStore::empty();
            for (fingerprint, der) in certificate_store.iter() {
                roots
                    .add(CertificateDer::from(der))
                    .wrap_err_with(|| format!("invalid trust anchor: {}", fingerprint.to_hex()))?;
            }
            if roots.is_empty() {
                bail!("cannot build certificate verifier: no trust anchors");
            }
            let verifier = rustls_upki::ServerVerifier::new(
                rustls_upki::Policy {
                    missing_data: rustls_upki::Outcome::Allowed,
                    ..Default::default()
                },
                config_file,
                Arc::new(roots),
                Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            )
            .wrap_err("cannot build certificate verifier")?;
            let certificates = CertificateDer::pem_reader_iter(&mut BufReader::new(stdin()))
                .collect::<Result<Vec<_>, _>>()
                .wrap_err("cannot parse certificates from stdin")?;
            let (end_entity, intermediates) = certificates
                .split_first()
                .ok_or_else(|| eyre::eyre!("standard input contains no certificates"))?;
            verifier
                .verify_server_cert(
                    end_entity,
                    intermediates,
                    &server_name,
                    &[],
                    UnixTime::now(),
                )
                .wrap_err("certificate verification failed")?;
            println!("Verified");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn detect_distro() -> Result<CertStoreDistro, Report> {
    let distro = whatadistro::Distro::current()
        .ok_or_else(|| eyre::eyre!("cannot detect distribution; pass --distro explicitly"))?;
    distro_from_id(&distro.id().to_string())
}

fn distro_from_id(id: &str) -> Result<CertStoreDistro, Report> {
    match id {
        "debian" => Ok(CertStoreDistro::Debian),
        "ubuntu" => Ok(CertStoreDistro::Ubuntu),
        "fedora" => Ok(CertStoreDistro::Fedora),
        "rhel" => Ok(CertStoreDistro::Rhel),
        "centos" => Ok(CertStoreDistro::Centos),
        "rocky" => Ok(CertStoreDistro::Rocky),
        "almalinux" => Ok(CertStoreDistro::Almalinux),
        "ol" => Ok(CertStoreDistro::OracleLinux),
        detected => bail!(
            "automatic certificate-store sync is unsupported for {detected}; use --distro with a compatible adapter (see sync --help)"
        ),
    }
}

fn source_name(source: upki::cert_store::CertificateSource) -> &'static str {
    match source {
        upki::cert_store::CertificateSource::Manual => "manual",
        upki::cert_store::CertificateSource::Distro => "distro",
    }
}

fn save_certificate_store(store: &CertificateStore, path: &std::path::Path) -> Result<(), Report> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).wrap_err("cannot create certificate store directory")?;
    }
    store.save(path)?;
    Ok(())
}

fn filter_revoked(
    certificates: Vec<CertificateDer<'static>>,
    revocation_store: &Store,
    allow_revoked: bool,
) -> Result<Vec<CertificateDer<'static>>, Report> {
    let mut accepted = Vec::with_capacity(certificates.len());
    for certificate in &certificates {
        let mut chain = Vec::with_capacity(certificates.len() + 1);
        chain.push(certificate.clone());
        chain.extend(certificates.iter().cloned());
        let input = RevocationCheckInput::from_certificates(&chain)
            .wrap_err("cannot prepare certificate revocation check")?;
        match revocation_store
            .check(&input)
            .wrap_err("cannot check certificate revocation")?
        {
            RevocationStatus::CertainlyRevoked if !allow_revoked => {
                let fingerprint = CertificateStore::new()
                    .add(certificate.as_ref())?
                    .to_hex();
                eprintln!("Skipping revoked certificate {fingerprint}");
            }
            _ => accepted.push(certificate.clone()),
        }
    }
    Ok(accepted)
}

fn open_certificate_store(path: &std::path::Path) -> Result<CertificateStore, Report> {
    match CertificateStore::open(path) {
        Ok(store) => Ok(store),
        Err(upki::cert_store::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(CertificateStore::new())
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Parser)]
#[command(name = "upki", author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Use this specific configuration file.  This must exist.
    ///
    /// If not specified, this tool looks for its configuration file in a platform-standard local directory.
    #[arg(long)]
    config_file: Option<PathBuf>,

    /// Emit logging output.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Update the local cache of crlite filters, downloading them as needed.
    ///
    /// If the `revocation.cache_dir` path does not exist, this tool creates it and parent directories.
    ///
    /// This also deletes filters that become unreferenced.
    #[cfg(feature = "__fetch")]
    Fetch {
        /// Download the new manifest, and then describe what actions are needed to
        /// synchronize with the remote server.
        #[arg(long)]
        dry_run: bool,
    },

    /// Verifies the local cache of crlite filters.
    ///
    /// Exits zero if the manifest and all referenced filters are present.
    ///
    /// Exits non-zero if the manifest if any filter file is missing or corrupt.
    ///
    /// This command does no network I/O.  It does not say anything whether the files are up-to-date or recent.
    #[cfg(feature = "__fetch")]
    Verify,

    /// Checks the revocation status of a certificate.
    #[clap(subcommand)]
    Revocation(Revocation),

    /// Maintain and query the independent certificate store.
    #[clap(subcommand)]
    CertStore(CertStoreCommand),

    /// Print the location of the configuration file.
    ShowConfigPath,

    /// Print the configuration that will be used.
    ShowConfig,
}

#[derive(Debug, Subcommand)]
enum CertStoreCommand {
    /// Verify a PEM certificate chain from standard input against the store.
    ///
    /// The first certificate must be the TLS server's end-entity certificate,
    /// followed by any intermediates. Only certificates in the store are trusted;
    /// roots supplied on stdin do not establish trust.
    ///
    /// Checks signatures, validity dates, server-auth usage, and the server name.
    /// Checks leaf revocation when local data is available. Missing data or
    /// coverage is allowed. Does not fetch missing intermediates or revocation data.
    /// Prints "Verified" and exits 0 on success; errors exit 1.
    Verify {
        #[command(flatten)]
        store: StoreOptions,
        /// Expected DNS name or IP address (not a URL).
        #[arg(long)]
        server_name: String,
    },

    /// Import the generated system certificate source into upki's snapshot.
    ///
    /// Run after the distro updates its trust store, such as from a package hook.
    /// Reconciles distro-managed entries only inside upki's snapshot; it does not
    /// replace system trust files or redirect applications to this store.
    Sync {
        #[command(flatten)]
        store: StoreOptions,
        /// Distro adapter to use (autodetected when omitted).
        #[arg(long, value_enum)]
        distro: Option<CertStoreDistro>,
        /// Override the Debian/Ubuntu generated bundle path (not supported by Fedora/RHEL).
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Allow certificates known to be revoked by the local revocation data.
        #[arg(long)]
        allow_revoked: bool,
    },

    /// Import administrator-managed certificates from PEM on standard input.
    Import {
        #[command(flatten)]
        store: StoreOptions,
        /// Allow certificates known to be revoked by the local revocation data.
        #[arg(long)]
        allow_revoked: bool,
    },

    /// Print fingerprints for certificates in a store.
    List {
        #[command(flatten)]
        store: StoreOptions,
        /// Include whether each certificate is manual or distro-managed.
        #[arg(long)]
        show_source: bool,
    },

    /// Write one certificate's DER bytes to standard output.
    Export {
        #[command(flatten)]
        store: StoreOptions,
        /// 64-digit hexadecimal SHA-256 fingerprint.
        #[arg(long)]
        fingerprint: String,
    },
}

#[derive(Debug, ClapArgs)]
struct StoreOptions {
    /// Snapshot path (default: UPKI_CERT_STORE, config cert-store, or cache-dir/certificates.store).
    #[arg(long)]
    store: Option<PathBuf>,
}

impl StoreOptions {
    fn resolve(self, config: &Config) -> Result<PathBuf, Report> {
        let path = self
            .store
            .or_else(|| std::env::var_os("UPKI_CERT_STORE").map(PathBuf::from))
            .unwrap_or_else(|| config.cert_store_path_or_default());
        if path.as_os_str().is_empty() {
            bail!("certificate store path must not be empty");
        }
        Ok(path)
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CertStoreDistro {
    Debian,
    Ubuntu,
    Fedora,
    Rhel,
    Centos,
    Rocky,
    Almalinux,
    OracleLinux,
}

impl CertStoreDistro {
    fn strategy(self, bundle: Option<PathBuf>) -> Result<Box<dyn IngestionStrategy>, Report> {
        match self {
            Self::Debian | Self::Ubuntu => Ok(Box::new(DebianUbuntu::new(bundle))),
            Self::Fedora
            | Self::Rhel
            | Self::Centos
            | Self::Rocky
            | Self::Almalinux
            | Self::OracleLinux => {
                if bundle.is_some() {
                    bail!(
                        "--bundle is only supported by Debian/Ubuntu; Fedora/RHEL requires p11-kit policy extraction"
                    );
                }
                Ok(Box::new(FedoraRhel::new()))
            }
        }
    }
}

impl fmt::Display for CertStoreDistro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debian => f.write_str("Debian"),
            Self::Ubuntu => f.write_str("Ubuntu"),
            Self::Fedora => f.write_str("Fedora"),
            Self::Rhel => f.write_str("RHEL"),
            Self::Centos => f.write_str("CentOS"),
            Self::Rocky => f.write_str("Rocky Linux"),
            Self::Almalinux => f.write_str("AlmaLinux"),
            Self::OracleLinux => f.write_str("Oracle Linux"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Revocation {
    /// Check the revocation status of an end-entity certificate.
    ///
    /// This interface reads a sequence of PEM-encoded certificates from standard input.
    /// The first **must** be the end-entity certificate.  The end-entity certificate's issuer
    /// **must** be present in the other certificates (but does not need to be in any specific
    /// position).
    ///
    /// Note this interface **only** checks the end-entity certificate for revocation.  It does
    /// **not** check any of the certificates for validity: it assumes the caller has done any
    /// required checks **before** calling this interface (path building, naming validation,
    /// expiry checking, etc.).
    ///
    /// # Exit status
    ///
    /// 0 means the certificate is not revoked or no revocation information is available,
    /// 1 means an error prevented the revocation check, and
    /// 2 means the revocation check completed and the certificate is revoked.
    Check,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_supported_distribution_ids() {
        assert!(matches!(
            distro_from_id("ubuntu").unwrap(),
            CertStoreDistro::Ubuntu
        ));
        assert!(matches!(
            distro_from_id("debian").unwrap(),
            CertStoreDistro::Debian
        ));
        for id in ["fedora", "rhel", "centos", "rocky", "almalinux", "ol"] {
            let strategy = distro_from_id(id)
                .unwrap()
                .strategy(None)
                .unwrap();
            assert_eq!(
                strategy.source_path(),
                std::path::Path::new("/usr/bin/trust")
            );
        }
        assert!(distro_from_id("arch").is_err());
        assert!(distro_from_id("opensuse-leap").is_err());
        assert!(distro_from_id("alpine").is_err());
    }

    #[test]
    fn bundle_overrides_are_only_supported_for_debian_ubuntu() {
        let bundle = PathBuf::from("/test/bundle.pem");
        for distro in [CertStoreDistro::Debian, CertStoreDistro::Ubuntu] {
            let strategy = distro
                .strategy(Some(bundle.clone()))
                .unwrap();
            assert_eq!(strategy.source_path(), bundle);
        }
        for id in ["fedora", "rhel", "centos", "rocky", "almalinux", "ol"] {
            assert!(
                distro_from_id(id)
                    .unwrap()
                    .strategy(Some(bundle.clone()))
                    .is_err()
            );
        }
    }
}
