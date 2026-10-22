//! upki command-line entrypoint.

use std::fs::File;
use std::io::{BufReader, Write, stdin};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use eyre::{Context, Report, bail};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use upki::cert_store::{CertificateStore, Fingerprint};
#[cfg(feature = "__fetch")]
use upki::fetch;
use upki::revocation::{RevocationCheckInput, Store};
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
        Command::CertStore(command) => return run_cert_store(command),
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

fn run_cert_store(command: CertStoreCommand) -> Result<ExitCode, Report> {
    match command {
        CertStoreCommand::SyncUbuntu { store, bundle } => {
            let file = File::open(&bundle)
                .wrap_err_with(|| format!("cannot open Ubuntu CA bundle {}", bundle.display()))?;
            let mut reader = BufReader::new(file);
            let certificates = CertificateDer::pem_reader_iter(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .wrap_err("cannot parse Ubuntu CA bundle")?;
            if certificates.is_empty() {
                bail!("Ubuntu CA bundle contains no certificates");
            }

            let mut certificate_store = CertificateStore::new();
            for certificate in &certificates {
                certificate_store.add(certificate.as_ref())?;
            }
            certificate_store.save(&store)?;
            eprintln!(
                "Synchronized {} certificates to {}",
                certificate_store.len(),
                store.display()
            );
        }
        CertStoreCommand::List { store } => {
            let certificate_store = CertificateStore::open(&store)?;
            for (fingerprint, _) in certificate_store.iter() {
                println!("{}", fingerprint.to_hex());
            }
        }
        CertStoreCommand::Export { store, fingerprint } => {
            let certificate_store = CertificateStore::open(&store)?;
            let fingerprint = Fingerprint::from_hex(&fingerprint)?;
            let der = certificate_store
                .get(&fingerprint)
                .ok_or_else(|| eyre::eyre!("certificate not found: {}", fingerprint.to_hex()))?;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(der)?;
        }
    }
    Ok(ExitCode::SUCCESS)
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
    /// Replace the store from Ubuntu's generated system CA bundle.
    ///
    /// Run this after update-ca-certificates, such as from a package postinst
    /// script or /etc/ca-certificates/update.d hook.
    SyncUbuntu {
        /// Destination snapshot file.
        #[arg(long)]
        store: PathBuf,
        /// Ubuntu/Debian generated bundle.
        #[arg(long, default_value = "/etc/ssl/certs/ca-certificates.crt")]
        bundle: PathBuf,
    },

    /// Print fingerprints for certificates in a store.
    List {
        /// Store snapshot file.
        #[arg(long)]
        store: PathBuf,
    },

    /// Write one certificate's DER bytes to standard output.
    Export {
        /// Store snapshot file.
        #[arg(long)]
        store: PathBuf,
        /// 64-digit hexadecimal SHA-256 fingerprint.
        #[arg(long)]
        fingerprint: String,
    },
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
