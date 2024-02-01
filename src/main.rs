use chrono::{Duration, NaiveDateTime};
use clap::Parser;
use openssl::asn1::Asn1TimeRef;
use openssl::x509::X509;
use openssl::{asn1::Asn1Time, pkcs12::Pkcs12};
use std::fmt::Write as WriteFmt;
use std::io::prelude::*;
use std::process;
use std::{fs::File, io::Read, path::PathBuf, process::Command};

/// Store PKCS12 contents in a 1Password item
///
/// The certificate and key will be stored inside the 1Password item as
/// PEM files cert.pem, key.pem.
///
/// Requires the `op` binary to be in your PATH.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to PKCS12 file
    #[arg(short, long)]
    file: PathBuf,

    /// Password to decrypt PKCS12 file
    #[arg(short, long)]
    password: String,

    /// 1Password item title
    #[arg(short, long)]
    title: String,

    /// 1Password vault
    #[arg(long)]
    vault: String,

    /// Filename to use for cert part in 1Password item
    #[arg(short, long, default_value = "cert.pem")]
    cert_filename: String,

    /// Filename to use for key part in 1Password item
    #[arg(short, long, default_value = "key.pem")]
    key_filename: String,

    #[arg(short, long)]
    dry_run: bool,

    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let cert_filename = args.cert_filename.replace('.', "\\.");
    let key_filename = args.key_filename.replace('.', "\\.");

    let mut pkcs12_bytes = Vec::new();
    File::open(&args.file)?.read_to_end(&mut pkcs12_bytes)?;

    let pkcs12 = Pkcs12::from_der(&pkcs12_bytes)?.parse2(&args.password)?;

    let cert = pkcs12
        .cert
        .ok_or_else(|| anyhow::anyhow!("no certs contained in pkcs12 structure"))?;
    let pkey = pkcs12
        .pkey
        .ok_or_else(|| anyhow::anyhow!("no key contained in pkcs12 structure"))?;

    let basic_cert_info = basic_cert_info(&cert)?;
    let valid_from = unix_timestamp(cert.not_before())?;
    let expires = unix_timestamp(cert.not_after())?;

    let mut cert_tempfile = tempfile::Builder::new().tempfile()?;
    let mut key_tempfile = tempfile::Builder::new().tempfile()?;

    // these will auto delete on drop
    cert_tempfile.write_all(&cert.to_pem()?)?;
    cert_tempfile.flush()?;
    key_tempfile.write_all(&pkey.private_key_to_pem_pkcs8()?)?;
    key_tempfile.flush()?;

    let mut op_command = Command::new("op");
    op_command
        .arg("item")
        .arg("create")
        .arg("--vault")
        .arg(args.vault)
        .arg("--category")
        .arg("API Credential")
        .arg("--title")
        .arg(args.title);
    if args.dry_run {
        op_command.arg("--dry-run");
    }
    op_command
        .arg(format!(
            "{cert_filename}[file]={}",
            cert_tempfile.path().display()
        ))
        .arg(format!(
            "{key_filename}[file]={}",
            key_tempfile.path().display()
        ))
        .arg(format!("validFrom[date]={}", valid_from))
        .arg(format!("expires[date]={}", expires))
        .arg(format!("notesPlain[text]={}", basic_cert_info));

    if args.verbose {
        let arglist = op_command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("calling `op {arglist}`");
    }
    let status = op_command.status()?;

    process::exit(status.code().unwrap_or(-1));
}

fn basic_cert_info(cert: &X509) -> anyhow::Result<String> {
    let mut ret = String::new();
    writeln!(&mut ret, "Subject:")?;
    for name_entry in cert.subject_name().entries() {
        writeln!(
            &mut ret,
            "{}: {}",
            name_entry.object().nid().long_name()?,
            name_entry.data().as_utf8()?
        )?;
    }
    writeln!(&mut ret)?;
    writeln!(&mut ret, "Issuer:")?;
    for name_entry in cert.issuer_name().entries() {
        writeln!(
            &mut ret,
            "{}: {}",
            name_entry.object().nid().long_name()?,
            name_entry.data().as_utf8()?
        )?;
    }
    Ok(ret)
}

fn unix_timestamp(asn1_time: &Asn1TimeRef) -> anyhow::Result<i64> {
    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.diff(asn1_time)?;

    let timestamp = NaiveDateTime::UNIX_EPOCH
        + Duration::days(diff.days as i64)
        + Duration::seconds(diff.secs as i64);
    Ok(timestamp.timestamp())
}
