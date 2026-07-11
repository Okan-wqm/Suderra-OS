// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-attestation` — TPM 2.0 PCR remote attestation istemcisi (RT-2, ADR-0009).
//!
//! Cihaz boot state'inin (UEFI → bootloader → kernel → initrd → rootfs) kriptografik
//! kanıtını üretir: PCR 0-7 üzerinden AK ile imzalı `tpm2_quote`. `tpm2-tools`'a
//! shell-out eder (`suderra_config::tpm`) — repo emsali; `tss-esapi` FFI gerekçesi
//! ADR-0009'da.
//!
//! Alt komutlar (hepsi senkron; tokio YOK):
//! - `setup`     : EK+AK üret, AK'yı persistent handle'a kaydet, AK pub'ı sakla.
//! - `baseline`  : PCR 0-7 oku → `baseline.json` (known-good referans).
//! - `quote --nonce <hex>` : AK ile imzalı quote evidence artifact'i üret (stdout/-o).
//! - `verify-local` : quote'u AK pub ile doğrula + baseline karşılaştır (fail-closed).
//!
//! DOĞRULAYICI SUNUCU KAPSAM DIŞI: repoda merkezi doğrulayıcı yok; bu istemci
//! imzalı evidence artifact'i (`suderra.attestation-evidence.v1`) üretir ve yerel
//! self-check yapar. Uzak doğrulayıcının kontrol etmesi gerekenler ADR-0009'da
//! sözleşme olarak belgelenir — sunucu İCAT EDİLMEZ.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use suderra_config::tpm::{have_tpm, Tpm};
use tracing::info;

const AK_HANDLE: u32 = 0x8101_0001;
const STATE_DIR: &str = "/data/suderra/attestation";
const BASELINE_SCHEMA: &str = "suderra.attestation-baseline.v1";
const EVIDENCE_SCHEMA: &str = "suderra.attestation-evidence.v1";

#[derive(Parser, Debug)]
#[command(
    name = "suderra-attestation",
    version,
    about = "TPM 2.0 PCR attestation client"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Prod modunu zorla (CI/dev'de gerçek prod davranışını sınamak için).
    #[arg(long, env = "SUDERRA_ATTESTATION_PRODUCTION", global = true)]
    production: bool,
    /// Durum/çıktı dizini (varsayılan /data/suderra/attestation).
    #[arg(long, env = "SUDERRA_ATTESTATION_DIR", global = true)]
    dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// EK+AK üret ve AK'yı persistent handle'a kaydet (idempotent).
    Setup,
    /// PCR 0-7 baseline'ını (known-good) yaz.
    Baseline,
    /// AK ile imzalı quote evidence üret.
    Quote(QuoteArgs),
    /// Quote'u AK pub ile doğrula + baseline karşılaştır.
    VerifyLocal(VerifyArgs),
}

#[derive(Args, Debug)]
struct QuoteArgs {
    /// Freshness nonce (hex). Doğrulayıcı replay'i önlemek için verir.
    #[arg(long)]
    nonce: String,
    /// Evidence çıktı yolu (yoksa stdout).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Doğrulanacak evidence artifact yolu.
    evidence: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Baseline {
    schema: String,
    pcrs_sha256_hex: String,
    created_at_source: String,
}

#[derive(Serialize, Deserialize)]
struct Evidence {
    schema: String,
    nonce: String,
    quote_msg_b64: String,
    quote_sig_b64: String,
    pcrs_sha256_hex: String,
    ak_pub_pem: String,
}

struct Ctx {
    tpm: Tpm,
    dir: PathBuf,
}

impl Ctx {
    fn ak_pub_path(&self) -> PathBuf {
        self.dir.join("ak.pub.pem")
    }
    fn baseline_path(&self) -> PathBuf {
        self.dir.join("baseline.json")
    }
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let cli = Cli::parse();
    let production = cli.production || suderra_config::variant::os_release_is_prod();
    let dir = cli.dir.clone().unwrap_or_else(|| PathBuf::from(STATE_DIR));
    let ctx = Ctx {
        tpm: Tpm::new(production),
        dir,
    };
    let result = match cli.command {
        Commands::Setup => setup(&ctx, production),
        Commands::Baseline => baseline(&ctx, production),
        Commands::Quote(args) => quote(&ctx, &args),
        Commands::VerifyLocal(args) => verify_local(&ctx, &args),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("suderra-attestation: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Prod'da TPM zorunlu (fail-closed); non-prod'da TPM yoksa temiz atla.
fn require_tpm(production: bool) -> Result<bool> {
    if have_tpm() {
        return Ok(true);
    }
    if production {
        bail!("prod cihazda TPM yok (/dev/tpm*): attestation fail-closed");
    }
    info!("TPM yok ve prod değil — attestation atlanıyor (no-op)");
    Ok(false)
}

fn setup(ctx: &Ctx, production: bool) -> Result<()> {
    if !require_tpm(production)? {
        return Ok(());
    }
    std::fs::create_dir_all(&ctx.dir)?;
    // AK zaten persistent ise idempotent: pub'ı tazele, yeniden üretme.
    if ctx
        .tpm
        .readpublic_pem(AK_HANDLE, &ctx.ak_pub_path())
        .is_ok()
    {
        info!("AK zaten mevcut (handle {AK_HANDLE:#x}); pub tazelendi");
        return Ok(());
    }
    let ek_ctx = ctx.dir.join("ek.ctx");
    let ak_ctx = ctx.dir.join("ak.ctx");
    ctx.tpm
        .run("tpm2_createek", &["-c", pstr(&ek_ctx)?, "-G", "rsa"])?;
    ctx.tpm.run(
        "tpm2_createak",
        &[
            "-C",
            pstr(&ek_ctx)?,
            "-c",
            pstr(&ak_ctx)?,
            "-G",
            "rsa",
            "-g",
            "sha256",
            "-s",
            "rsassa",
        ],
    )?;
    ctx.tpm.run(
        "tpm2_evictcontrol",
        &["-C", "o", "-c", pstr(&ak_ctx)?, &format!("{AK_HANDLE:#x}")],
    )?;
    ctx.tpm.readpublic_pem(AK_HANDLE, &ctx.ak_pub_path())?;
    info!(handle = AK_HANDLE, "AK üretildi ve kalıcı kaydedildi");
    Ok(())
}

fn baseline(ctx: &Ctx, production: bool) -> Result<()> {
    if !require_tpm(production)? {
        return Ok(());
    }
    std::fs::create_dir_all(&ctx.dir)?;
    let pcr_file = ctx.dir.join("pcrs.bin");
    ctx.tpm.pcr_read_to(&pcr_file)?;
    let digest = sha256_hex_of(&pcr_file)?;
    let baseline = Baseline {
        schema: BASELINE_SCHEMA.to_string(),
        pcrs_sha256_hex: digest,
        created_at_source: "tpm2_pcrread sha256:0-7".to_string(),
    };
    std::fs::write(ctx.baseline_path(), serde_json::to_vec_pretty(&baseline)?)?;
    info!(
        "PCR 0-7 baseline yazıldı: {}",
        ctx.baseline_path().display()
    );
    Ok(())
}

fn quote(ctx: &Ctx, args: &QuoteArgs) -> Result<()> {
    if !have_tpm() {
        bail!("quote için TPM gerekli (/dev/tpm*)");
    }
    if args.nonce.is_empty() || !args.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("nonce hex olmalı");
    }
    let tmp = tempdir_in(&ctx.dir)?;
    let msg = tmp.join("quote.msg");
    let sig = tmp.join("quote.sig");
    let pcr = tmp.join("quote.pcr");
    ctx.tpm.run(
        "tpm2_quote",
        &[
            "-c",
            &format!("{AK_HANDLE:#x}"),
            "-l",
            "sha256:0,1,2,3,4,5,6,7",
            "-q",
            &args.nonce,
            "-m",
            pstr(&msg)?,
            "-s",
            pstr(&sig)?,
            "-o",
            pstr(&pcr)?,
        ],
    )?;
    let evidence = Evidence {
        schema: EVIDENCE_SCHEMA.to_string(),
        nonce: args.nonce.clone(),
        quote_msg_b64: b64(&std::fs::read(&msg)?),
        quote_sig_b64: b64(&std::fs::read(&sig)?),
        pcrs_sha256_hex: sha256_hex_of(&pcr)?,
        ak_pub_pem: std::fs::read_to_string(ctx.ak_pub_path())
            .context("AK pub okunamadı — önce `setup` çalıştırın")?,
    };
    let json = serde_json::to_vec_pretty(&evidence)?;
    match &args.out {
        Some(path) => std::fs::write(path, &json)?,
        None => {
            use std::io::Write as _;
            std::io::stdout().write_all(&json)?;
        }
    }
    Ok(())
}

fn verify_local(ctx: &Ctx, args: &VerifyArgs) -> Result<()> {
    let evidence: Evidence = serde_json::from_slice(&std::fs::read(&args.evidence)?)
        .context("evidence JSON parse edilemedi")?;
    if evidence.schema != EVIDENCE_SCHEMA {
        bail!("beklenmeyen evidence şeması: {}", evidence.schema);
    }
    let tmp = tempdir_in(&ctx.dir)?;
    let ak = tmp.join("ak.pub.pem");
    let msg = tmp.join("q.msg");
    let sig = tmp.join("q.sig");
    std::fs::write(&ak, evidence.ak_pub_pem.as_bytes())?;
    std::fs::write(&msg, unb64(&evidence.quote_msg_b64)?)?;
    std::fs::write(&sig, unb64(&evidence.quote_sig_b64)?)?;
    ctx.tpm.run(
        "tpm2_checkquote",
        &[
            "-u",
            pstr(&ak)?,
            "-m",
            pstr(&msg)?,
            "-s",
            pstr(&sig)?,
            "-q",
            &evidence.nonce,
        ],
    )?;
    if ctx.baseline_path().exists() {
        let baseline: Baseline = serde_json::from_slice(&std::fs::read(ctx.baseline_path())?)?;
        if baseline.pcrs_sha256_hex != evidence.pcrs_sha256_hex {
            bail!(
                "PCR baseline uyuşmazlığı (cihaz kurcalanmış olabilir): beklenen {}, gelen {}",
                baseline.pcrs_sha256_hex,
                evidence.pcrs_sha256_hex
            );
        }
    }
    info!("attestation evidence yerel doğrulaması GEÇTİ");
    Ok(())
}

// --- yardımcılar -----------------------------------------------------------

fn pstr(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| anyhow::anyhow!("path UTF-8 değil: {}", p.display()))
}

fn sha256_hex_of(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    Ok(hex_encode(&Sha256::digest(&bytes)))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

/// Basit, çakışmasız geçici alt-dizin (harici tempfile'a bağımlı kalmadan;
/// çağıran süreç kısa ömürlü — quote/verify tek atış).
fn tempdir_in(base: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(base)?;
    let dir = base.join(format!(".tmp-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_roundtrips_json() {
        let ev = Evidence {
            schema: EVIDENCE_SCHEMA.to_string(),
            nonce: "abcd".to_string(),
            quote_msg_b64: b64(b"msg"),
            quote_sig_b64: b64(b"sig"),
            pcrs_sha256_hex: "00".repeat(32),
            ak_pub_pem: "-----BEGIN PUBLIC KEY-----\n".to_string(),
        };
        let json = serde_json::to_vec(&ev).unwrap();
        let back: Evidence = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.schema, EVIDENCE_SCHEMA);
        assert_eq!(unb64(&back.quote_msg_b64).unwrap(), b"msg");
    }

    #[test]
    fn hex_encode_matches_known_vector() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x10]), "00ff10");
    }
}
