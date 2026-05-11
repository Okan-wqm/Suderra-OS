// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-attestation` — TPM 2.0 PCR remote attestation.
//!
//! Cihaz boot state'inin (UEFI → bootloader → kernel → initrd → rootfs)
//! kriptografik kanıtını cloud'a sunar. Cloud bu kanıtı doğrulayarak
//! cihazın hangi yazılım sürümünü çalıştırdığını **manipülasyon dışı**
//! öğrenir.
//!
//! Akış:
//! 1. tpm2_pcrread → PCR 0-7 hash'lerini oku
//! 2. tpm2_quote → AIK ile imzalı quote oluştur
//! 3. Cloud'a gönder (mTLS + AIK certificate chain)
//! 4. Cloud: known-good PCR set ile karşılaştır
//! 5. Mismatch → device flagged (telemetry alert)
//!
//! Faz 8+ (SL3 ya da yüksek-güven müşteri için).
//!
//! NOT: SL2 hedefi için zorunlu değil, ama mimari hazır olsun diye eklendi.

use anyhow::Result;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!(
        "suderra-attestation v{} başlatılıyor",
        env!("CARGO_PKG_VERSION")
    );

    // TODO Faz 8+:
    // - tss-esapi crate ile TPM2 erişim
    // - PCR read (sealed in kernel measure boot)
    // - Quote oluştur (AIK private key)
    // - mTLS + cosign ile cloud'a gönder

    warn!("suderra-attestation Faz 8+ scope, şu an placeholder");
    Ok(())
}
