// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 subprocess sarmalayıcısı — `tpm2-tools` üzerinden (ADR-0009).
//!
//! Repo emsali: `suderra-ota` rauc CLI'ye, `suderra-installer` cosign CLI'ye,
//! `suderra-data-provision` systemd-cryptenroll'e shell-out eder — hepsi
//! fail-closed exit-code kontrolüyle. TPM için de aynı desen: `tpm2-tools`
//! zaten her prod imajda (tüketicisiz duruyordu) — bu modül onu tüketir.
//! `tss-esapi` FFI'ya karşı gerekçe ADR-0009'da: musl cross-compile'da
//! bindgen/C-header yükü yok, ikinci bir TSS kopyası denetlenmez, tedarik
//! zinciri büyümez.
//!
//! Yalnız MAKİNE-OKUR çıktılar kullanılır: NV sayaç ham baytları (`tpm2_nvread`),
//! quote/PCR çıktıları `-o` ile dosyaya — serbest metin stdout parse YOK.
//!
//! ## Mock seam (test)
//! Binary çözümü, `suderra-ota`/`installer`'daki `dev_override` desenini izler:
//! prod'da (`caller is_production`) sabit `/usr/bin/tpm2_*`; aksi halde
//! `SUDERRA_TPM2_BIN_DIR` (varsa) veya PATH. Böylece unit testler tempdir'e
//! sahte `tpm2_*` scriptleri koyup PATH/-DIR'e işaret eder — trait makinesi yok.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// TPM 2.0 cihazının varlığı (RevPi SLB9670 / x86 fTPM / swtpm).
pub fn have_tpm() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

/// `tpm2-tools` alt-aracına (`tpm2_nvread`, `tpm2_quote`, ...) shell-out eden
/// bağlam. `production` true iken binary yolu sabittir (env ile kaydırılamaz —
/// prod'da güvenlik davranışı env ile gevşetilemez, #84 dev_override sözleşmesi).
pub struct Tpm {
    production: bool,
}

impl Tpm {
    /// `production`: çağıran crate'in `is_production()` sonucu geçilir (kök
    /// `suderra_config::variant::os_release_is_prod` + crate-özel env politikası).
    pub fn new(production: bool) -> Self {
        Self { production }
    }

    /// Alt-aracın çalıştırılabilir yolunu çözer.
    fn resolve(&self, tool: &str) -> Result<PathBuf> {
        if self.production {
            // Prod: sabit sistem yolu. tpm2-tools prod imajda /usr/bin altında.
            let p = PathBuf::from("/usr/bin").join(tool);
            if p.exists() {
                return Ok(p);
            }
            bail!("tpm2 tool bulunamadı (prod, sabit yol): {}", p.display());
        }
        // Non-prod: önce açık dizin (mock için), sonra PATH.
        if let Ok(dir) = std::env::var("SUDERRA_TPM2_BIN_DIR") {
            let p = PathBuf::from(dir).join(tool);
            if p.exists() {
                return Ok(p);
            }
        }
        which(tool)
    }

    /// Alt-aracı verilen argümanlarla çalıştırır; başarısız exit fail-closed hata.
    /// stdout ham bayt olarak döner (makine-okur çıktılar için).
    pub fn run(&self, tool: &str, args: &[&str]) -> Result<Vec<u8>> {
        let bin = self.resolve(tool)?;
        let output = Command::new(&bin)
            .args(args)
            .output()
            .with_context(|| format!("{} çalıştırılamadı", bin.display()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "{} {:?} başarısız (exit {:?}): {}",
                tool,
                args,
                output.status.code(),
                stderr.trim()
            );
        }
        Ok(output.stdout)
    }

    // --- NV monotonic counter (RT-6 anti-rollback donanım çıpası) ------------

    /// NV counter index'ini tanımlar (idempotent: zaten tanımlıysa no-op).
    /// `nt=counter` → yalnız artar; owner auth ile bile geri sarılamaz.
    pub fn nv_define_counter(&self, index: u32) -> Result<()> {
        // Zaten tanımlıysa nvreadpublic başarılı olur → tekrar tanımlama.
        if self
            .run("tpm2_nvreadpublic", &[&format!("{index:#x}")])
            .is_ok()
        {
            return Ok(());
        }
        self.run(
            "tpm2_nvdefine",
            &[
                &format!("{index:#x}"),
                "-C",
                "o",
                "-a",
                "nt=counter|ownerread|authread|authwrite|policywrite",
            ],
        )
        .map(|_| ())
    }

    /// NV counter'ı bir artırır (mark-good başarısında; başarısız güncelleme
    /// sayacı yakmaz — çağıran sıralar).
    pub fn nv_increment(&self, index: u32) -> Result<()> {
        self.run("tpm2_nvincrement", &[&format!("{index:#x}")])
            .map(|_| ())
    }

    /// NV counter'ın mevcut değerini okur (8-byte big-endian).
    pub fn nv_read_counter(&self, index: u32) -> Result<u64> {
        let raw = self.run(
            "tpm2_nvread",
            &[&format!("{index:#x}"), "-s", "8", "-o", "-"],
        )?;
        // `-o -` stdout'a ham bayt yazar. tpm2_nvread bazı sürümlerde stdout'a
        // doğrudan yazar; 8 baytı bekleriz.
        if raw.len() < 8 {
            bail!(
                "NV counter {index:#x} 8 bayttan kısa döndü ({} bayt)",
                raw.len()
            );
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&raw[raw.len() - 8..]);
        Ok(u64::from_be_bytes(buf))
    }

    // --- PCR / quote (RT-2 attestation) --------------------------------------

    /// PCR 0-7 (sha256) değerlerini bir dosyaya yazar (`tpm2_pcrread -o`).
    pub fn pcr_read_to(&self, out: &Path) -> Result<()> {
        self.run(
            "tpm2_pcrread",
            &["sha256:0,1,2,3,4,5,6,7", "-o", &path_str(out)?],
        )
        .map(|_| ())
    }

    // --- Genel imza/anahtar (RT-3 kimlik) ------------------------------------

    /// Persistent handle'ın public kısmını PEM olarak bir dosyaya yazar.
    pub fn readpublic_pem(&self, handle: u32, out: &Path) -> Result<()> {
        self.run(
            "tpm2_readpublic",
            &[
                "-c",
                &format!("{handle:#x}"),
                "-f",
                "pem",
                "-o",
                &path_str(out)?,
            ],
        )
        .map(|_| ())
    }
}

fn path_str(p: &Path) -> Result<String> {
    p.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("path UTF-8 değil: {}", p.display()))
}

/// Mini PATH lookup — `verify.rs`'teki desenle aynı (harici `which` dep'inden
/// kaçınma), böylece bağımlılık yüzeyi büyümez.
fn which(binary: &str) -> Result<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(dir).join(binary);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("'{binary}' PATH'te bulunamadı")
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    // SUDERRA_TPM2_BIN_DIR process-global; env'e dokunan testleri serileştir.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Bir tempdir'e verilen isimde çalıştırılabilir sahte tpm2 scripti kurar.
    fn fake_tool(dir: &Path, name: &str, body: &str) {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh\n{body}").unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }

    #[test]
    fn nv_read_counter_parses_big_endian_8_bytes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // 0x0000000000000005 (big-endian) yaz.
        fake_tool(
            dir.path(),
            "tpm2_nvread",
            "printf '\\000\\000\\000\\000\\000\\000\\000\\005'",
        );
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(false);
        assert_eq!(tpm.nv_read_counter(0x0150_0001).unwrap(), 5);
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }

    #[test]
    fn run_propagates_nonzero_exit_fail_closed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        fake_tool(dir.path(), "tpm2_nvincrement", "echo boom >&2; exit 3");
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(false);
        let err = tpm.nv_increment(0x0150_0001).unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }

    #[test]
    fn define_counter_is_idempotent_when_already_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // nvreadpublic başarılı → zaten var → nvdefine ÇAĞRILMAMALI.
        fake_tool(dir.path(), "tpm2_nvreadpublic", "exit 0");
        fake_tool(
            dir.path(),
            "tpm2_nvdefine",
            "echo should-not-run >&2; exit 1",
        );
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(false);
        assert!(tpm.nv_define_counter(0x0150_0001).is_ok());
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }

    #[test]
    fn prod_uses_fixed_path_not_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Prod'da SUDERRA_TPM2_BIN_DIR yok sayılır (env ile kaydırılamaz).
        let dir = tempfile::tempdir().unwrap();
        fake_tool(dir.path(), "tpm2_nvread", "printf 'x'");
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(true);
        // /usr/bin/tpm2_nvread test host'unda yok → çözüm başarısız (env'e düşmez).
        assert!(tpm.nv_read_counter(0x0150_0001).is_err());
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }
}
