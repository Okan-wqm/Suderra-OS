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

    // --- NV ordinal (RT-6 anti-rollback epoch tutucu) ------------------------
    //
    // TASARIM (ADR-0009, kod incelemesi düzeltmesi): `nt=counter` KULLANILMAZ.
    // Bir TPM counter index'i (a) ilk `NV_Increment`'e kadar `NV_Read`'de
    // UNINITIALIZED verir (0 okunmaz → taze cihazda floor_sync patlar, prod OTA
    // kilitlenir) ve (b) ilk increment değeri TPM-global bir yüksek-su-işaretine
    // ayarlanır (küçük değil) → küçük `rollback_epoch` ordinaliyle karşılaştırma
    // temelden yanlıştır. Bunun yerine 8-byte ORDINARY NV index kullanılır: epoch
    // ordinal'ini DOĞRUDAN tutarız (biz yazarız → mutlak-değer sorunu yok;
    // tanımda 0 yazarız → UNINITIALIZED sorunu yok).
    //
    // Tehdit modeli: ordinary NV, /data silinerek floor sıfırlama saldırısını
    // engeller (NV, /data'dan ayrı; factory-reset'e dayanır). Online-root'un NV'yi
    // yeniden yazması KAPSAM DIŞI (zaten game-over). Donanım-monotonic anti-rewrite
    // (online-root'a karşı) bir G5/Wave-7 sertleştirme kalemidir.

    /// Ordinary NV index'ini idempotent tanımlar ve tanımda 0'a başlatır (fresh
    /// index UNINITIALIZED yerine okunabilir olsun). Zaten tanımlıysa no-op.
    pub fn nv_define_ordinal(&self, index: u32) -> Result<()> {
        if self
            .run("tpm2_nvreadpublic", &[&format!("{index:#x}")])
            .is_ok()
        {
            return Ok(()); // zaten tanımlı → mevcut değeri koru
        }
        self.run(
            "tpm2_nvdefine",
            &[
                &format!("{index:#x}"),
                "-C",
                "o",
                "-s",
                "8",
                "-a",
                "ownerread|ownerwrite|authread|authwrite",
            ],
        )?;
        // Tanımdan hemen sonra 0 yaz → sonraki okumalar UNINITIALIZED vermez.
        self.nv_write_ordinal(index, 0)
    }

    /// Ordinary NV index'ine 8-byte big-endian değeri yazar (`tpm2_nvwrite`).
    pub fn nv_write_ordinal(&self, index: u32, value: u64) -> Result<()> {
        let tmp = std::env::temp_dir().join(format!("suderra-nv-{index:x}-{value}.bin"));
        std::fs::write(&tmp, value.to_be_bytes())
            .with_context(|| format!("NV yazma girdisi oluşturulamadı: {}", tmp.display()))?;
        let res = self.run(
            "tpm2_nvwrite",
            &[&format!("{index:#x}"), "-C", "o", "-i", &path_str(&tmp)?],
        );
        let _ = std::fs::remove_file(&tmp);
        res.map(|_| ())
    }

    /// Ordinary NV index'inin değerini okur (8-byte big-endian).
    ///
    /// `-s 8 -o -` TAM 8 ham bayt üretmelidir. Uzunluk 8 değilse (bir tpm2-tools
    /// sürümü fazladan newline/diagnostic eklerse) son-8-baytı almak sessizce
    /// YANLIŞ değer verirdi ve bu downgrade kararını sürerdi → fail-closed.
    pub fn nv_read_ordinal(&self, index: u32) -> Result<u64> {
        let raw = self.run(
            "tpm2_nvread",
            &[&format!("{index:#x}"), "-s", "8", "-o", "-"],
        )?;
        if raw.len() != 8 {
            bail!(
                "NV ordinal {index:#x} beklenen 8 bayt yerine {} bayt döndü (fail-closed)",
                raw.len()
            );
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&raw);
        Ok(u64::from_be_bytes(buf))
    }

    /// Ordinal'i `target`'a YÜKSELTİR (yalnız artırır; düşürme yok). Tek yazma —
    /// counter increment döngüsü YOK. ota + firstboot ortak kullanır.
    pub fn nv_raise_ordinal(&self, index: u32, target: u64) -> Result<()> {
        let current = self.nv_read_ordinal(index)?;
        if target > current {
            self.nv_write_ordinal(index, target)?;
        }
        Ok(())
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

    /// DURUMLU sahte tpm2 NV: değeri `<dir>/nvstate` dosyasında tutar; nvdefine
    /// yalnız yoksa oluşturur (define+0 semantiği), nvwrite `-i <infile>`'dan 8
    /// baytı state'e kopyalar, nvread state'i (yoksa "tanımsız" → exit 1) döker,
    /// nvreadpublic state varsa 0. Böylece define→read=0, write→read, raise
    /// senaryoları GERÇEK NV davranışını modelleyerek sınanır.
    fn install_stateful_nv(dir: &Path) {
        let state = dir.join("nvstate");
        let s = state.to_str().unwrap();
        fake_tool(dir, "tpm2_nvreadpublic", &format!("test -f {s}"));
        // nvdefine: state yoksa oluştur (henüz 0 yazılmadı — nvwrite 0 yapacak).
        fake_tool(dir, "tpm2_nvdefine", &format!(": > {s}.defined"));
        // nvwrite: `-i <infile>` argümanı; son argüman infile. 8 baytı state'e yaz.
        fake_tool(
            dir,
            "tpm2_nvwrite",
            &format!("infile=\"\"; while [ $# -gt 0 ]; do [ \"$1\" = \"-i\" ] && {{ shift; infile=$1; }}; shift; done; cp \"$infile\" {s}"),
        );
        // nvread: state (8 bayt) yoksa fail-closed (tanımsız NV gibi).
        fake_tool(
            dir,
            "tpm2_nvread",
            &format!("[ -s {s} ] && cat {s} || {{ echo uninit >&2; exit 1; }}"),
        );
    }

    #[test]
    fn ordinal_define_then_read_is_zero_then_write_read_roundtrips() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        install_stateful_nv(dir.path());
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(false);
        // define → 0'a başlatır (UNINITIALIZED YOK — taze donanım bug'ının regresyonu).
        tpm.nv_define_ordinal(0x0150_0001).unwrap();
        assert_eq!(tpm.nv_read_ordinal(0x0150_0001).unwrap(), 0);
        // write → read roundtrip.
        tpm.nv_write_ordinal(0x0150_0001, 7).unwrap();
        assert_eq!(tpm.nv_read_ordinal(0x0150_0001).unwrap(), 7);
        // raise yalnız artırır: 3 (< 7) no-op, 9 (> 7) yükseltir.
        tpm.nv_raise_ordinal(0x0150_0001, 3).unwrap();
        assert_eq!(tpm.nv_read_ordinal(0x0150_0001).unwrap(), 7);
        tpm.nv_raise_ordinal(0x0150_0001, 9).unwrap();
        assert_eq!(tpm.nv_read_ordinal(0x0150_0001).unwrap(), 9);
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }

    #[test]
    fn nv_read_ordinal_rejects_non_8_byte_output_fail_closed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // 8 bayt + fazladan newline → fail-closed (son-8-bayt sessizce alınmaz).
        fake_tool(
            dir.path(),
            "tpm2_nvread",
            "printf '\\000\\000\\000\\000\\000\\000\\000\\005\\n'",
        );
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(false);
        let err = tpm.nv_read_ordinal(0x0150_0001).unwrap_err();
        assert!(err.to_string().contains("8 bayt"), "{err}");
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }

    #[test]
    fn define_ordinal_is_idempotent_when_already_present() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // nvreadpublic başarılı → zaten var → nvdefine/nvwrite(0) ÇAĞRILMAMALI.
        fake_tool(dir.path(), "tpm2_nvreadpublic", "exit 0");
        fake_tool(
            dir.path(),
            "tpm2_nvdefine",
            "echo should-not-run >&2; exit 1",
        );
        fake_tool(
            dir.path(),
            "tpm2_nvwrite",
            "echo should-not-run >&2; exit 1",
        );
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(false);
        assert!(tpm.nv_define_ordinal(0x0150_0001).is_ok());
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }

    #[test]
    fn run_propagates_nonzero_exit_fail_closed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        fake_tool(dir.path(), "tpm2_nvread", "echo boom >&2; exit 3");
        std::env::set_var("SUDERRA_TPM2_BIN_DIR", dir.path());
        let tpm = Tpm::new(false);
        let err = tpm.nv_read_ordinal(0x0150_0001).unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
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
        assert!(tpm.nv_read_ordinal(0x0150_0001).is_err());
        std::env::remove_var("SUDERRA_TPM2_BIN_DIR");
    }
}
