// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Facts of the signed OS image (ADR-048 DEC-8.2, DEC-19, DEC-23).
//!
//! The production/dev variant, the OS version and agent ABI range, the
//! declared features, the board and the kernel config list all come from
//! files on the verity rootfs (`/etc/os-release`, `/etc/suderra/features`,
//! `/etc/suderra/board`, `/etc/suderra/kernel-config`), never from the
//! environment: an env var or unit drop-in can change at run time, the verity
//! image cannot. A variant that is not exactly `dev`, or an unreadable
//! os-release, is production (fail-safe).
//!
//! Every image carries the OS facts ([`OsFacts`]); only an image that
//! boards.json maps to a board_profile carries `/etc/suderra/board`, and only
//! such an image runs the edge chain ([`ImageFacts`] requires the board, so no
//! edge, lifecycle or result path can run on a boardless image).

use crate::contracts::encoding::{
    is_kernel_symbol, is_os_version, parse_abi_range, parse_version_core,
};
use crate::contracts::registry::{Arch, BoardProfile};
use crate::contracts::verify::OsCompat;
use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Image variant (os-release `VARIANT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    /// `VARIANT=dev`: dev/CI keys, dev lifecycle entry rule (DEC-12).
    Dev,
    /// Everything else.
    Production,
}

/// Parses os-release(5) syntax: `KEY=value` lines, values optionally in one
/// pair of matching quotes, `#` comments and blank lines ignored.
pub(crate) fn parse_env_file(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw) = line
            .split_once('=')
            .with_context(|| format!("line {}: not KEY=value", number + 1))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            bail!("line {}: invalid key {key:?}", number + 1);
        }
        let value = match raw.as_bytes() {
            [q @ (b'"' | b'\''), inner @ .., last] if last == q => {
                std::str::from_utf8(inner).context("value is not UTF-8")?
            }
            _ => raw,
        };
        if out.insert(key.to_owned(), value.to_owned()).is_some() {
            bail!("line {}: duplicate key {key}", number + 1);
        }
    }
    Ok(out)
}

/// The variant from os-release text; anything but `dev` is production.
pub(crate) fn variant_of(os_release: &str) -> Variant {
    match parse_env_file(os_release) {
        Ok(map) if map.get("VARIANT").map(String::as_str) == Some("dev") => Variant::Dev,
        _ => Variant::Production,
    }
}

/// The image variant; an unreadable os-release is production.
#[cfg(any(test, feature = "package-commands"))]
pub(crate) fn variant(paths: &Paths) -> Variant {
    std::fs::read_to_string(paths.os_release())
        .map(|text| variant_of(&text))
        .unwrap_or(Variant::Production)
}

/// True on production images (legacy package path; DEC-19: never from env).
#[cfg(any(test, feature = "package-commands"))]
pub(crate) fn is_production() -> bool {
    Paths::system()
        .map(|p| variant(&p))
        .unwrap_or(Variant::Production)
        == Variant::Production
}

/// /etc/suderra/board: the board identity the image declares (DEC-8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoardFile {
    /// board_profile.
    pub board: BoardProfile,
    /// arch.
    pub arch: Arch,
}

/// Feature names /etc/suderra/features may declare.
pub(crate) const IMAGE_FEATURES: [&str; 5] = ["verity", "secure-boot", "rauc", "tpm", "luks"];

impl BoardFile {
    /// Parses `BOARD_PROFILE=`, `ARCH=` and optional `RAUC_COMPATIBLE=`; the
    /// values must agree with boards.json. Features are an image fact of
    /// every image and live in /etc/suderra/features only.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let map = parse_env_file(text)?;
        if map.contains_key("FEATURES") {
            bail!("FEATURES belongs in /etc/suderra/features, not the board file");
        }
        let board_text = map.get("BOARD_PROFILE").context("BOARD_PROFILE missing")?;
        let board = BoardProfile::parse(board_text)
            .with_context(|| format!("unknown board_profile {board_text:?}"))?;
        let arch_text = map.get("ARCH").context("ARCH missing")?;
        let arch = Arch::parse(arch_text).with_context(|| format!("unknown arch {arch_text:?}"))?;
        let spec = board.spec();
        if arch != spec.arch {
            bail!(
                "ARCH {arch} differs from boards.json arch {} of {board}",
                spec.arch
            );
        }
        if let Some(rauc) = map.get("RAUC_COMPATIBLE") {
            if rauc != spec.rauc_compatible {
                bail!(
                    "RAUC_COMPATIBLE {rauc} differs from boards.json {}",
                    spec.rauc_compatible
                );
            }
        }
        Ok(Self { board, arch })
    }

    /// The image's board, or `None` on an image that declares none (no
    /// /etc/suderra/board).
    pub(crate) fn load(paths: &Paths) -> Result<Option<Self>> {
        match std::fs::read_to_string(paths.board_file()) {
            Ok(text) => Self::parse(&text).context("/etc/suderra/board").map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => {
                Err(e).with_context(|| format!("cannot read {}", paths.board_file().display()))
            }
        }
    }
}

/// Parses /etc/suderra/features: one `FEATURES=` line (space separated
/// names from [`IMAGE_FEATURES`]), nothing else.
pub(crate) fn parse_features(text: &str) -> Result<BTreeSet<String>> {
    let map = parse_env_file(text)?;
    if map.keys().any(|k| k != "FEATURES") {
        bail!("/etc/suderra/features holds only FEATURES");
    }
    let mut features = BTreeSet::new();
    for feature in map
        .get("FEATURES")
        .context("FEATURES missing")?
        .split_whitespace()
    {
        if !IMAGE_FEATURES.contains(&feature) {
            bail!("unknown image feature {feature:?}");
        }
        features.insert(feature.to_owned());
    }
    Ok(features)
}

/// Parses /etc/suderra/kernel-config: one `CONFIG_<NAME>=y|m` line per
/// enabled symbol, nothing else.
pub(crate) fn parse_kernel_config(text: &str) -> Result<BTreeSet<String>> {
    let mut symbols = BTreeSet::new();
    for (number, line) in text.lines().enumerate() {
        let (symbol, value) = line
            .split_once('=')
            .with_context(|| format!("kernel-config line {}: not CONFIG_X=y|m", number + 1))?;
        if !is_kernel_symbol(symbol) || !matches!(value, "y" | "m") {
            bail!("kernel-config line {}: {line:?}", number + 1);
        }
        symbols.insert(symbol.to_owned());
    }
    Ok(symbols)
}

/// The facts every image carries, with or without a board.
#[derive(Debug, Clone)]
pub(crate) struct OsFacts {
    /// Production or dev.
    pub variant: Variant,
    /// VERSION_ID text.
    pub os_version: String,
    /// SUDERRA_AGENT_ABI text.
    pub agent_abi: String,
    /// Features the image declares (DEC-6.8): the health predicate fails on
    /// a declared feature that is absent and never probes undeclared ones.
    pub features: BTreeSet<String>,
    /// Compatibility facts for release verification.
    pub compat: OsCompat,
}

impl OsFacts {
    /// Reads the OS facts; any missing or malformed fact is an error.
    pub(crate) fn load(paths: &Paths) -> Result<Self> {
        let os_text = std::fs::read_to_string(paths.os_release())
            .with_context(|| format!("cannot read {}", paths.os_release().display()))?;
        let os = parse_env_file(&os_text).context("/etc/os-release")?;
        let version = os.get("VERSION_ID").context("VERSION_ID missing")?;
        if !is_os_version(version) {
            bail!("VERSION_ID {version:?} is not MAJOR.MINOR.PATCH");
        }
        let abi_text = os
            .get("SUDERRA_AGENT_ABI")
            .context("SUDERRA_AGENT_ABI missing")?;
        let abi = parse_abi_range(abi_text)
            .filter(|(min, max)| min <= max)
            .with_context(|| format!("SUDERRA_AGENT_ABI {abi_text:?} is not MIN-MAX"))?;
        let features_text = std::fs::read_to_string(paths.features_file())
            .with_context(|| format!("cannot read {}", paths.features_file().display()))?;
        let features = parse_features(&features_text).context("/etc/suderra/features")?;
        let kernel_text = std::fs::read_to_string(paths.kernel_config())
            .with_context(|| format!("cannot read {}", paths.kernel_config().display()))?;
        let kernel_config = parse_kernel_config(&kernel_text)?;
        let version_tuple = parse_version_core(version).context("VERSION_ID")?;
        Ok(Self {
            variant: variant_of(&os_text),
            os_version: version.clone(),
            agent_abi: abi_text.clone(),
            features,
            compat: OsCompat {
                version: version_tuple,
                abi,
                kernel_config,
            },
        })
    }
}

/// Every image fact the edge chain depends on: the OS facts and the board.
#[derive(Debug, Clone)]
pub(crate) struct ImageFacts {
    /// The OS facts.
    pub os: OsFacts,
    /// Board identity.
    pub board: BoardFile,
}

impl ImageFacts {
    /// Which keys this image may pin (DEC-3.9).
    pub(crate) fn pin_policy(&self) -> crate::trust_anchors::PinPolicy {
        crate::trust_anchors::PinPolicy::of(self.os.variant, self.board.board)
    }

    /// Reads the image facts; any missing or malformed fact is an error,
    /// and so is an image that declares no board (it runs no edge agent).
    pub(crate) fn load(paths: &Paths) -> Result<Self> {
        let os = OsFacts::load(paths)?;
        let board = BoardFile::load(paths)?.with_context(|| {
            format!(
                "{} is missing: this image declares no board_profile and runs no edge agent",
                paths.board_file().display()
            )
        })?;
        Ok(Self { os, board })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_comes_only_from_os_release_and_fails_safe() {
        assert_eq!(variant_of("VARIANT=dev\n"), Variant::Dev);
        assert_eq!(variant_of("VARIANT=\"dev\"\n"), Variant::Dev);
        for prod in [
            "VARIANT=prod",
            "VARIANT=lab",
            "",
            "garbage",
            "VARIANT=dev\nVARIANT=dev",
        ] {
            assert_eq!(variant_of(prod), Variant::Production, "{prod:?}");
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let paths = Paths::under(tmp.path());
        assert_eq!(
            variant(&paths),
            Variant::Production,
            "missing os-release is production"
        );
        std::fs::create_dir_all(tmp.path().join("etc")).unwrap();
        std::fs::write(tmp.path().join("etc/os-release"), "VARIANT=prod\n").unwrap();
        assert_eq!(variant(&paths), Variant::Production);
        std::fs::write(tmp.path().join("etc/os-release"), "VARIANT=dev\n").unwrap();
        assert_eq!(variant(&paths), Variant::Dev);
    }

    /// DEC-19: no production code path of the installer reads the
    /// environment. Only the dev-only package path (feature
    /// `package-commands`, never in an image build) may.
    #[test]
    fn production_sources_read_no_environment() {
        const PACKAGE_PATH: [&str; 6] = [
            "audit.rs",
            "download.rs",
            "manifest.rs",
            "sources.rs",
            "verify.rs",
            "cmd/install.rs",
        ];
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src.clone()];
        let mut offenders = Vec::new();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(&src)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if PACKAGE_PATH.contains(&rel.as_str()) || !rel.ends_with(".rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for needle in ["env::var(", "env::var_os(", "env::vars(", "#[arg(long, env"] {
                    // The needle list itself lives in this file.
                    if rel != "variant.rs" && text.contains(needle) {
                        offenders.push(format!("{rel}: {needle}"));
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "environment reads: {offenders:?}");
    }

    #[test]
    fn board_file_agrees_with_boards_json() {
        let ok = BoardFile::parse(
            "BOARD_PROFILE=revpi-connect4\nARCH=aarch64\nRAUC_COMPATIBLE=suderra-os-revpi-connect4\nDEVICE_BINDING_METHOD=tpm-ek-sha256\n",
        )
        .unwrap();
        assert_eq!(ok.board, BoardProfile::RevpiConnect4);
        for bad in [
            "BOARD_PROFILE=revpi4\nARCH=aarch64\n",
            "BOARD_PROFILE=revpi-connect4\nARCH=x86_64\n",
            "BOARD_PROFILE=revpi-connect4\nARCH=aarch64\nRAUC_COMPATIBLE=suderra-os-aarch64\n",
            "BOARD_PROFILE=revpi-connect4\nARCH=aarch64\nFEATURES=tpm\n",
            "ARCH=aarch64\n",
        ] {
            assert!(BoardFile::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn features_are_one_strict_declaration() {
        let got = parse_features("FEATURES=\"verity rauc tpm luks\"\n").unwrap();
        assert!(got.contains("tpm") && got.contains("verity"));
        assert!(parse_features("FEATURES=\"\"\n").unwrap().is_empty());
        for bad in ["", "FEATURES=wifi\n", "FEATURES=rauc\nBOARD_PROFILE=x\n"] {
            assert!(parse_features(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_boardless_image_has_os_facts_but_no_image_facts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = crate::test_support::image(tmp.path());
        std::fs::remove_file(paths.board_file()).unwrap();
        let os = OsFacts::load(&paths).unwrap();
        assert_eq!(os.variant, Variant::Dev);
        assert!(BoardFile::load(&paths).unwrap().is_none());
        assert!(ImageFacts::load(&paths).is_err());
    }

    #[test]
    fn kernel_config_lines_are_strict() {
        let set = parse_kernel_config("CONFIG_DM_CRYPT=y\nCONFIG_SPI_SPIDEV=m\n").unwrap();
        assert!(set.contains("CONFIG_SPI_SPIDEV"));
        assert!(parse_kernel_config("CONFIG_X=n\n").is_err());
        assert!(parse_kernel_config("# comment\n").is_err());
    }
}
