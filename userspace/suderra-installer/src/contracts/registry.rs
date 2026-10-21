// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! The closed vocabularies of the edge contract, compiled in.
//!
//! The release binary cannot read `contracts/suderra-edge/v1` at run time (it
//! is not on the device) or at build time (the cross build mounts only the
//! cargo workspace), so the parts of statements.json, boards.json,
//! artifact-naming.json and test-keys/keyring.json the root verifier needs are
//! mirrored here. `tests` compares every table with the vendored contract and
//! fails the build on any drift (tier 3, "make it detectable").

#[cfg(test)]
use super::statements::NetRole;
use serde::{Deserialize, Serialize};

macro_rules! string_enum {
    // `all`: production code iterates the vocabulary, so `ALL` is always
    // compiled; otherwise only the drift tests iterate it.
    (all $(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        string_enum!(@define $(#[$meta])* $name { $($variant => $text),+ });
        impl $name {
            /// Every value, in declaration order.
            pub(crate) const ALL: &'static [$name] = &[$($name::$variant),+];
        }
    };
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        string_enum!(@define $(#[$meta])* $name { $($variant => $text),+ });
        #[cfg(test)]
        impl $name {
            /// Every value, in declaration order.
            pub(crate) const ALL: &'static [$name] = &[$($name::$variant),+];
        }
    };
    (@define $(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) enum $name { $($variant),+ }

        impl $name {
            /// Contract spelling.
            pub(crate) fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }

            /// Parses the contract spelling.
            pub(crate) fn parse(text: &str) -> Option<Self> {
                match text { $($text => Some($name::$variant),)+ _ => None }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                $name::parse(&text).ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        concat!("unknown ", stringify!($name), " {:?}"),
                        text
                    ))
                })
            }
        }
    };
}

string_enum!(
    /// Rejection codes of signed statements and operational result codes
    /// (statements.json `rejection_reasons`, `operational_reasons`).
    Reason {
        EnvelopeInvalid => "envelope-invalid",
        PayloadTypeMismatch => "payload-type-mismatch",
        KeyUnknown => "key-unknown",
        KeyPurposeMismatch => "key-purpose-mismatch",
        KeyEpochBelowRatchet => "key-epoch-below-ratchet",
        SignatureInvalid => "signature-invalid",
        PayloadJsonInvalid => "payload-json-invalid",
        SchemaInvalid => "schema-invalid",
        KeyEpochMismatch => "key-epoch-mismatch",
        NotYetValid => "not-yet-valid",
        Expired => "expired",
        DeviceBindingMismatch => "device-binding-mismatch",
        DeviceIdMismatch => "device-id-mismatch",
        TenantMismatch => "tenant-mismatch",
        TenantScopeMismatch => "tenant-scope-mismatch",
        NonceMismatch => "nonce-mismatch",
        BoardMismatch => "board-mismatch",
        RollbackBelowFloor => "rollback-below-floor",
        SequenceReplay => "sequence-replay",
        ReleaseDigestMismatch => "release-digest-mismatch",
        ReleaseMismatch => "release-mismatch",
        ReleaseProfileMismatch => "release-profile-mismatch",
        OsVersionTooOld => "os-version-too-old",
        AgentAbiUnsupported => "agent-abi-unsupported",
        CompatibleMismatch => "compatible-mismatch",
        KernelConfigMissing => "kernel-config-missing",
        SiteConfigDigestMismatch => "site-config-digest-mismatch",
        TrustAnchorsDigestMismatch => "trust-anchors-digest-mismatch",
        ManifestDigestMismatch => "manifest-digest-mismatch",
        AnchorNotOsPinned => "anchor-not-os-pinned",
        AnchorInvalid => "anchor-invalid",
        SiteFileDigestMismatch => "site-file-digest-mismatch",
        RbacManifestDigestMismatch => "rbac-manifest-digest-mismatch",
        ActorKeyNotAnchored => "actor-key-not-anchored",
        InstalledDigestMismatch => "installed-digest-mismatch",
        InterfaceMappingInvalid => "interface-mapping-invalid",
        ClockUnsynced => "clock-unsynced",
        FetchFailed => "fetch-failed",
        ArtifactDigestMismatch => "artifact-digest-mismatch",
        BinaryDigestMismatch => "binary-digest-mismatch",
        ArchiveInvalid => "archive-invalid",
        IoError => "io-error",
        HealthWindowFailed => "health-window-failed",
        ReleaseNotInstalled => "release-not-installed",
        CurrentLinkMismatch => "current-link-mismatch",
        ReceiptMissing => "receipt-missing",
        FirewallLoadFailed => "firewall-load-failed",
        StateCorrupt => "state-corrupt",
        AgentNotActive => "agent-not-active",
        AgentDegraded => "agent-degraded",
        VerityInactive => "verity-inactive",
        DataMapperMissing => "data-mapper-missing",
        FirewallHashMismatch => "firewall-hash-mismatch",
        LifecycleInconsistent => "lifecycle-inconsistent",
        ClockBelowFloor => "clock-below-floor",
        TpmUnavailable => "tpm-unavailable",
        BspProbeFailed => "bsp-probe-failed",
        AbiIncompatible => "abi-incompatible",
        DataUnmountable => "data-unmountable",
        TpmUnsealFailed => "tpm-unseal-failed",
        MaintenanceBlocked => "maintenance-blocked",
        ApprovalMissing => "approval-missing",
        RaucInstallFailed => "rauc-install-failed",
        SiteBundleMissing => "site-bundle-missing",
        ConfigRscLoadFailed => "config-rsc-load-failed",
        RequestTooLarge => "request-too-large",
        RequestNotRegularFile => "request-not-regular-file",
        RequestUnsupported => "request-unsupported",
        UsbLayoutInvalid => "usb-layout-invalid",
        ProvisioningModeActive => "provisioning-mode-active",
    }
);

#[cfg(test)]
impl Reason {
    /// The first operational code; everything before it is a statement
    /// rejection code.
    const FIRST_OPERATIONAL: Reason = Reason::ClockUnsynced;

    /// True for statement rejection codes (statements.json `rejection_reasons`).
    pub(crate) fn is_statement_rejection(self) -> bool {
        self < Self::FIRST_OPERATIONAL
    }
}

/// statements.json `verification_order`: run in this order, first failure wins.
pub(crate) const VERIFICATION_ORDER: [Reason; 8] = [
    Reason::EnvelopeInvalid,
    Reason::PayloadTypeMismatch,
    Reason::KeyUnknown,
    Reason::KeyPurposeMismatch,
    Reason::KeyEpochBelowRatchet,
    Reason::SignatureInvalid,
    Reason::PayloadJsonInvalid,
    Reason::SchemaInvalid,
];

/// statements.json `reverification`: checks skipped and added on re-verification.
pub(crate) const REVERIFY_SKIPPED: [Reason; 4] = [
    Reason::NotYetValid,
    Reason::Expired,
    Reason::SequenceReplay,
    Reason::InterfaceMappingInvalid,
];
/// See [`REVERIFY_SKIPPED`].
pub(crate) const REVERIFY_ADDED: [Reason; 1] = [Reason::InstalledDigestMismatch];

string_enum!(
    all
    /// Signing purposes (statements.json `purposes`, DEC-3.3).
    Purpose {
        EdgeRelease => "edge-release",
        EdgeProvisioning => "edge-provisioning",
        FleetRoot => "fleet-root",
        DeviceLifecycle => "device-lifecycle",
        ConfigIntegrity => "config-integrity",
        RbacManifest => "rbac-manifest",
        Command => "command",
        MqttCa => "mqtt-ca",
    }
);

impl Purpose {
    /// Anchored by a key pinned in the OS image.
    pub(crate) fn anchored_in_os_image(self) -> bool {
        matches!(
            self,
            Purpose::EdgeRelease
                | Purpose::EdgeProvisioning
                | Purpose::FleetRoot
                | Purpose::DeviceLifecycle
        )
    }

    /// Anchored in the trust-anchors bundle.
    pub(crate) fn anchored_in_bundle(self) -> bool {
        !matches!(self, Purpose::FleetRoot | Purpose::DeviceLifecycle)
    }

    /// Anchored only in the bundle: resolved against a verified bundle.
    pub(crate) fn bundle_only(self) -> bool {
        self.anchored_in_bundle() && !self.anchored_in_os_image()
    }

    /// Algorithm (statements.json `purposes[].algorithm`).
    #[cfg(test)]
    pub(crate) fn algorithm(self) -> &'static str {
        if self == Purpose::MqttCa {
            "x509"
        } else {
            "ed25519"
        }
    }
}

string_enum!(
    all
    /// Signed statement types (statements.json `statements`).
    StatementType {
        EdgeRelease => "suderra.edge-release.v1",
        EdgeProvisioning => "suderra.edge-provisioning.v1",
        EdgeActivationReceipt => "suderra.edge-activation-receipt.v1",
        TrustAnchors => "suderra.trust-anchors.v1",
        DeviceLifecycle => "suderra.device-lifecycle.v1",
        SiteConfig => "suderra.site-config.v1",
        RbacManifest => "suderra.rbac-manifest.v1",
        EdgeUpdate => "suderra.edge-update.v1",
        OsUpdate => "suderra.os-update.v1",
        SiteNetpolicy => "suderra.site-netpolicy.v1",
    }
);

/// How an equal sequence value is treated (statements.json `sequences`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EqualSeq {
    /// Equal is replay.
    Reject,
    /// Equal is accepted only for the identical installed statement.
    IdenticalOnly,
}

/// Sequence rule of a statement type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SequenceRule {
    /// Payload member carrying the sequence.
    pub field: &'static str,
    /// Equal-value policy.
    pub equal: EqualSeq,
}

/// One row of statements.json `statements` as the OS root verifier uses it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StatementSpec {
    /// Key purpose that must sign the statement.
    pub signing_purpose: Purpose,
    /// device_binding and device_id are compared.
    pub device_bound: bool,
    /// tenant_id (or tenant_scope) is compared.
    pub tenant_bound: bool,
    /// Sequence rule, if any.
    pub sequence: Option<SequenceRule>,
    /// Statements delivered with and verified under this one.
    #[cfg(test)]
    pub nested: &'static [StatementType],
    /// Statement checks after schema validation.
    pub checks: &'static [Reason],
    /// Re-verified before every agent start (statements.json `reverification`).
    #[cfg(test)]
    pub reverified: bool,
}

impl StatementType {
    /// Short kind used in payload types and `/data/suderra/os/seq/<kind>`.
    pub(crate) fn kind(self) -> &'static str {
        let name = self.as_str();
        &name["suderra.".len()..name.len() - ".v1".len()]
    }

    /// DSSE payloadType this call site pins.
    pub(crate) fn payload_type(self) -> String {
        format!("application/vnd.suderra.{}.v1+json", self.kind())
    }

    /// `_type` member of the payload.
    pub(crate) fn type_member(self) -> &'static str {
        self.as_str()
    }

    /// The statements.json row of this type.
    pub(crate) fn spec(self) -> StatementSpec {
        use Reason as R;
        use StatementType as T;
        match self {
            T::EdgeRelease => StatementSpec {
                signing_purpose: Purpose::EdgeRelease,
                device_bound: false,
                tenant_bound: false,
                sequence: None,
                #[cfg(test)]
                nested: &[],
                checks: &[
                    R::ReleaseProfileMismatch,
                    R::BoardMismatch,
                    R::OsVersionTooOld,
                    R::AgentAbiUnsupported,
                    R::KernelConfigMissing,
                ],
                #[cfg(test)]
                reverified: true,
            },
            T::EdgeProvisioning => StatementSpec {
                signing_purpose: Purpose::EdgeProvisioning,
                device_bound: true,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "update_seq",
                    equal: EqualSeq::Reject,
                }),
                #[cfg(test)]
                nested: &[T::EdgeRelease, T::TrustAnchors, T::SiteConfig],
                checks: &[
                    R::KeyEpochMismatch,
                    R::NotYetValid,
                    R::Expired,
                    R::DeviceBindingMismatch,
                    R::DeviceIdMismatch,
                    R::TenantMismatch,
                    R::NonceMismatch,
                    R::BoardMismatch,
                    R::RollbackBelowFloor,
                    R::SequenceReplay,
                    R::ReleaseDigestMismatch,
                    R::ReleaseMismatch,
                    R::SiteConfigDigestMismatch,
                    R::TrustAnchorsDigestMismatch,
                ],
                #[cfg(test)]
                reverified: false,
            },
            T::EdgeActivationReceipt => StatementSpec {
                signing_purpose: Purpose::EdgeProvisioning,
                device_bound: true,
                tenant_bound: true,
                sequence: None,
                #[cfg(test)]
                nested: &[],
                checks: &[
                    R::NotYetValid,
                    R::Expired,
                    R::DeviceBindingMismatch,
                    R::DeviceIdMismatch,
                    R::TenantMismatch,
                    R::ManifestDigestMismatch,
                ],
                #[cfg(test)]
                reverified: false,
            },
            T::TrustAnchors => StatementSpec {
                signing_purpose: Purpose::FleetRoot,
                device_bound: false,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "bundle_seq",
                    equal: EqualSeq::IdenticalOnly,
                }),
                #[cfg(test)]
                nested: &[],
                checks: &[
                    R::TenantScopeMismatch,
                    R::SequenceReplay,
                    R::AnchorNotOsPinned,
                    R::AnchorInvalid,
                ],
                #[cfg(test)]
                reverified: true,
            },
            T::DeviceLifecycle => StatementSpec {
                signing_purpose: Purpose::DeviceLifecycle,
                device_bound: true,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "update_seq",
                    equal: EqualSeq::Reject,
                }),
                #[cfg(test)]
                nested: &[],
                checks: &[
                    R::NotYetValid,
                    R::Expired,
                    R::DeviceBindingMismatch,
                    R::DeviceIdMismatch,
                    R::TenantMismatch,
                    R::SequenceReplay,
                ],
                #[cfg(test)]
                reverified: false,
            },
            T::SiteConfig => StatementSpec {
                signing_purpose: Purpose::ConfigIntegrity,
                device_bound: true,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "update_seq",
                    equal: EqualSeq::IdenticalOnly,
                }),
                #[cfg(test)]
                nested: &[T::RbacManifest],
                checks: &[
                    R::NotYetValid,
                    R::Expired,
                    R::DeviceBindingMismatch,
                    R::DeviceIdMismatch,
                    R::TenantMismatch,
                    R::SequenceReplay,
                    R::SiteFileDigestMismatch,
                    R::RbacManifestDigestMismatch,
                ],
                #[cfg(test)]
                reverified: true,
            },
            T::RbacManifest => StatementSpec {
                signing_purpose: Purpose::RbacManifest,
                device_bound: false,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "policy_version",
                    equal: EqualSeq::IdenticalOnly,
                }),
                #[cfg(test)]
                nested: &[],
                checks: &[
                    R::NotYetValid,
                    R::Expired,
                    R::TenantMismatch,
                    R::SequenceReplay,
                    R::ActorKeyNotAnchored,
                ],
                #[cfg(test)]
                reverified: true,
            },
            T::EdgeUpdate => StatementSpec {
                signing_purpose: Purpose::EdgeProvisioning,
                device_bound: true,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "update_seq",
                    equal: EqualSeq::Reject,
                }),
                #[cfg(test)]
                nested: &[T::EdgeRelease],
                checks: &[
                    R::NotYetValid,
                    R::Expired,
                    R::DeviceBindingMismatch,
                    R::DeviceIdMismatch,
                    R::TenantMismatch,
                    R::BoardMismatch,
                    R::RollbackBelowFloor,
                    R::SequenceReplay,
                    R::ReleaseDigestMismatch,
                    R::ReleaseMismatch,
                ],
                #[cfg(test)]
                reverified: false,
            },
            T::OsUpdate => StatementSpec {
                signing_purpose: Purpose::EdgeProvisioning,
                device_bound: true,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "update_seq",
                    equal: EqualSeq::Reject,
                }),
                #[cfg(test)]
                nested: &[],
                checks: &[
                    R::NotYetValid,
                    R::Expired,
                    R::DeviceBindingMismatch,
                    R::DeviceIdMismatch,
                    R::TenantMismatch,
                    R::CompatibleMismatch,
                    R::OsVersionTooOld,
                    R::RollbackBelowFloor,
                    R::AgentAbiUnsupported,
                    R::SequenceReplay,
                ],
                #[cfg(test)]
                reverified: false,
            },
            T::SiteNetpolicy => StatementSpec {
                signing_purpose: Purpose::ConfigIntegrity,
                device_bound: true,
                tenant_bound: true,
                sequence: Some(SequenceRule {
                    field: "update_seq",
                    equal: EqualSeq::IdenticalOnly,
                }),
                #[cfg(test)]
                nested: &[],
                checks: &[
                    R::NotYetValid,
                    R::Expired,
                    R::DeviceBindingMismatch,
                    R::DeviceIdMismatch,
                    R::TenantMismatch,
                    R::SequenceReplay,
                    R::InterfaceMappingInvalid,
                ],
                #[cfg(test)]
                reverified: true,
            },
        }
    }
}

string_enum!(
    /// Board vocabulary (common.schema.json `board_profile`, boards.json).
    BoardProfile {
        RevpiConnect4 => "revpi-connect4",
        Rpi4Cm4 => "rpi4-cm4",
        QemuX86_64 => "qemu-x86_64",
    }
);

string_enum!(
    /// Release architectures (common.schema.json `arch`).
    Arch {
        Aarch64 => "aarch64",
        X86_64 => "x86_64",
    }
);

string_enum!(
    /// Agent profiles (common.schema.json `agent_profile`).
    AgentProfile {
        SuderraOs => "suderra-os",
    }
);

string_enum!(
    /// Agent cargo features a Suderra OS release may carry (common.schema.json).
    CargoFeature {
        Gpio => "gpio",
        RevpiIo => "revpi-io",
        ScadaDisplay => "scada-display",
        SuderraOs => "suderra-os",
    }
);

string_enum!(
    /// Device binding methods (common.schema.json `device_binding.method`).
    BindingMethod {
        TpmEkSha256 => "tpm-ek-sha256",
        Bcm2711SerialOtpSha256 => "bcm2711-serial-otp-sha256",
        DmiProductUuidSha256 => "dmi-product-uuid-sha256",
    }
);

string_enum!(
    all
    /// Fixed site file paths relative to /data/suderra/site (common.schema.json
    /// `site_path`).
    SitePath {
        ConfigYaml => "config.yaml",
        IoConfigYaml => "io-config.yaml",
        SitePolicyJson => "site-policy.json",
        HardwareInventoryYaml => "hardware-inventory.yaml",
        RevpiConfigRsc => "revpi/config.rsc",
    }
);

string_enum!(
    /// Root-owned lifecycle states (common.schema.json `lifecycle_state`).
    LifecycleState {
        Factory => "FACTORY",
        Provisioning => "PROVISIONING",
        Active => "ACTIVE",
        Maintenance => "MAINTENANCE",
        Decommissioned => "DECOMMISSIONED",
        Rma => "RMA",
        Locked => "LOCKED",
    }
);

string_enum!(
    /// boards.json `boards[].role`.
    BoardRole {
        Primary => "primary",
        Secondary => "secondary",
        Ci => "ci",
    }
);

/// One row of boards.json `boards`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoardSpec {
    /// Role of the board: `ci` boards are dev/CI targets that pin dev/CI
    /// keys in every variant (DEC-3.9).
    pub role: BoardRole,
    /// Release architecture.
    pub arch: Arch,
    /// Agent profile.
    pub agent_profile: AgentProfile,
    /// Exact cargo feature set of the release.
    pub cargo_features: &'static [CargoFeature],
    /// RAUC compatible of the board's images.
    pub rauc_compatible: &'static str,
    /// Device binding method of the board.
    pub device_binding_method: BindingMethod,
    /// Role of every Ethernet interface until a signed site policy maps it to
    /// another one (boards.json `default_interface_role`, DEC-11.6).
    #[cfg(test)]
    pub default_interface_role: NetRole,
}

impl BoardProfile {
    /// boards.json row.
    pub(crate) fn spec(self) -> BoardSpec {
        use CargoFeature as F;
        match self {
            BoardProfile::RevpiConnect4 => BoardSpec {
                role: BoardRole::Primary,
                arch: Arch::Aarch64,
                agent_profile: AgentProfile::SuderraOs,
                cargo_features: &[F::RevpiIo, F::ScadaDisplay, F::SuderraOs],
                rauc_compatible: "suderra-os-revpi-connect4",
                device_binding_method: BindingMethod::TpmEkSha256,
                #[cfg(test)]
                default_interface_role: NetRole::Wan,
            },
            BoardProfile::Rpi4Cm4 => BoardSpec {
                role: BoardRole::Secondary,
                arch: Arch::Aarch64,
                agent_profile: AgentProfile::SuderraOs,
                cargo_features: &[F::Gpio, F::ScadaDisplay, F::SuderraOs],
                rauc_compatible: "suderra-os-rpi4-cm4",
                device_binding_method: BindingMethod::Bcm2711SerialOtpSha256,
                #[cfg(test)]
                default_interface_role: NetRole::Wan,
            },
            BoardProfile::QemuX86_64 => BoardSpec {
                role: BoardRole::Ci,
                arch: Arch::X86_64,
                agent_profile: AgentProfile::SuderraOs,
                cargo_features: &[F::ScadaDisplay, F::SuderraOs],
                rauc_compatible: "suderra-os-qemu-x86_64",
                device_binding_method: BindingMethod::TpmEkSha256,
                #[cfg(test)]
                default_interface_role: NetRole::Wan,
            },
        }
    }
}

/// artifact-naming.json `suderra_os_channel`.
pub(crate) mod naming {
    use super::{Arch, BoardProfile};

    /// Name of the single binary member of every Suderra OS release artifact.
    pub(crate) const BINARY_NAME: &str = "suderra-agent";
    /// Archive members, exactly (DEC-1.10).
    pub(crate) const ARCHIVE_MEMBERS: [&str; 1] = [BINARY_NAME];
    /// Artifact format.
    pub(crate) const FORMAT: &str = "tar.gz";
    /// Artifact name template.
    pub(crate) const ARTIFACT_TEMPLATE: &str =
        "suderra-agent-os-{version}-{board_profile}-{arch}.tar.gz";
    /// Release statement name template.
    #[cfg(test)]
    pub(crate) const STATEMENT_TEMPLATE: &str = "{artifact}.release.dsse.json";

    /// Artifact name of a release (`suderra_os_channel.artifact`).
    pub(crate) fn artifact_name(version: &str, board: BoardProfile, arch: Arch) -> String {
        ARTIFACT_TEMPLATE
            .replace("{version}", version)
            .replace("{board_profile}", board.as_str())
            .replace("{arch}", arch.as_str())
    }
}

/// Domain prefix of [`TEST_ONLY_KEYID_DIGESTS`].
pub(crate) const TEST_ONLY_DIGEST_PREFIX: &str = "suderra-test-only-keyid:";

/// SHA-256 of `TEST_ONLY_DIGEST_PREFIX ‖ keyid` for every key of
/// test-keys/keyring.json (keys and unanchored keys). No image of any variant
/// may pin one (DEC-3.9); the root key loader refuses them. The keyids
/// themselves never appear in this source or the binary: they are contract
/// key material, which scripts/ci/check-no-contract-test-keys.py refuses in
/// every tracked file and every built rootfs.
pub(crate) const TEST_ONLY_KEYID_DIGESTS: [&str; 10] = [
    "6312b1a979b3772b75af0ee3d503388f8c51a36d8b0db1443dcee6afe1eea946",
    "e1a54e464806e01d452063f3e6ab77b575ae879371c291aa8602a928a5636979",
    "182750ec9905b0935311a44b89a0b703b6071f0f3813c686a005bb3d87415305",
    "945f94543aab29ddfe9dc6022bfe877b6ab3be175f29dc4e2209065f3ca969bd",
    "a5e8adf4c980b8783c5b51de02d0fcbb37c902eb69ab0034d3b47c864f7ac450",
    "2bd600715a406e089dde59f8ece94321a18030cda6dcd2c2f702ca0f689fce06",
    "191397efe5d5af9c6d2cb7049ee0dfef37119864ae3d06361805bf204346d69b",
    "2316cd164dbf5f52e14b0b717735c573d945516214cdf0d1f360c3af1cd1e0fd",
    "899c29ded5253070371e2d54310450dfd820371e8cf6792852f29ad9934a33ca",
    "b91ac42615956e27827a52c6944582c203b1f1765cf4bb9405126655c2c8ba00",
];

/// Whether `keyid` is a contract TEST-ONLY key.
pub(crate) fn is_test_only_keyid(keyid: &str) -> bool {
    let digest =
        super::encoding::sha256_hex(format!("{TEST_ONLY_DIGEST_PREFIX}{keyid}").as_bytes());
    TEST_ONLY_KEYID_DIGESTS.contains(&digest.as_str())
}

string_enum!(
    /// Result kinds (result.schema.json `kind`).
    ResultKind {
        Provisioning => "provisioning",
        EdgeInstall => "edge-install",
        EdgeUpdate => "edge-update",
        EdgeRollback => "edge-rollback",
        VerifyCurrent => "verify-current",
        SiteConfig => "site-config",
        Lockdown => "lockdown",
        Lifecycle => "lifecycle",
        HealthGate => "health-gate",
        DataUnlock => "data-unlock",
        TimeState => "time-state",
        OsUpdate => "os-update",
        UpdateRequest => "update-request",
        SiteNetpolicy => "site-netpolicy",
        TrustAnchors => "trust-anchors",
    }
);

string_enum!(
    /// Result outcomes (result.schema.json `outcome`).
    Outcome {
        Ok => "ok",
        Rejected => "rejected",
        Failed => "failed",
        Alarm => "alarm",
    }
);

string_enum!(
    /// Clock trust (result.schema.json `time_state`, DEC-7.3).
    TimeState {
        Unsynced => "unsynced",
        SyncedUnauthenticated => "synced-unauthenticated",
        SyncedNts => "synced-nts",
    }
);

impl ResultKind {
    /// Whether a result of this kind concludes a request on the update channel
    /// and so names the statement it concludes in `subject.statement_type` and
    /// `subject.statement_digest` (result.schema.json; channels.json
    /// update_channel.settlement): that digest is what settles the request.
    pub(crate) fn names_its_statement(self) -> bool {
        matches!(
            self,
            ResultKind::EdgeUpdate
                | ResultKind::OsUpdate
                | ResultKind::SiteConfig
                | ResultKind::SiteNetpolicy
                | ResultKind::TrustAnchors
        )
    }

    /// statements.json `unsigned_documents.suderra.result.v1.reasons_by_kind`:
    /// (statements verified, re-verification, operational codes).
    fn reason_sources(self) -> (&'static [StatementType], bool, &'static [Reason]) {
        use Reason as R;
        use StatementType as T;
        const DOWNLOAD: &[Reason] = &[
            R::ClockUnsynced,
            R::FetchFailed,
            R::ArtifactDigestMismatch,
            R::BinaryDigestMismatch,
            R::ArchiveInvalid,
            R::IoError,
        ];
        match self {
            ResultKind::Provisioning => (
                &[
                    T::EdgeProvisioning,
                    T::EdgeRelease,
                    T::TrustAnchors,
                    T::SiteConfig,
                    T::RbacManifest,
                ],
                false,
                &[
                    R::ClockUnsynced,
                    R::FetchFailed,
                    R::ArtifactDigestMismatch,
                    R::BinaryDigestMismatch,
                    R::ArchiveInvalid,
                    R::UsbLayoutInvalid,
                    R::IoError,
                ],
            ),
            ResultKind::EdgeInstall => (&[T::EdgeRelease], false, DOWNLOAD),
            ResultKind::EdgeUpdate => (
                &[T::EdgeUpdate, T::EdgeRelease],
                false,
                &[
                    R::ClockUnsynced,
                    R::FetchFailed,
                    R::ArtifactDigestMismatch,
                    R::BinaryDigestMismatch,
                    R::ArchiveInvalid,
                    R::MaintenanceBlocked,
                    R::ApprovalMissing,
                    R::IoError,
                ],
            ),
            ResultKind::OsUpdate => (
                &[T::OsUpdate],
                false,
                &[
                    R::ClockUnsynced,
                    R::FetchFailed,
                    R::ArtifactDigestMismatch,
                    R::RaucInstallFailed,
                    R::MaintenanceBlocked,
                    R::ApprovalMissing,
                    R::IoError,
                ],
            ),
            ResultKind::UpdateRequest => (
                &[],
                false,
                &[
                    R::RequestTooLarge,
                    R::RequestNotRegularFile,
                    R::RequestUnsupported,
                    R::IoError,
                ],
            ),
            ResultKind::EdgeRollback => (&[], false, &[R::HealthWindowFailed, R::IoError]),
            ResultKind::VerifyCurrent => (
                &[
                    T::EdgeRelease,
                    T::TrustAnchors,
                    T::SiteConfig,
                    T::SiteNetpolicy,
                    T::RbacManifest,
                ],
                true,
                &[
                    R::ReleaseNotInstalled,
                    R::CurrentLinkMismatch,
                    R::BinaryDigestMismatch,
                ],
            ),
            ResultKind::SiteConfig => (
                &[T::SiteConfig, T::RbacManifest, T::TrustAnchors],
                false,
                &[
                    R::ClockUnsynced,
                    R::FetchFailed,
                    R::SiteBundleMissing,
                    R::MaintenanceBlocked,
                    R::ApprovalMissing,
                    R::ConfigRscLoadFailed,
                    R::IoError,
                ],
            ),
            ResultKind::SiteNetpolicy => (
                &[T::SiteNetpolicy],
                false,
                &[R::ClockUnsynced, R::FirewallLoadFailed, R::IoError],
            ),
            ResultKind::TrustAnchors => (&[T::TrustAnchors], false, &[R::IoError]),
            ResultKind::Lockdown => (
                &[],
                false,
                &[
                    R::ReceiptMissing,
                    R::LifecycleInconsistent,
                    R::ProvisioningModeActive,
                    R::FirewallLoadFailed,
                    R::IoError,
                ],
            ),
            ResultKind::Lifecycle => (
                &[T::DeviceLifecycle, T::EdgeActivationReceipt],
                false,
                &[R::StateCorrupt, R::IoError],
            ),
            ResultKind::HealthGate => (
                &[],
                false,
                &[
                    R::AgentNotActive,
                    R::AgentDegraded,
                    R::VerityInactive,
                    R::DataMapperMissing,
                    R::FirewallHashMismatch,
                    R::LifecycleInconsistent,
                    R::ClockBelowFloor,
                    R::TpmUnavailable,
                    R::BspProbeFailed,
                    R::AbiIncompatible,
                ],
            ),
            ResultKind::DataUnlock => (
                &[],
                false,
                &[R::DataUnmountable, R::TpmUnsealFailed, R::IoError],
            ),
            ResultKind::TimeState => (&[], false, &[R::ClockUnsynced, R::ClockBelowFloor]),
        }
    }

    /// Reasons a result of this kind may carry: the rejection codes of the
    /// statements it verifies plus its operational codes.
    pub(crate) fn allows(self, reason: Reason) -> bool {
        let (statements, reverification, operational) = self.reason_sources();
        if operational.contains(&reason) {
            return true;
        }
        if statements.is_empty() {
            return false;
        }
        if reverification && REVERIFY_ADDED.contains(&reason) {
            return true;
        }
        if reverification && REVERIFY_SKIPPED.contains(&reason) {
            return false;
        }
        VERIFICATION_ORDER.contains(&reason)
            || statements.iter().any(|t| t.spec().checks.contains(&reason))
    }
}

#[cfg(test)]
mod tests {
    //! Drift gate: every table above against the vendored contract.

    use super::*;
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    pub(crate) fn contract_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/suderra-edge/v1")
    }

    fn load(rel: &str) -> Value {
        let path = contract_dir().join(rel);
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| {
            panic!("vendored contract file {} unreadable: {e}", path.display())
        }))
        .unwrap()
    }

    fn strings(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect()
    }

    fn set<T: AsRef<str>>(items: impl IntoIterator<Item = T>) -> BTreeSet<String> {
        items.into_iter().map(|s| s.as_ref().to_owned()).collect()
    }

    #[test]
    fn reasons_match_contract() {
        let st = load("statements.json");
        let rejections: BTreeSet<String> = st["rejection_reasons"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let operational: BTreeSet<String> = st["unsigned_documents"]["suderra.result.v1"]
            ["operational_reasons"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let ours_rej = set(Reason::ALL
            .iter()
            .filter(|r| r.is_statement_rejection())
            .map(|r| r.as_str()));
        let ours_op = set(Reason::ALL
            .iter()
            .filter(|r| !r.is_statement_rejection())
            .map(|r| r.as_str()));
        assert_eq!(ours_rej, rejections);
        assert_eq!(ours_op, operational);
        assert_eq!(
            strings(&st["verification_order"]),
            VERIFICATION_ORDER.map(|r| r.as_str().to_owned()).to_vec()
        );
        assert_eq!(
            set(strings(&st["reverification"]["skipped_checks"])),
            set(REVERIFY_SKIPPED.map(Reason::as_str))
        );
        assert_eq!(
            set(strings(&st["reverification"]["added_checks"])),
            set(REVERIFY_ADDED.map(Reason::as_str))
        );
    }

    #[test]
    fn statements_match_contract() {
        let st = load("statements.json");
        let rows = st["statements"].as_object().unwrap();
        assert_eq!(
            set(rows.keys()),
            set(StatementType::ALL.iter().map(|t| t.as_str()))
        );
        let reverified = set(strings(&st["reverification"]["applies_to"]));
        for t in StatementType::ALL {
            let row = &rows[t.as_str()];
            let spec = t.spec();
            assert_eq!(row["payload_type"], t.payload_type(), "{t}");
            assert_eq!(row["signing_purpose"], spec.signing_purpose.as_str(), "{t}");
            assert_eq!(row["device_bound"], spec.device_bound, "{t}");
            assert_eq!(row["tenant_bound"], spec.tenant_bound, "{t}");
            assert_eq!(
                strings(&row["checks"]),
                spec.checks
                    .iter()
                    .map(|r| r.as_str().to_owned())
                    .collect::<Vec<_>>(),
                "{t}"
            );
            assert_eq!(
                strings(&row["nested"]),
                spec.nested
                    .iter()
                    .map(|n| n.as_str().to_owned())
                    .collect::<Vec<_>>(),
                "{t}"
            );
            assert!(
                strings(&row["verified_by"]["os-root"]["omits"]).is_empty(),
                "{t}"
            );
            match (&row["sequence"], spec.sequence) {
                (Value::Null, None) => {}
                (seq, Some(rule)) => {
                    assert_eq!(seq["field"], rule.field, "{t}");
                    let equal = match rule.equal {
                        EqualSeq::Reject => "reject",
                        EqualSeq::IdenticalOnly => "identical-only",
                    };
                    assert_eq!(seq["equal_seq"], equal, "{t}");
                }
                (other, rule) => panic!("{t}: sequence {other} vs {rule:?}"),
            }
            assert_eq!(reverified.contains(t.as_str()), spec.reverified, "{t}");
            let schema = load(row["schema"].as_str().unwrap());
            assert_eq!(
                schema["properties"]["_type"]["const"],
                t.type_member(),
                "{t}"
            );
        }
    }

    #[test]
    fn purposes_match_contract() {
        let st = load("statements.json");
        let purposes = st["purposes"].as_object().unwrap();
        assert_eq!(
            set(purposes.keys()),
            set(Purpose::ALL.iter().map(|p| p.as_str()))
        );
        for p in Purpose::ALL {
            let row = &purposes[p.as_str()];
            let anchored = set(strings(&row["anchored_in"]));
            assert_eq!(
                anchored.contains("os-image"),
                p.anchored_in_os_image(),
                "{p}"
            );
            assert_eq!(
                anchored.contains("trust-anchors-bundle"),
                p.anchored_in_bundle(),
                "{p}"
            );
            assert_eq!(row["algorithm"], p.algorithm(), "{p}");
        }
    }

    #[test]
    fn boards_and_naming_match_contract() {
        let boards = load("boards.json");
        let rows = boards["boards"].as_array().unwrap();
        assert_eq!(
            set(rows.iter().map(|r| r["board_profile"].as_str().unwrap())),
            set(BoardProfile::ALL.iter().map(|b| b.as_str()))
        );
        for row in rows {
            let board = BoardProfile::parse(row["board_profile"].as_str().unwrap()).unwrap();
            let spec = board.spec();
            assert_eq!(row["role"], spec.role.as_str(), "{board}");
            assert_eq!(row["arch"], spec.arch.as_str(), "{board}");
            assert_eq!(row["agent_profile"], spec.agent_profile.as_str(), "{board}");
            assert_eq!(
                set(strings(&row["cargo_features"])),
                set(spec.cargo_features.iter().map(|f| f.as_str())),
                "{board}"
            );
            assert_eq!(row["rauc_compatible"], spec.rauc_compatible, "{board}");
            assert_eq!(
                row["device_binding_method"],
                spec.device_binding_method.as_str(),
                "{board}"
            );
            assert_eq!(
                row["default_interface_role"],
                match spec.default_interface_role {
                    NetRole::Wan => "wan",
                    NetRole::Ot => "ot",
                },
                "{board}"
            );
        }
        let boards_schema = load("schemas/boards.schema.json");
        assert_eq!(
            set(strings(
                &boards_schema["properties"]["boards"]["items"]["properties"]["role"]["enum"]
            )),
            set(BoardRole::ALL.iter().map(|r| r.as_str()))
        );
        let common = load("schemas/common.schema.json");
        let defs = &common["$defs"];
        let enum_set = |name: &str| set(strings(&defs[name]["enum"]));
        assert_eq!(
            enum_set("board_profile"),
            set(BoardProfile::ALL.iter().map(|b| b.as_str()))
        );
        assert_eq!(enum_set("arch"), set(Arch::ALL.iter().map(|b| b.as_str())));
        assert_eq!(
            enum_set("agent_profile"),
            set(AgentProfile::ALL.iter().map(|b| b.as_str()))
        );
        assert_eq!(
            enum_set("cargo_feature"),
            set(CargoFeature::ALL.iter().map(|b| b.as_str()))
        );
        assert_eq!(
            enum_set("site_path"),
            set(SitePath::ALL.iter().map(|b| b.as_str()))
        );
        assert_eq!(
            enum_set("lifecycle_state"),
            set(LifecycleState::ALL.iter().map(|b| b.as_str()))
        );
        assert_eq!(
            set(strings(
                &defs["device_binding"]["properties"]["method"]["enum"]
            )),
            set(BindingMethod::ALL.iter().map(|b| b.as_str()))
        );

        let naming = load("artifact-naming.json");
        let os = &naming["suderra_os_channel"];
        assert_eq!(os["artifact"], naming::ARTIFACT_TEMPLATE);
        assert_eq!(os["statement"], naming::STATEMENT_TEMPLATE);
        assert_eq!(os["format"], naming::FORMAT);
        assert_eq!(os["binary_name"], naming::BINARY_NAME);
        assert_eq!(
            strings(&os["archive_members"]),
            naming::ARCHIVE_MEMBERS.to_vec()
        );
    }

    #[test]
    fn test_keyids_match_keyring() {
        let ring = load("test-keys/keyring.json");
        assert_eq!(ring["test_only"], true);
        let keyids: Vec<&str> = ring["keys"]
            .as_array()
            .unwrap()
            .iter()
            .chain(ring["unanchored_keys"].as_array().unwrap())
            .map(|k| k["keyid"].as_str().unwrap())
            .collect();
        let mut digests: Vec<String> = keyids
            .iter()
            .map(|id| {
                crate::contracts::encoding::sha256_hex(
                    format!("{TEST_ONLY_DIGEST_PREFIX}{id}").as_bytes(),
                )
            })
            .collect();
        digests.sort();
        let mut ours: Vec<String> = TEST_ONLY_KEYID_DIGESTS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        ours.sort();
        assert_eq!(ours, digests);
        assert!(keyids.iter().all(|id| is_test_only_keyid(id)));
        assert!(!is_test_only_keyid(&"0".repeat(64)));
    }

    #[test]
    fn result_reasons_match_schema() {
        let schema = load("schemas/result.schema.json");
        let kinds = set(strings(&schema["properties"]["kind"]["enum"]));
        assert_eq!(kinds, set(ResultKind::ALL.iter().map(|k| k.as_str())));
        assert_eq!(
            set(strings(&schema["properties"]["outcome"]["enum"])),
            set(Outcome::ALL.iter().map(|k| k.as_str()))
        );
        assert_eq!(
            set(strings(&schema["properties"]["time_state"]["enum"])),
            set(TimeState::ALL.iter().map(|k| k.as_str()))
        );
        let st = load("statements.json");
        let by_kind = st["unsigned_documents"]["suderra.result.v1"]["reasons_by_kind"]
            .as_object()
            .unwrap();
        // The kinds whose results settle a request name their statement.
        assert_eq!(
            set(strings(&schema["if"]["properties"]["kind"]["enum"])),
            set(ResultKind::ALL
                .iter()
                .filter(|k| k.names_its_statement())
                .map(|k| k.as_str())),
        );
        for rule in schema["allOf"].as_array().unwrap() {
            let kind =
                ResultKind::parse(rule["if"]["properties"]["kind"]["const"].as_str().unwrap())
                    .unwrap();
            let allowed = set(strings(&rule["then"]["properties"]["reason"]["enum"]));
            let ours = set(Reason::ALL
                .iter()
                .filter(|r| kind.allows(**r))
                .map(|r| r.as_str()));
            assert_eq!(ours, allowed, "{kind}");
            let row = &by_kind[kind.as_str()];
            let (statements, reverification, operational) = kind.reason_sources();
            assert_eq!(
                strings(&row["statements"]),
                statements
                    .iter()
                    .map(|t| t.as_str().to_owned())
                    .collect::<Vec<_>>(),
                "{kind}"
            );
            assert_eq!(row["reverification"], reverification, "{kind}");
            assert_eq!(
                strings(&row["operational"]),
                operational
                    .iter()
                    .map(|r| r.as_str().to_owned())
                    .collect::<Vec<_>>(),
                "{kind}"
            );
        }
    }
}
