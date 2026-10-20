// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Golden fixtures of contract v1 (fixtures/index.json) through the OS root
//! verifier: every statement fixture whose verifier is `os-root`, every
//! delivery, the request and result documents, and the DSSE PAE and
//! signature vectors must reach exactly their labelled verdict and reason.

use super::delivery::{Delivery, ProvisioningRequest};
use super::dsse::{pae, verify_strict, Envelope};
use super::encoding::{decode_base64_array, sha256_hex};
use super::keys::{KeyEntry, KeyStore};
use super::registry::{Arch, BoardProfile, Purpose, Reason, SitePath, StatementType};
use super::statements::DeviceBinding;
use super::verify::{
    verify_lifecycle, verify_provisioning, verify_rbac_with_bundle, verify_receipt, verify_release,
    verify_site_config_with_bundle, verify_trust_anchors, Accepted, Delivered, DeviceRecord,
    Identity, Mode, OsCompat, Scope, SiteFiles,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn contract() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/suderra-edge/v1")
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = contract().join("fixtures").join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn index() -> Value {
    serde_json::from_slice(&fixture("index.json")).unwrap()
}

/// OS image pins of the fixtures' simulated device (keyring fixture_anchor).
fn os_pins() -> KeyStore {
    let ring: Value =
        serde_json::from_slice(&std::fs::read(contract().join("test-keys/keyring.json")).unwrap())
            .unwrap();
    KeyStore::from_entries(
        ring["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|k| k["fixture_anchor"] == "os-image")
            .map(|k| KeyEntry {
                purpose: Purpose::parse(k["purpose"].as_str().unwrap()).unwrap(),
                epoch: u16::try_from(k["epoch"].as_u64().unwrap()).unwrap(),
                raw: decode_base64_array::<32>(k["public_key"].as_str().unwrap()).unwrap(),
            }),
    )
    .unwrap()
}

fn statement_digest_of_fixture(rel: &str) -> String {
    sha256_hex(&Envelope::parse(&fixture(rel)).unwrap().payload)
}

fn device(index: &Value, name: &str) -> DeviceRecord {
    let ctx = &index["device_contexts"][name];
    assert!(ctx.is_object(), "unknown device context {name}");
    let identity = match (ctx["tenant_id"].as_str(), ctx["device_id"].as_str()) {
        (Some(t), Some(d)) => Some(Identity {
            tenant_id: t.to_owned(),
            device_id: d.to_owned(),
        }),
        (None, None) => None,
        other => panic!("{name}: half an identity {other:?}"),
    };
    let accepted = ctx["accepted"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(t, a)| {
            (
                StatementType::parse(t).unwrap(),
                Accepted {
                    seq: a.get("seq").map(|s| s.as_u64().unwrap()),
                    statement_digest: a["statement_digest"]["sha256"].as_str().unwrap().to_owned(),
                },
            )
        })
        .collect();
    let ratchet = ctx["ratchet"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, e)| {
            (
                Purpose::parse(p).unwrap(),
                u16::try_from(e.as_u64().unwrap()).unwrap(),
            )
        })
        .collect();
    let os = &ctx["os_release"];
    let version = super::encoding::parse_version_core(os["VERSION_ID"].as_str().unwrap()).unwrap();
    let abi = super::encoding::parse_abi_range(os["SUDERRA_AGENT_ABI"].as_str().unwrap()).unwrap();
    let kernel_config = ctx["kernel_config"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().split('=').next().unwrap().to_owned())
        .collect();
    DeviceRecord {
        board: BoardProfile::parse(ctx["board_profile"].as_str().unwrap()).unwrap(),
        arch: Arch::parse(ctx["arch"].as_str().unwrap()).unwrap(),
        binding: serde_json::from_value::<DeviceBinding>(ctx["device_binding"].clone()).unwrap(),
        identity,
        security_version_floor: ctx["security_version_floor"].as_u64().unwrap(),
        accepted,
        ratchet,
        installed_manifest_digest: ctx["installed_manifest"]
            .as_str()
            .map(statement_digest_of_fixture),
        os: OsCompat {
            version,
            abi,
            kernel_config,
        },
    }
}

fn envelope(inputs: &Value, name: &str) -> Envelope {
    let rel = inputs[name]
        .as_str()
        .unwrap_or_else(|| panic!("fixture needs input {name}"));
    Envelope::parse(&fixture(rel)).unwrap_or_else(|r| panic!("input {rel}: {r}"))
}

fn site_files(inputs: &Value) -> SiteFiles {
    inputs["site_files"]
        .as_object()
        .map(|files| {
            files
                .iter()
                .map(|(path, rel)| {
                    (
                        SitePath::parse(path).unwrap(),
                        fixture(rel.as_str().unwrap()),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Reasons the OS root verifier reports for one statement fixture.
fn run_statement(index: &Value, keys: &KeyStore, entry: &Value) -> BTreeSet<Reason> {
    let now = index["evaluation_time"].as_str().unwrap();
    let record = entry["device_context"]
        .as_str()
        .map(|name| device(index, name));
    let mode = match entry["mode"].as_str().unwrap() {
        "accept" => Mode::Accept,
        "reverify" => Mode::Reverify,
        other => panic!("mode {other}"),
    };
    let scope = Scope {
        os_keys: keys,
        device: record.as_ref(),
        now,
        mode,
    };
    let env = match Envelope::parse(&fixture(entry["path"].as_str().unwrap())) {
        Ok(env) => env,
        Err(reason) => return BTreeSet::from([reason]),
    };
    let inputs = &entry["inputs"];
    let statement_type = StatementType::parse(entry["statement_type"].as_str().unwrap()).unwrap();
    match statement_type {
        StatementType::EdgeRelease => verify_release(&env, &scope, None).reasons,
        StatementType::TrustAnchors => verify_trust_anchors(&env, &scope, None).reasons,
        StatementType::RbacManifest => {
            verify_rbac_with_bundle(&env, &envelope(inputs, "trust_anchors"), &scope, None).reasons
        }
        StatementType::SiteConfig => {
            verify_site_config_with_bundle(
                &env,
                &envelope(inputs, "trust_anchors"),
                &scope,
                None,
                &envelope(inputs, "rbac_manifest"),
                &site_files(inputs),
            )
            .reasons
        }
        StatementType::EdgeProvisioning => {
            let files = site_files(inputs);
            let (release, ta, site, rbac) = (
                envelope(inputs, "release_statement"),
                envelope(inputs, "trust_anchors"),
                envelope(inputs, "site_config"),
                envelope(inputs, "rbac_manifest"),
            );
            verify_provisioning(
                &env,
                Delivered {
                    release: &release,
                    trust_anchors: &ta,
                    site_config: &site,
                    rbac: &rbac,
                    site_files: &files,
                },
                inputs["request_nonce"].as_str().unwrap(),
                &scope,
            )
            .reasons
        }
        StatementType::EdgeActivationReceipt => verify_receipt(&env, &scope).reasons,
        StatementType::DeviceLifecycle => verify_lifecycle(&env, &scope).reasons,
    }
}

fn expected(entry: &Value) -> BTreeSet<Reason> {
    match entry["expect"].as_str().unwrap() {
        "accept" => BTreeSet::new(),
        "reject" => BTreeSet::from([Reason::parse(entry["reason"].as_str().unwrap())
            .unwrap_or_else(|| panic!("unknown reason in {entry}"))]),
        other => panic!("expect {other}"),
    }
}

#[test]
fn every_os_root_statement_fixture_reaches_its_verdict() {
    let index = index();
    let keys = os_pins();
    let mut failures = Vec::new();
    let mut ran = 0;
    for entry in index["statements"].as_array().unwrap() {
        if entry["verifier"] != "os-root" {
            continue;
        }
        ran += 1;
        let got = run_statement(&index, &keys, entry);
        let want = expected(entry);
        if got != want {
            failures.push(format!(
                "{} [{} {} ctx={}]: want {:?}, got {:?}",
                entry["path"],
                entry["statement_type"],
                entry["mode"],
                entry["device_context"],
                want,
                got
            ));
        }
    }
    assert!(ran > 100, "only {ran} os-root fixtures found");
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_delivery_reaches_its_verdict() {
    let index = index();
    let keys = os_pins();
    let now = index["evaluation_time"].as_str().unwrap();
    let deliveries = index["deliveries"].as_array().unwrap();
    assert!(!deliveries.is_empty());
    for entry in deliveries {
        let record = device(&index, entry["device_context"].as_str().unwrap());
        let scope = Scope {
            os_keys: &keys,
            device: Some(&record),
            now,
            mode: Mode::Accept,
        };
        let request = ProvisioningRequest::parse(&fixture(entry["request"].as_str().unwrap()))
            .expect("golden request");
        let got = match Delivery::parse(&fixture(entry["path"].as_str().unwrap())) {
            Ok(delivery) => delivery.verify(&request.nonce, &scope).reasons,
            Err(reason) => BTreeSet::from([reason]),
        };
        assert_eq!(got, expected(entry), "{}", entry["path"]);
    }
}

#[test]
fn accepted_delivery_yields_the_complete_statement_set() {
    let index = index();
    let keys = os_pins();
    let record = device(&index, "revpi-factory");
    let scope = Scope {
        os_keys: &keys,
        device: Some(&record),
        now: index["evaluation_time"].as_str().unwrap(),
        mode: Mode::Accept,
    };
    let delivery = Delivery::parse(&fixture(
        "edge-provisioning-delivery/valid/revpi-connect4-first.json",
    ))
    .unwrap();
    let request = ProvisioningRequest::parse(&fixture(
        "edge-provisioning-request/valid/revpi-connect4-first.json",
    ))
    .unwrap();
    let set = delivery
        .verify(&request.nonce, &scope)
        .accepted
        .expect("accepted");
    assert_eq!(set.manifest.statement.board, BoardProfile::RevpiConnect4);
    assert_eq!(
        set.release.statement.version,
        set.manifest.statement.version
    );
    assert_eq!(
        set.site_config.statement.files.len(),
        delivery.site_files.len()
    );
    assert_eq!(set.manifest.digest, delivery.manifest.statement_digest());
}

#[test]
fn documents_validate_exactly_as_labelled() {
    let index = index();
    for entry in index["documents"].as_array().unwrap() {
        let bytes = fixture(entry["path"].as_str().unwrap());
        let got = match entry["document_type"].as_str().unwrap() {
            "suderra.edge-provisioning-request.v1" => ProvisioningRequest::parse(&bytes).err(),
            "suderra.result.v1" => crate::results::ResultDocument::parse(&bytes).err(),
            other => panic!("document type {other}"),
        };
        let want = expected(entry).into_iter().next();
        assert_eq!(got, want, "{}", entry["path"]);
    }
}

#[derive(Deserialize)]
struct Vectors<T> {
    vectors: Vec<T>,
}

#[derive(Deserialize)]
struct PaeVector {
    payload_type: String,
    payload: String,
    pae_hex: String,
}

#[derive(Deserialize)]
struct SignatureVector {
    id: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
    verify_strict: bool,
}

#[test]
fn pae_vectors_match_byte_for_byte() {
    let v: Vectors<PaeVector> = serde_json::from_slice(&fixture("dsse/pae-vectors.json")).unwrap();
    assert!(!v.vectors.is_empty());
    for vector in v.vectors {
        let payload = super::encoding::decode_canonical_base64(&vector.payload).unwrap();
        assert_eq!(
            hex::encode(pae(&vector.payload_type, &payload)),
            vector.pae_hex
        );
    }
}

#[test]
fn signature_vectors_pin_verify_strict() {
    let v: Vectors<SignatureVector> =
        serde_json::from_slice(&fixture("dsse/signature-vectors.json")).unwrap();
    let mut ids = BTreeSet::new();
    for vector in v.vectors {
        let key: [u8; 32] = hex::decode(&vector.public_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let sig: [u8; 64] = hex::decode(&vector.signature_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let message = hex::decode(&vector.message_hex).unwrap();
        assert_eq!(
            verify_strict(&key, &message, &sig),
            vector.verify_strict,
            "{}",
            vector.id
        );
        ids.insert(vector.id);
    }
    for required in [
        "non-canonical-s",
        "small-order-r",
        "non-canonical-a",
        "non-canonical-r",
    ] {
        assert!(ids.contains(required), "vector {required} missing");
    }
}

#[test]
fn reprovisioning_after_install_replays_are_refused() {
    // The first delivery, accepted on the factory device, must be refused once
    // root has recorded it: the manifest's update_seq is spent.
    let index = index();
    let keys = os_pins();
    let mut record = device(&index, "revpi-factory");
    let delivery = Delivery::parse(&fixture(
        "edge-provisioning-delivery/valid/revpi-connect4-first.json",
    ))
    .unwrap();
    let request = ProvisioningRequest::parse(&fixture(
        "edge-provisioning-request/valid/revpi-connect4-first.json",
    ))
    .unwrap();
    let now = index["evaluation_time"].as_str().unwrap();
    let set = {
        let scope = Scope {
            os_keys: &keys,
            device: Some(&record),
            now,
            mode: Mode::Accept,
        };
        delivery.verify(&request.nonce, &scope).accepted.unwrap()
    };
    record.identity = Some(Identity {
        tenant_id: set.manifest.statement.tenant_id.clone(),
        device_id: set.manifest.statement.device_id.clone(),
    });
    record.accepted = BTreeMap::from([(
        StatementType::EdgeProvisioning,
        Accepted {
            seq: Some(set.manifest.statement.update_seq),
            statement_digest: set.manifest.digest.clone(),
        },
    )]);
    let scope = Scope {
        os_keys: &keys,
        device: Some(&record),
        now,
        mode: Mode::Accept,
    };
    assert_eq!(
        delivery.verify(&request.nonce, &scope).reasons,
        BTreeSet::from([Reason::SequenceReplay])
    );
}
