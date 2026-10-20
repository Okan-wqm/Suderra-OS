// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! DSSE v1 envelopes (statements.json `dsse`, DEC-3.2).
//!
//! The signature covers `PAE(payloadType, payload bytes)` exactly; nothing
//! is re-serialized or canonicalized, and a payload is parsed only after its
//! signature verifies under ed25519-dalek `verify_strict`.

use super::encoding::{
    decode_base64_array, decode_canonical_base64, is_payload_type, is_sha256_hex,
};
use super::json::check_strict_object;
use super::registry::Reason;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

/// Largest base64 payload the envelope schema admits.
const MAX_PAYLOAD_B64: usize = 1_048_576;

/// The wire form of an envelope (schemas/dsse-envelope.schema.json).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawEnvelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: Vec<RawSignature>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    keyid: String,
    sig: String,
}

/// A schema-valid envelope with its payload and signature decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    /// DSSE payloadType.
    pub payload_type: String,
    /// The exact signed payload bytes.
    pub payload: Vec<u8>,
    /// Keyid of the single signature.
    pub keyid: String,
    /// The 64-byte Ed25519 signature.
    pub signature: [u8; 64],
}

impl Envelope {
    /// Parses envelope bytes; any failure is `envelope-invalid`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Reason> {
        check_strict_object(bytes).map_err(|_| Reason::EnvelopeInvalid)?;
        let raw: RawEnvelope =
            serde_json::from_slice(bytes).map_err(|_| Reason::EnvelopeInvalid)?;
        Self::from_raw(raw).map_err(|_| Reason::EnvelopeInvalid)
    }

    /// Validates the wire form against the envelope schema.
    pub(crate) fn from_raw(raw: RawEnvelope) -> Result<Self, String> {
        if !is_payload_type(&raw.payload_type) {
            return Err("payloadType does not match the envelope schema".into());
        }
        if raw.payload.len() < 4 || raw.payload.len() > MAX_PAYLOAD_B64 {
            return Err("payload length outside the envelope schema bounds".into());
        }
        let payload = decode_canonical_base64(&raw.payload)
            .ok_or("payload is not canonical standard base64")?;
        let [signature] = <[RawSignature; 1]>::try_from(raw.signatures)
            .map_err(|_| "an envelope carries exactly one signature")?;
        if !is_sha256_hex(&signature.keyid) {
            return Err("keyid is not lowercase hex SHA-256".into());
        }
        if signature.sig.len() != 88 {
            return Err("sig is not the base64 of 64 bytes".into());
        }
        let sig = decode_base64_array::<64>(&signature.sig)
            .ok_or("sig is not canonical base64 of 64 bytes")?;
        Ok(Self {
            payload_type: raw.payload_type,
            payload,
            keyid: signature.keyid,
            signature: sig,
        })
    }

    /// The envelope as DSSE JSON (canonical base64, one signature).
    pub(crate) fn to_json(&self) -> Vec<u8> {
        let value = serde_json::json!({
            "payloadType": self.payload_type,
            "payload": super::encoding::encode_base64(&self.payload),
            "signatures": [{
                "keyid": self.keyid,
                "sig": super::encoding::encode_base64(&self.signature),
            }],
        });
        value.to_string().into_bytes()
    }

    /// SHA-256 of the decoded payload (statements.json `statement_digest`).
    pub(crate) fn statement_digest(&self) -> String {
        super::encoding::sha256_hex(&self.payload)
    }
}

/// DSSE v1 pre-authentication encoding.
pub(crate) fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// `verify_strict` of `signature` over `message` under the raw public key.
/// A key that is not a canonical, decodable point never verifies.
pub(crate) fn verify_strict(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public_key)
        .and_then(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_example() {
        assert_eq!(
            hex::encode(pae("http://example.com/HelloWorld", b"hello world")),
            "44535345763120323920687474703a2f2f6578616d706c652e636f6d2f48656c6c6f576f726c642031312068656c6c6f20776f726c64"
        );
    }

    #[test]
    fn envelope_rejects_schema_violations() {
        let sig = "A".repeat(85) + "A==";
        let ok = format!(
            r#"{{"payloadType":"application/vnd.suderra.edge-release.v1+json","payload":"e30=","signatures":[{{"keyid":"{}","sig":"{sig}"}}]}}"#,
            "a".repeat(64)
        );
        let env = Envelope::parse(ok.as_bytes()).unwrap();
        assert_eq!(Envelope::parse(&env.to_json()).unwrap(), env);
        for bad in [
            ok.replace(r#""signatures":["#, r#""extra":1,"signatures":["#),
            ok.replace("e30=", "e30"),
            ok.replace("e30=", ""),
            ok.replace(&"a".repeat(64), &"A".repeat(64)),
            ok.replace("edge-release.v1", "edge-release.v0"),
            ok.replace(&sig, &("A".repeat(85) + "B==")),
            ok.replace("}]}", r#"},{"keyid":"x","sig":"y"}]}"#),
        ] {
            assert_eq!(
                Envelope::parse(bad.as_bytes()),
                Err(Reason::EnvelopeInvalid),
                "{bad}"
            );
        }
    }
}
