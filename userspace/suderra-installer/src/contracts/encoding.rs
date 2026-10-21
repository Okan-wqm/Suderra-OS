// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Lexical forms of the edge contract (schemas/common.schema.json `$defs`).
//!
//! Each predicate is the exact language of one schema pattern; the typed
//! statement parsers call them so a payload the JSON Schema rejects is
//! `schema-invalid` here too.

use base64::Engine;
use sha2::{Digest as _, Sha256};

/// Lowercase hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Raw SHA-256 of `bytes`.
#[cfg(test)]
pub(crate) fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn all_bytes(s: &str, ok: impl Fn(u8) -> bool) -> bool {
    s.bytes().all(ok)
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// `^[0-9a-f]{64}$` (sha256_hex, keyid).
pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && all_bytes(s, is_lower_hex)
}

/// Lowercase canonical RFC 9562 UUID (`uuid`).
pub(crate) fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            14 => (b'1'..=b'8').contains(&c),
            19 => matches!(c, b'8' | b'9' | b'a' | b'b'),
            _ => is_lower_hex(c),
        })
}

fn digits(s: &[u8], range: std::ops::RangeInclusive<u8>) -> bool {
    s.iter().all(|c| c.is_ascii_digit()) && s.len() == 2 && {
        let v = (s[0] - b'0') * 10 + (s[1] - b'0');
        range.contains(&v)
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` with the schema's field ranges (`timestamp`).
pub(crate) fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && digits(&b[5..7], 1..=12)
        && b[7] == b'-'
        && digits(&b[8..10], 1..=31)
        && b[10] == b'T'
        && digits(&b[11..13], 0..=23)
        && b[13] == b':'
        && digits(&b[14..16], 0..=59)
        && b[16] == b':'
        && digits(&b[17..19], 0..=59)
        && b[19] == b'Z'
}

/// Current UTC time in the contract timestamp form. Timestamps are
/// fixed-width, so their string order is their time order.
pub(crate) fn now_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// `0|[1-9][0-9]*` without bounds; returns the value when it fits u64.
fn decimal(s: &str) -> Option<u64> {
    let ok = match s.as_bytes() {
        [] => false,
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if ok {
        s.parse().ok()
    } else {
        None
    }
}

/// `MAJOR.MINOR.PATCH` with decimal integers (`os_version` core); returns
/// the integer tuple compared by the compatibility rules.
pub(crate) fn parse_version_core(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.split('.');
    let major = decimal(parts.next()?)?;
    let minor = decimal(parts.next()?)?;
    let patch = decimal(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Path-safe semantic version (`semver`, DEC-1.10).
pub(crate) fn is_semver(s: &str) -> bool {
    if s.len() > 64 {
        return false;
    }
    let (core, pre) = match s.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (s, None),
    };
    parse_version_core(core).is_some()
        && pre.is_none_or(|pre| {
            pre.split('.').all(|id| {
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        })
}

/// `0|[1-9][0-9]{0,8}`: a decimal component of at most nine digits, the bound
/// of `os_version` and `agent_abi_range` components (common.schema.json), so
/// that every verifier, whatever its integer width, reads the same number.
fn bounded_decimal(s: &str) -> Option<u64> {
    if s.len() > 9 {
        None
    } else {
        decimal(s)
    }
}

/// `os_version`: version core only, each component at most nine digits.
pub(crate) fn is_os_version(s: &str) -> bool {
    let mut parts = s.split('.');
    let components = [parts.next(), parts.next(), parts.next()];
    parts.next().is_none()
        && components
            .iter()
            .all(|c| c.and_then(bounded_decimal).is_some())
}

/// `MIN-MAX` agent ABI range of /etc/os-release and the provisioning request,
/// each component at most nine digits.
pub(crate) fn parse_abi_range(s: &str) -> Option<(u64, u64)> {
    let (min, max) = s.split_once('-')?;
    Some((bounded_decimal(min)?, bounded_decimal(max)?))
}

/// `https_url`.
pub(crate) fn is_https_url(s: &str) -> bool {
    if s.len() > 2048 {
        return false;
    }
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    !host.is_empty()
        && all_bytes(host, |b| {
            b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
        })
        && port.is_none_or(|p| (1..=5).contains(&p.len()) && all_bytes(p, |b| b.is_ascii_digit()))
        && path.is_none_or(|p| {
            all_bytes(p, |b| {
                b.is_ascii_alphanumeric() || b"._~%!$&'()*+,;=:@/-".contains(&b)
            })
        })
}

/// One DNS label: 1 to 63 characters of `[a-z0-9-]`, starting and ending with
/// an alphanumeric one; the last label of a name must also start with a
/// letter, which keeps an IP literal from being a host name.
fn is_dns_label(label: &str, last: bool) -> bool {
    let bytes = label.as_bytes();
    let (Some(first), Some(end)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    let alnum = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    bytes.len() <= 63
        && alnum(first)
        && alnum(end)
        && bytes.iter().all(|b| alnum(b) || *b == b'-')
        && (!last || first.is_ascii_lowercase())
}

/// `fetch_url`: the form of every URL root fetches on behalf of a signed
/// statement (channels.json `update_channel.fetch`): https on port 443 (no
/// port, or `:443`), a lowercase DNS name of at least two labels whose last
/// label starts with a letter (never an IP literal), no userinfo, and a path of
/// the schema's character set.
pub(crate) fn is_fetch_url(s: &str) -> bool {
    if s.len() > 2048 {
        return false;
    }
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i..)),
        None => (rest, None),
    };
    let host = authority.strip_suffix(":443").unwrap_or(authority);
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels
            .iter()
            .enumerate()
            .all(|(i, label)| is_dns_label(label, i + 1 == labels.len()))
        && path.is_none_or(|p| {
            all_bytes(p, |b| {
                b.is_ascii_alphanumeric() || b"._~%!$&'()*+,;=:@/-".contains(&b)
            })
        })
}

/// `[a-z0-9]` groups separated by single hyphens (the body of `slug` and
/// `rauc_compatible`).
#[cfg(test)]
fn is_slug_body(s: &str) -> bool {
    s.split('-')
        .all(|w| !w.is_empty() && all_bytes(w, |b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

/// `slug`: lowercase identifier of at most 32 characters.
#[cfg(test)]
pub(crate) fn is_slug(s: &str) -> bool {
    s.len() <= 32 && is_slug_body(s)
}

/// `rauc_compatible`: `suderra-os-<board_profile>`, at most 64 characters.
#[cfg(test)]
pub(crate) fn is_rauc_compatible(s: &str) -> bool {
    s.len() <= 64 && s.strip_prefix("suderra-os-").is_some_and(is_slug_body)
}

/// `mac`: six lowercase hex pairs separated by colons.
#[cfg(test)]
pub(crate) fn is_mac(s: &str) -> bool {
    let pairs: Vec<&str> = s.split(':').collect();
    pairs.len() == 6
        && pairs
            .iter()
            .all(|p| p.len() == 2 && all_bytes(p, is_lower_hex))
}

/// `pci_path`: `DDDD:BB:SS.F` in lowercase hex with a function of 0 to 7.
#[cfg(test)]
pub(crate) fn is_pci_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&i| is_lower_hex(b[i]))
        && (b'0'..=b'7').contains(&b[11])
}

/// `cidr4`: dotted-decimal IPv4 network without leading zeros and a prefix
/// length of 0 to 32; the address as an integer and the prefix length.
#[cfg(test)]
pub(crate) fn parse_cidr4(s: &str) -> Option<(u32, u8)> {
    let (address, prefix) = s.split_once('/')?;
    let prefix = u8::try_from(decimal(prefix)?).ok().filter(|p| *p <= 32)?;
    let mut value = 0u32;
    let mut octets = 0;
    for octet in address.split('.') {
        let octet = u8::try_from(decimal(octet)?).ok()?;
        value = (value << 8) | u32::from(octet);
        octets += 1;
    }
    (octets == 4).then_some((value, prefix))
}

/// `host`: a lowercase fully qualified DNS name or a dotted-decimal address,
/// at most 253 characters.
#[cfg(test)]
pub(crate) fn is_host(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    s.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && all_bytes(l, |b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
                })
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// `device_code`.
pub(crate) fn is_device_code(s: &str) -> bool {
    (1..=50).contains(&s.len())
        && all_bytes(s, |b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Provisioning request nonce: `^[0-9a-f]{32,128}$`.
pub(crate) fn is_nonce(s: &str) -> bool {
    (32..=128).contains(&s.len()) && all_bytes(s, is_lower_hex)
}

/// Canonical RFC 4648 standard base64 with padding and zero trailing bits
/// (`base64`); the decoded bytes when `s` has that form.
pub(crate) fn decode_canonical_base64(s: &str) -> Option<Vec<u8>> {
    // The STANDARD engine requires canonical padding and rejects non-zero
    // trailing bits, which is exactly the schema pattern.
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Canonical base64 of exactly `N` bytes.
pub(crate) fn decode_base64_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    decode_canonical_base64(s)?.try_into().ok()
}

/// `ed25519_public_key`: canonical base64 of a raw 32-byte key.
pub(crate) fn is_ed25519_public_key(s: &str) -> bool {
    s.len() == 44 && decode_base64_array::<32>(s).is_some()
}

/// Standard base64 with padding of `bytes`.
pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// DSSE payloadType form of the envelope schema.
pub(crate) fn is_payload_type(s: &str) -> bool {
    let Some(rest) = s
        .strip_prefix("application/vnd.suderra.")
        .and_then(|r| r.strip_suffix("+json"))
    else {
        return false;
    };
    let Some((kind, version)) = rest.rsplit_once(".v") else {
        return false;
    };
    let version_ok = match version.as_bytes() {
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    version_ok
        && kind.split('-').all(|w| {
            !w.is_empty() && all_bytes(w, |b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// `^CONFIG_[A-Z0-9_]+$`.
pub(crate) fn is_kernel_symbol(s: &str) -> bool {
    s.strip_prefix("CONFIG_").is_some_and(|rest| {
        !rest.is_empty()
            && all_bytes(rest, |b| {
                b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'
            })
    })
}

/// RBAC `tag_id`.
pub(crate) fn is_tag_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && all_bytes(s, |b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

/// PEM certificate form of the trust-anchors x509 anchor.
pub(crate) fn is_pem_certificate(s: &str) -> bool {
    s.strip_prefix("-----BEGIN CERTIFICATE-----\n")
        .and_then(|r| r.strip_suffix("-----END CERTIFICATE-----\n"))
        .is_some_and(|body| {
            !body.is_empty()
                && all_bytes(body, |b| b.is_ascii_alphanumeric() || b"+/=\n".contains(&b))
        })
}

/// Result `reason` form: `^[a-z0-9]+(-[a-z0-9]+)*$`, at most 64 characters.
pub(crate) fn is_reason_code(s: &str) -> bool {
    s.len() <= 64
        && s.split('-').all(|w| {
            !w.is_empty() && all_bytes(w, |b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// Result `statement_type` form: `^suderra\.[a-z0-9-]+\.v[1-9][0-9]*$`.
pub(crate) fn is_statement_type_name(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("suderra.") else {
        return false;
    };
    let Some((kind, version)) = rest.rsplit_once(".v") else {
        return false;
    };
    let version_ok = match version.as_bytes() {
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    version_ok
        && !kind.is_empty()
        && all_bytes(kind, |b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_is_path_safe() {
        for ok in [
            "1.6.0",
            "0.0.0",
            "10.20.30",
            "1.0.0-rc.1",
            "1.0.0-alpha-1.x",
        ] {
            assert!(is_semver(ok), "{ok}");
        }
        for bad in [
            "../../etc",
            "1.6",
            "01.6.0",
            "1.6.0+build",
            "1.6.0-",
            "1.6.0-a..b",
            "1.6.0/x",
            "v1.6.0",
            "",
            &"1".repeat(65),
        ] {
            assert!(!is_semver(bad), "{bad}");
        }
    }

    #[test]
    fn timestamps_and_uuids() {
        assert!(is_timestamp("2026-10-20T12:00:00Z"));
        for bad in [
            "2026-10-20T12:00:00.000Z",
            "2026-10-20T12:00:00+00:00",
            "2026-13-20T12:00:00Z",
            "2026-10-20 12:00:00Z",
        ] {
            assert!(!is_timestamp(bad), "{bad}");
        }
        assert!(is_uuid("7e570000-0000-4000-8000-0000000000d1"));
        assert!(!is_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(!is_uuid("7E570000-0000-4000-8000-0000000000D1"));
        assert!(is_timestamp(&now_timestamp()));
    }

    #[test]
    fn base64_must_be_canonical() {
        assert_eq!(decode_canonical_base64("aGVsbG8=").unwrap(), b"hello");
        assert!(
            decode_canonical_base64("aGVsbG9=").is_none(),
            "non-zero trailing bits"
        );
        assert!(
            decode_canonical_base64("aGVsbG8").is_none(),
            "missing padding"
        );
        assert!(decode_canonical_base64("aGVs bG8=").is_none());
    }

    #[test]
    fn urls_and_payload_types() {
        assert!(is_https_url(
            "https://edge-releases.example.com/agent/1.6.0/suderra-agent-os-1.6.0-revpi-connect4-aarch64.tar.gz"
        ));
        assert!(is_https_url("https://10.0.2.2:8443"));
        for bad in [
            "http://x",
            "https://",
            "https://a b",
            "https://x:123456/",
            "https://x/<",
        ] {
            assert!(!is_https_url(bad), "{bad}");
        }
        assert!(is_payload_type(
            "application/vnd.suderra.edge-release.v1+json"
        ));
        assert!(!is_payload_type(
            "application/vnd.suderra.edge--release.v1+json"
        ));
        assert!(!is_payload_type(
            "application/vnd.suderra.edge-release.v0+json"
        ));
        assert_eq!(parse_abi_range("1-3"), Some((1, 3)));
        assert_eq!(parse_abi_range("01-3"), None);
    }

    #[test]
    fn fetch_urls_are_https_on_443_at_a_dns_name() {
        for ok in [
            "https://artifacts.suderra.example/edge/release.dsse.json",
            "https://artifacts.suderra.example:443/edge/release.dsse.json",
            "https://a.bc",
            "https://artifacts-1.example.com/a%20b/c",
            &format!("https://{}.example.com/x", "a".repeat(63)),
        ] {
            assert!(is_fetch_url(ok), "{ok}");
        }
        let long_label = format!("https://{}.example.com/x", "a".repeat(64));
        let long_path = format!("https://example.com/{}", "a".repeat(2048));
        for bad in [
            "https://10.0.2.2/x",
            "https://10.0.2.2:443/x",
            "https://example.123/x",
            "https://example.com:8443/x",
            "https://example.com:0443/x",
            "https://example.com:/x",
            "https://user@example.com/x",
            "https://Example.com/x",
            "https://example/x",
            "https://-a.example.com/x",
            "https://a-.example.com/x",
            "https://a..example.com/x",
            "https://example.com./x",
            "https://example.com/x?y",
            "https://example.com/x#y",
            "http://example.com/x",
            "https://",
            long_label.as_str(),
            long_path.as_str(),
        ] {
            assert!(!is_fetch_url(bad), "{bad}");
        }
    }

    #[test]
    fn os_version_and_abi_components_have_at_most_nine_digits() {
        assert!(is_os_version("999999999.999999999.999999999"));
        assert!(is_os_version("0.0.0"));
        for bad in [
            "1000000000.0.0",
            "0.1000000000.0",
            "0.0.1000000000",
            "99999999999999999999.0.0",
            "01.0.0",
            "1.0",
            "1.0.0.0",
            "1.0.0-rc1",
        ] {
            assert!(!is_os_version(bad), "{bad}");
        }
        assert_eq!(parse_abi_range("0-999999999"), Some((0, 999_999_999)));
        for bad in [
            "01-2",
            "1-02",
            "1-1000000000",
            "1000000000-1",
            "1",
            "1-",
            "-1",
            "1-2-3",
        ] {
            assert_eq!(parse_abi_range(bad), None, "{bad}");
        }
    }
}
