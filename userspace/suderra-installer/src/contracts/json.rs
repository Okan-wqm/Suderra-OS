// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Strict JSON gate of the edge contract (statements.json `dsse.json`).
//!
//! Every JSON document of the contract must be UTF-8 without a byte order
//! mark, a top-level object, free of duplicate member names, carry only
//! integers of the form `-?(0|[1-9][0-9]*)` with a magnitude of at most
//! 2^53-1, and pair every UTF-16 surrogate escape. serde_json alone accepts
//! duplicate members in maps and fractional or huge numbers, so this scanner
//! runs before any typed parse; a violation is `payload-json-invalid` for a
//! verified payload and `envelope-invalid` for an envelope.

use std::collections::HashSet;

/// Largest integer magnitude a contract document may carry (2^53-1).
pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Nesting bound: every contract document is at most a handful of levels
/// deep, and the scanner runs on unauthenticated envelopes, so recursion is
/// capped well below the stack limit.
const MAX_DEPTH: usize = 64;

/// Checks `bytes` against the contract's strict JSON rules.
pub(crate) fn check_strict_object(bytes: &[u8]) -> Result<(), String> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err("byte order mark".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    let mut scanner = Scanner {
        bytes: text.as_bytes(),
        pos: 0,
    };
    scanner.skip_ws();
    if scanner.peek() != Some(b'{') {
        return Err("top-level value is not an object".into());
    }
    scanner.value(0)?;
    scanner.skip_ws();
    if scanner.pos != scanner.bytes.len() {
        return Err(scanner.error("trailing data"));
    }
    Ok(())
}

struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Scanner<'_> {
    fn error(&self, message: &str) -> String {
        format!("{message} at byte {}", self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", byte as char)))
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting too deep"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(drop),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("invalid token")),
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn number(&mut self) -> Result<(), String> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let start = self.pos;
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.error("invalid number")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(self.error("number with a fraction or an exponent"));
        }
        let digits = &self.bytes[start..self.pos];
        let mut magnitude: u64 = 0;
        for digit in digits {
            magnitude = magnitude
                .checked_mul(10)
                .and_then(|m| m.checked_add(u64::from(digit - b'0')))
                .filter(|m| *m <= MAX_SAFE_INTEGER)
                .ok_or_else(|| self.error("integer beyond 2^53-1"))?;
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.pos + 4;
        let chunk = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| self.error("truncated \\u escape"))?;
        let text = std::str::from_utf8(chunk).map_err(|_| self.error("invalid \\u escape"))?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(self.error("invalid \\u escape"));
        }
        let value = u32::from_str_radix(text, 16).map_err(|_| self.error("invalid \\u escape"))?;
        self.pos = end;
        Ok(value)
    }

    /// Scans one string and returns its decoded value.
    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| self.error("unterminated string"))?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = self
                        .peek()
                        .ok_or_else(|| self.error("unterminated escape"))?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            let scalar = match unit {
                                0xD800..=0xDBFF => {
                                    if !self.bytes[self.pos..].starts_with(b"\\u") {
                                        return Err(self.error("unpaired high surrogate"));
                                    }
                                    self.pos += 2;
                                    let low = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&low) {
                                        return Err(self.error("unpaired high surrogate"));
                                    }
                                    0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                                }
                                0xDC00..=0xDFFF => {
                                    return Err(self.error("unpaired low surrogate"));
                                }
                                other => other,
                            };
                            out.push(
                                char::from_u32(scalar)
                                    .ok_or_else(|| self.error("invalid scalar value"))?,
                            );
                        }
                        _ => return Err(self.error("invalid escape")),
                    }
                }
                0x00..=0x1F => return Err(self.error("control character in string")),
                _ => {
                    // The input is valid UTF-8 (checked up front), so copy one
                    // whole scalar value.
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| self.error("not UTF-8"))?;
                    let ch = rest
                        .chars()
                        .next()
                        .ok_or_else(|| self.error("unterminated string"))?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), String> {
        self.expect(b'{')?;
        let mut names = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected member name"));
            }
            let name = self.string()?;
            if !names.insert(name.clone()) {
                return Err(self.error(&format!("duplicate member \"{name}\"")));
            }
            self.skip_ws();
            self.expect(b':')?;
            self.value(depth + 1)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), String> {
        self.expect(b'[')?;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.value(depth + 1)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_contract_shaped_objects() {
        for ok in [
            r#"{}"#,
            r#"{"a":1,"b":[true,false,null],"c":{"d":"é😀"}}"#,
            " {\"n\": -9007199254740991}\n",
            r#"{"z":0,"m":-0}"#,
        ] {
            check_strict_object(ok.as_bytes()).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
    }

    #[test]
    fn rejects_every_rule_violation() {
        for bad in [
            "\u{feff}{}",
            "[]",
            "\"s\"",
            r#"{"a":1,"a":2}"#,
            r#"{"o":{"x":1,"x":1}}"#,
            r#"{"n":1.0}"#,
            r#"{"n":1e0}"#,
            r#"{"n":9007199254740992}"#,
            r#"{"n":01}"#,
            r#"{"s":"\ud800"}"#,
            r#"{"s":"\udc00"}"#,
            r#"{"s":"\ud800A"}"#,
            "{\"s\":\"\u{1}\"}",
            r#"{"a":1} x"#,
            r#"{"a":1,}"#,
            r#"{"a":tru}"#,
        ] {
            assert!(
                check_strict_object(bad.as_bytes()).is_err(),
                "{bad:?} accepted"
            );
        }
        assert!(check_strict_object(&[b'{', b'"', 0xff, b'"', b':', b'1', b'}']).is_err());
    }

    #[test]
    fn caps_nesting_depth() {
        let deep = format!(
            "{}{}",
            "{\"a\":".repeat(100),
            "1".to_owned() + &"}".repeat(100)
        );
        assert!(check_strict_object(deep.as_bytes()).is_err());
    }
}
