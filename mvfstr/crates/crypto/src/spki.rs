/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! DER SubjectPublicKeyInfo (RFC 5280): split into the contents of its AlgorithmIdentifier and
//! its key bits, as rustls-webpki splits it, and built back from them. Also the RSAPublicKey
//! (RFC 8017) in the key bits of an RSA key, read as ring reads it.

/// The DER tag of an INTEGER.
pub(crate) const INTEGER: u8 = 0x02;

/// The DER tag of a SEQUENCE.
pub(crate) const SEQUENCE: u8 = 0x30;

/// The DER tag of a BIT STRING.
const BIT_STRING: u8 = 0x03;

/// Returns the contents of the AlgorithmIdentifier of `spki` and its subjectPublicKey bits, or
/// `None` unless `spki` is exactly one SEQUENCE of a SEQUENCE and a BIT STRING with zero unused
/// bits.
pub(crate) fn split(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body, rest) = element(spki, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (algorithm, body) = element(body, SEQUENCE)?;
    let (bits, rest) = element(body, BIT_STRING)?;
    if !rest.is_empty() {
        return None;
    }
    match bits.split_first()? {
        (0, key) => Some((algorithm, key)),
        _ => None,
    }
}

/// Builds the DER SubjectPublicKeyInfo with AlgorithmIdentifier contents `algorithm` and key bits
/// `key`.
pub(crate) fn build(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    let mut algorithm_id = Vec::with_capacity(algorithm.len() + 4);
    push_element(&mut algorithm_id, SEQUENCE, &[algorithm]);
    let mut bits = Vec::with_capacity(key.len() + 5);
    push_element(&mut bits, BIT_STRING, &[&[0], key]);
    let mut spki = Vec::with_capacity(algorithm_id.len() + bits.len() + 4);
    push_element(&mut spki, SEQUENCE, &[&algorithm_id, &bits]);
    spki
}

/// Returns the modulus of the DER RSAPublicKey `key`, without a leading zero byte, or `None`
/// unless `key` is exactly one SEQUENCE of two positive INTEGERs in minimal form. ring's
/// `parse_public_key` takes the same encodings; OpenSSL's parser also takes trailing data,
/// long-form lengths and leading zeros, and reads a negative number as positive.
pub(crate) fn rsa_modulus(key: &[u8]) -> Option<&[u8]> {
    let (body, rest) = element(key, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (modulus, body) = positive_integer(body)?;
    let (_exponent, rest) = positive_integer(body)?;
    rest.is_empty().then_some(modulus)
}

/// Returns the value of the positive DER INTEGER at the start of `input`, without a leading zero
/// byte, and what follows it.
fn positive_integer(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (contents, rest) = element(input, INTEGER)?;
    let value = match contents {
        [0, 0x80..=0xff, ..] => &contents[1..],
        [0x01..=0x7f, ..] => contents,
        // Empty, zero, negative, or with an unneeded zero byte.
        _ => return None,
    };
    Some((value, rest))
}

/// Returns the contents of the DER element with tag `tag` at the start of `input`, and what
/// follows it. Lengths must be minimal and below 65536, which is enough for a
/// SubjectPublicKeyInfo.
fn element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, rest) = input.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            (len >= 0x80).then_some((usize::from(len), rest))?
        }
        0x82 => {
            let (len, rest) = rest.split_first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*len));
            (len >= 0x100).then_some((len, rest))?
        }
        _ => return None,
    };
    rest.split_at_checked(len)
}

/// Appends the DER element with tag `tag` whose contents are `parts`, concatenated.
fn push_element(out: &mut Vec<u8>, tag: u8, parts: &[&[u8]]) {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    out.push(tag);
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let bytes = len.to_be_bytes();
            let significant = &bytes[bytes.iter().take_while(|&&b| b == 0).count()..];
            // At most `size_of::<usize>()` bytes, so the count fits the low 7 bits.
            out.push(0x80 | significant.len() as u8);
            out.extend_from_slice(significant);
        }
    }
    for part in parts {
        out.extend_from_slice(part);
    }
}

/// Returns the DER element with tag `tag` whose contents are `parts`, concatenated.
#[cfg(test)]
pub(crate) fn der(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    push_element(&mut out, tag, parts);
    out
}

/// Builds the DER RSAPublicKey with modulus `n` and public exponent `e`, both big-endian
/// without leading zeros.
#[cfg(test)]
pub(crate) fn rsa_public_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    let integer = |value: &[u8]| {
        let sign: &[u8] = if value[0] >= 0x80 { &[0] } else { &[] };
        der(INTEGER, &[sign, value])
    };
    der(SEQUENCE, &[&integer(n), &integer(e)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testcerts::RSA_4096_SPKI;
    use crate::testcerts::RSA_8192_SPKI;
    use crate::testdata::unhex;

    /// rsaEncryption with its NULL parameter.
    const RSA_ENCRYPTION: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];

    /// id-Ed25519.
    const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

    #[test]
    fn rsa_spkis_with_two_byte_lengths_split_and_build_back() {
        for (spki, key_len) in [(unhex(RSA_4096_SPKI), 526), (unhex(RSA_8192_SPKI), 1038)] {
            assert_eq!(spki[1], 0x82);
            let (algorithm, key) = split(&spki).unwrap();
            assert_eq!(algorithm, RSA_ENCRYPTION);
            assert_eq!(key.len(), key_len);
            assert_eq!(build(algorithm, key), spki);
        }
    }

    #[test]
    fn short_and_one_byte_lengths_build_and_split_back() {
        for key_len in [0, 1, 32, 0x7a, 0x7b, 0x7f, 0x80, 0xfe, 0xff, 0x100, 0x1234] {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let spki = build(ED25519, &key);
            assert_eq!(split(&spki), Some((ED25519, &key[..])), "{key_len}");
        }
        let ed25519 = build(ED25519, &[7; 32]);
        let mut expected = vec![0x30, 0x2a, 0x30, 0x05];
        expected.extend_from_slice(ED25519);
        expected.extend_from_slice(&[0x03, 0x21, 0x00]);
        expected.extend_from_slice(&[7; 32]);
        assert_eq!(ed25519, expected);
    }

    #[test]
    fn malformed_spkis_are_rejected() {
        let good = build(ED25519, &[7; 32]);
        assert!(split(&good).is_some());
        let with = |index: usize, value: u8| {
            let mut spki = good.clone();
            spki[index] = value;
            spki
        };
        let mut trailing = good.clone();
        trailing.push(0);
        let mut inner_trailing = good.clone();
        inner_trailing.push(0);
        inner_trailing[1] += 1;
        let unused_bits = with(4 + ED25519.len() + 2, 1);
        let cases: [(&str, Vec<u8>); 10] = [
            ("non-zero unused bits", unused_bits),
            ("trailing data", trailing),
            ("trailing data in the SEQUENCE", inner_trailing),
            ("outer tag", with(0, 0x31)),
            ("algorithm tag", with(2, 0x31)),
            ("key tag", with(4 + ED25519.len(), 0x04)),
            ("truncated", good[..good.len() - 1].to_vec()),
            (
                "non-minimal length",
                [&[0x30, 0x81, 0x2a][..], &good[2..]].concat(),
            ),
            (
                "indefinite length",
                [&[0x30, 0x80][..], &good[2..], &[0, 0]].concat(),
            ),
            ("empty", Vec::new()),
        ];
        for (what, spki) in cases {
            assert_eq!(split(&spki), None, "{what}");
        }
        let no_bits = [
            0x30, 0x09, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x00,
        ];
        assert_eq!(
            split(&no_bits),
            None,
            "a BIT STRING without its unused-bits byte"
        );
    }

    #[test]
    fn rsa_public_keys_give_their_modulus() {
        let n = [0xc5; 256];
        let key = rsa_public_key(&n, &[1, 0, 1]);
        assert_eq!(
            &key[..9],
            &[0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00]
        );
        assert_eq!(rsa_modulus(&key), Some(&n[..]));
        assert_eq!(
            rsa_modulus(&rsa_public_key(&[0x45, 1], &[3])),
            Some(&[0x45, 1][..])
        );
        for (spki, n_len) in [(unhex(RSA_4096_SPKI), 512), (unhex(RSA_8192_SPKI), 1024)] {
            let (_, key) = split(&spki).unwrap();
            assert_eq!(rsa_modulus(key).map(<[u8]>::len), Some(n_len));
        }
    }

    #[test]
    fn malformed_rsa_public_keys_are_rejected() {
        let integer = |contents: &[u8]| der(INTEGER, &[contents]);
        let key = |integers: &[&[u8]]| der(SEQUENCE, integers);
        let n = [&[0][..], &[0xc5; 256]].concat();
        let (n, e) = (integer(&n), integer(&[1, 0, 1]));
        let good = key(&[&n, &e]);
        assert!(rsa_modulus(&good).is_some());
        let cases: [(&str, Vec<u8>); 15] = [
            ("trailing data", [&good[..], &[0]].concat()),
            ("a third INTEGER", key(&[&n, &e, &e])),
            ("one INTEGER", key(&[&n])),
            ("no INTEGER", key(&[])),
            ("a negative modulus", key(&[&integer(&[0xc5; 256]), &e])),
            ("a negative exponent", key(&[&n, &integer(&[0x81])])),
            ("an unneeded zero byte", key(&[&n, &integer(&[0, 1, 0, 1])])),
            ("a zero exponent", key(&[&n, &integer(&[0])])),
            ("an empty INTEGER", key(&[&n, &integer(&[])])),
            (
                "a BIT STRING for an INTEGER",
                key(&[&n, &der(BIT_STRING, &[&[1, 0, 1]])]),
            ),
            ("an outer SET", [&[0x31][..], &good[1..]].concat()),
            (
                "a long-form length",
                [&[0x30, 0x83, 0x00][..], &good[2..]].concat(),
            ),
            (
                "an indefinite length",
                [&[0x30, 0x80][..], &n, &e, &[0, 0]].concat(),
            ),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("empty", Vec::new()),
        ];
        for (what, key) in cases {
            assert_eq!(rsa_modulus(&key), None, "{what}");
        }
    }
}
