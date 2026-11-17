use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::cipher::{AesCtr, Ctr, IV_LEN, KEY_LEN};
use crate::config::SECRET_KEY_LEN;

pub const INIT_LEN: usize = 64;
/// Padded intermediate transport, the only one allowed with fake-tls secrets.
pub const TAG_SECURE: [u8; 4] = [0xdd; 4];

const KEYS_START: usize = 8;
const KEYS_END: usize = KEYS_START + KEY_LEN + IV_LEN;
const TAG_POS: usize = 56;
const DC_POS: usize = 60;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InitError {
    #[error("unexpected protocol tag")]
    BadProtoTag,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClientKeys {
    pub dec_key: [u8; KEY_LEN],
    pub dec_iv: [u8; IV_LEN],
    pub enc_key: [u8; KEY_LEN],
    pub enc_iv: [u8; IV_LEN],
}

fn split_key_iv(material: &[u8; KEY_LEN + IV_LEN]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
    let mut key = [0u8; KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    key.copy_from_slice(&material[..KEY_LEN]);
    iv.copy_from_slice(&material[KEY_LEN..]);
    (key, iv)
}

fn key_material(init: &[u8; INIT_LEN]) -> ([u8; KEY_LEN + IV_LEN], [u8; KEY_LEN + IV_LEN]) {
    let mut forward = [0u8; KEY_LEN + IV_LEN];
    forward.copy_from_slice(&init[KEYS_START..KEYS_END]);
    let mut reversed = forward;
    reversed.reverse();
    (forward, reversed)
}

fn hash_with_secret(prekey: &[u8; KEY_LEN], secret: &[u8; SECRET_KEY_LEN]) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(prekey);
    hasher.update(secret);
    hasher.finalize().into()
}

/// Keys as seen by the proxy: `dec` for client→proxy bytes, `enc` for proxy→client bytes.
pub fn derive_client_keys(init: &[u8; INIT_LEN], secret: &[u8; SECRET_KEY_LEN]) -> ClientKeys {
    let (forward, reversed) = key_material(init);
    let (dec_prekey, dec_iv) = split_key_iv(&forward);
    let (enc_prekey, enc_iv) = split_key_iv(&reversed);
    ClientKeys {
        dec_key: hash_with_secret(&dec_prekey, secret),
        dec_iv,
        enc_key: hash_with_secret(&enc_prekey, secret),
        enc_iv,
    }
}

pub struct ClientInit {
    /// Already advanced past the 64-byte init.
    pub dec: AesCtr,
    pub enc: AesCtr,
    pub dc_idx: i16,
    pub keys: ClientKeys,
}

pub fn parse_client_init(
    init: &[u8; INIT_LEN],
    secret: &[u8; SECRET_KEY_LEN],
) -> Result<ClientInit, InitError> {
    let keys = derive_client_keys(init, secret);
    let mut dec = AesCtr::new(&keys.dec_key, &keys.dec_iv);
    let mut plain = *init;
    dec.apply(&mut plain);
    if plain[TAG_POS..TAG_POS + 4] != TAG_SECURE {
        return Err(InitError::BadProtoTag);
    }
    let dc_idx = i16::from_le_bytes([plain[DC_POS], plain[DC_POS + 1]]);
    let enc = AesCtr::new(&keys.enc_key, &keys.enc_iv);
    Ok(ClientInit {
        dec,
        enc,
        dc_idx,
        keys,
    })
}

/// Fixed-size replay-cache key for the init's key material.
pub fn replay_key(init: &[u8; INIT_LEN]) -> [u8; 32] {
    Sha256::digest(&init[KEYS_START..KEYS_END]).into()
}

/// Prefixes a DC would mistake for another transport or for HTTP.
pub fn is_reserved_prefix(init: &[u8; INIT_LEN]) -> bool {
    const RESERVED: [[u8; 4]; 7] = [
        *b"HEAD",
        *b"POST",
        *b"GET ",
        *b"OPTI",
        [0xee; 4],
        [0xdd; 4],
        [0x16, 0x03, 0x01, 0x02],
    ];
    init[0] == 0xef || RESERVED.iter().any(|p| init[..4] == *p) || init[4..8] == [0; 4]
}

pub fn random_init_seed() -> [u8; INIT_LEN] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; INIT_LEN];
    loop {
        rng.fill_bytes(&mut seed);
        if !is_reserved_prefix(&seed) {
            return seed;
        }
    }
}

pub struct UpstreamInit {
    /// Bytes to send to the DC.
    pub wire: [u8; INIT_LEN],
    /// For proxy→DC bytes, already advanced past the init.
    pub enc: AesCtr,
    /// For DC→proxy bytes.
    pub dec: AesCtr,
}

/// Builds the obfuscated2 init sent to a DC. Unlike the client leg, the DC leg
/// uses the raw init bytes as key and IV: no SHA-256 and no secret.
///
/// With `dc_to_proxy` set, those bytes become the key and IV the DC encrypts
/// with. Passing the client's `enc_key`/`enc_iv` makes the DC produce exactly
/// the ciphertext the client expects, so that direction needs no AES here.
pub fn upstream_init(
    seed: [u8; INIT_LEN],
    dc_to_proxy: Option<(&[u8; KEY_LEN], &[u8; IV_LEN])>,
) -> UpstreamInit {
    let mut plain = seed;
    plain[TAG_POS..TAG_POS + 4].copy_from_slice(&TAG_SECURE);
    if let Some((key, iv)) = dc_to_proxy {
        let mut material = [0u8; KEY_LEN + IV_LEN];
        material[..KEY_LEN].copy_from_slice(key);
        material[KEY_LEN..].copy_from_slice(iv);
        material.reverse();
        plain[KEYS_START..KEYS_END].copy_from_slice(&material);
    }

    let (forward, reversed) = key_material(&plain);
    let (enc_key, enc_iv) = split_key_iv(&forward);
    let (dec_key, dec_iv) = split_key_iv(&reversed);
    let mut enc = AesCtr::new(&enc_key, &enc_iv);
    let dec = AesCtr::new(&dec_key, &dec_iv);

    let mut encrypted = plain;
    enc.apply(&mut encrypted);
    let mut wire = plain;
    wire[TAG_POS..].copy_from_slice(&encrypted[TAG_POS..]);
    UpstreamInit { wire, enc, dec }
}

pub struct ClientSide {
    pub wire: [u8; INIT_LEN],
    /// For client→proxy bytes, already advanced past the init.
    pub enc: AesCtr,
    /// For proxy→client bytes.
    pub dec: AesCtr,
}

/// The client's half of the handshake. Used by tests and the load generator.
pub fn client_init(seed: [u8; INIT_LEN], secret: &[u8; SECRET_KEY_LEN], dc_idx: i16) -> ClientSide {
    let mut plain = seed;
    plain[TAG_POS..TAG_POS + 4].copy_from_slice(&TAG_SECURE);
    plain[DC_POS..DC_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());

    let keys = derive_client_keys(&plain, secret);
    let mut enc = AesCtr::new(&keys.dec_key, &keys.dec_iv);
    let dec = AesCtr::new(&keys.enc_key, &keys.enc_iv);

    let mut encrypted = plain;
    enc.apply(&mut encrypted);
    let mut wire = plain;
    wire[TAG_POS..].copy_from_slice(&encrypted[TAG_POS..]);
    ClientSide { wire, enc, dec }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; SECRET_KEY_LEN] = *b"0123456789abcdef";

    fn seed(fill: impl Fn(usize) -> u8) -> [u8; INIT_LEN] {
        let mut out = [0u8; INIT_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = fill(i);
        }
        out
    }

    #[test]
    fn key_derivation_matches_the_definition() {
        let init = seed(|i| i as u8);
        let keys = derive_client_keys(&init, &SECRET);

        let mut dec_input = init[8..40].to_vec();
        dec_input.extend_from_slice(&SECRET);
        assert_eq!(keys.dec_key, <[u8; 32]>::from(Sha256::digest(&dec_input)));
        assert_eq!(keys.dec_iv, init[40..56]);

        let reversed: Vec<u8> = init[8..56].iter().rev().copied().collect();
        let mut enc_input = reversed[..32].to_vec();
        enc_input.extend_from_slice(&SECRET);
        assert_eq!(keys.enc_key, <[u8; 32]>::from(Sha256::digest(&enc_input)));
        assert_eq!(keys.enc_iv, reversed[32..]);
    }

    #[test]
    fn client_and_proxy_agree() {
        for dc_idx in [1, 2, 5, -3, i16::MIN, i16::MAX] {
            let mut client = client_init(seed(|i| (i * 7 + 3) as u8), &SECRET, dc_idx);
            let mut proxy = parse_client_init(&client.wire, &SECRET).unwrap();
            assert_eq!(proxy.dc_idx, dc_idx);

            let mut up = *b"client to proxy payload";
            client.enc.apply(&mut up);
            proxy.dec.apply(&mut up);
            assert_eq!(&up, b"client to proxy payload");

            let mut down = *b"proxy to client payload";
            proxy.enc.apply(&mut down);
            client.dec.apply(&mut down);
            assert_eq!(&down, b"proxy to client payload");
        }
    }

    #[test]
    fn wrong_secret_or_tag_is_rejected() {
        let client = client_init(seed(|i| i as u8 ^ 0x5a), &SECRET, 2);
        assert_eq!(
            parse_client_init(&client.wire, b"another secret!!").err(),
            Some(InitError::BadProtoTag)
        );
        assert_eq!(
            parse_client_init(&[0u8; INIT_LEN], &SECRET).err(),
            Some(InitError::BadProtoTag)
        );
    }

    #[test]
    fn other_transport_tags_are_rejected() {
        for tag in [[0xefu8; 4], [0xee; 4]] {
            let mut plain = seed(|i| i as u8);
            plain[56..60].copy_from_slice(&tag);
            let keys = derive_client_keys(&plain, &SECRET);
            let mut enc = AesCtr::new(&keys.dec_key, &keys.dec_iv);
            let mut wire = plain;
            enc.apply(&mut wire);
            wire[..56].copy_from_slice(&plain[..56]);
            assert_eq!(
                parse_client_init(&wire, &SECRET).err(),
                Some(InitError::BadProtoTag)
            );
        }
    }

    #[test]
    fn reserved_prefixes() {
        let ok = seed(|i| i as u8 + 1);
        assert!(!is_reserved_prefix(&ok));
        for prefix in [
            &b"HEAD"[..],
            b"POST",
            b"GET ",
            b"OPTI",
            &[0xee; 4],
            &[0xdd; 4],
            &[0x16, 0x03, 0x01, 0x02],
            &[0xef],
        ] {
            let mut init = ok;
            init[..prefix.len()].copy_from_slice(prefix);
            assert!(is_reserved_prefix(&init), "{prefix:x?}");
        }
        let mut init = ok;
        init[4..8].fill(0);
        assert!(is_reserved_prefix(&init));
    }

    #[test]
    fn random_seed_avoids_reserved_prefixes() {
        for _ in 0..2000 {
            assert!(!is_reserved_prefix(&random_init_seed()));
        }
    }

    /// What a DC does with the init it receives.
    fn dc_side(wire: &[u8; INIT_LEN]) -> (AesCtr, AesCtr, [u8; INIT_LEN]) {
        let (forward, reversed) = key_material(wire);
        let (dec_key, dec_iv) = split_key_iv(&forward);
        let (enc_key, enc_iv) = split_key_iv(&reversed);
        let mut dec = AesCtr::new(&dec_key, &dec_iv);
        let enc = AesCtr::new(&enc_key, &enc_iv);
        let mut plain = *wire;
        dec.apply(&mut plain);
        (dec, enc, plain)
    }

    #[test]
    fn upstream_init_is_understood_by_a_dc() {
        let s = seed(|i| (i * 3 + 1) as u8);
        let mut up = upstream_init(s, None);
        assert_eq!(up.wire[..56], s[..56]);
        let (mut dc_dec, mut dc_enc, plain) = dc_side(&up.wire);
        assert_eq!(plain[56..60], TAG_SECURE);

        let mut msg = *b"to the dc";
        up.enc.apply(&mut msg);
        dc_dec.apply(&mut msg);
        assert_eq!(&msg, b"to the dc");

        let mut msg = *b"from the dc";
        dc_enc.apply(&mut msg);
        up.dec.apply(&mut msg);
        assert_eq!(&msg, b"from the dc");
    }

    #[test]
    fn fast_mode_makes_the_dc_encrypt_for_the_client() {
        let mut client = client_init(seed(|i| (i * 11) as u8 | 1), &SECRET, 2);
        let proxy = parse_client_init(&client.wire, &SECRET).unwrap();
        let s = seed(|i| (i * 5 + 9) as u8);
        let up = upstream_init(s, Some((&proxy.keys.enc_key, &proxy.keys.enc_iv)));
        assert_eq!(up.wire[..8], s[..8]);

        let (_, mut dc_enc, plain) = dc_side(&up.wire);
        assert_eq!(plain[56..60], TAG_SECURE);

        // No proxy cipher is applied between the DC and the client.
        let mut msg = *b"dc ciphertext goes straight through";
        dc_enc.apply(&mut msg);
        client.dec.apply(&mut msg);
        assert_eq!(&msg, b"dc ciphertext goes straight through");
    }

    #[test]
    fn replay_key_covers_exactly_the_key_material() {
        let a = seed(|i| i as u8);
        let mut b = a;
        b[0] ^= 1;
        b[63] ^= 1;
        assert_eq!(replay_key(&a), replay_key(&b));
        b[8] ^= 1;
        assert_ne!(replay_key(&a), replay_key(&b));
        let mut c = a;
        c[55] ^= 1;
        assert_ne!(replay_key(&a), replay_key(&c));
    }
}
