use ctr::cipher::{KeyIvInit, StreamCipher};

pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;

/// AES-256-CTR keystream applied in place. Encryption and decryption are the same operation.
pub trait Ctr {
    fn apply(&mut self, buf: &mut [u8]);
}

pub struct RustCryptoCtr(ctr::Ctr128BE<aes::Aes256>);

impl RustCryptoCtr {
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self(ctr::Ctr128BE::<aes::Aes256>::new(key.into(), iv.into()))
    }
}

impl Ctr for RustCryptoCtr {
    #[inline]
    fn apply(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

/// Backend selected at startup. An enum rather than `Box<dyn Ctr>` keeps the
/// relay loop free of virtual calls and of a per-connection heap allocation.
pub enum AesCtr {
    RustCrypto(RustCryptoCtr),
}

impl AesCtr {
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self::RustCrypto(RustCryptoCtr::new(key, iv))
    }
}

impl Ctr for AesCtr {
    #[inline]
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::RustCrypto(c) => c.apply(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // NIST SP 800-38A F.5.5 (CTR-AES256.Encrypt).
    const KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                         30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    const CIPHER: &str = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5\
                          2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";

    fn nist_cipher() -> AesCtr {
        let key: [u8; KEY_LEN] = hex::decode(KEY).unwrap().try_into().unwrap();
        let iv: [u8; IV_LEN] = hex::decode(IV).unwrap().try_into().unwrap();
        AesCtr::new(&key, &iv)
    }

    #[test]
    fn matches_nist_vector() {
        let mut buf = hex::decode(PLAIN).unwrap();
        nist_cipher().apply(&mut buf);
        assert_eq!(hex::encode(buf), CIPHER);
    }

    #[test]
    fn keystream_is_continuous_across_calls() {
        let mut buf = hex::decode(PLAIN).unwrap();
        let mut cipher = nist_cipher();
        let (a, rest) = buf.split_at_mut(7);
        let (b, c) = rest.split_at_mut(30);
        cipher.apply(a);
        cipher.apply(b);
        cipher.apply(&mut []);
        cipher.apply(c);
        assert_eq!(hex::encode(buf), CIPHER);
    }

    #[test]
    fn counter_carries_across_the_full_128_bits() {
        let key = [7u8; KEY_LEN];
        let mut wrapped = AesCtr::new(&key, &[0xff; IV_LEN]);
        let mut zero = AesCtr::new(&key, &[0; IV_LEN]);
        let mut a = [0u8; 32];
        let mut b = [0u8; 16];
        wrapped.apply(&mut a);
        zero.apply(&mut b);
        assert_eq!(a[16..], b);
    }

    proptest! {
        #[test]
        fn encrypt_then_decrypt_round_trips(
            key in any::<[u8; KEY_LEN]>(),
            iv in any::<[u8; IV_LEN]>(),
            data in proptest::collection::vec(any::<u8>(), 0..4096),
            split in any::<prop::sample::Index>(),
        ) {
            let mut buf = data.clone();
            AesCtr::new(&key, &iv).apply(&mut buf);
            let mut dec = AesCtr::new(&key, &iv);
            let at = split.index(buf.len() + 1);
            let (head, tail) = buf.split_at_mut(at);
            dec.apply(head);
            dec.apply(tail);
            prop_assert_eq!(buf, data);
        }
    }
}
