#![no_main]

use echo_mtproxy::cipher::Ctr;
use echo_mtproxy::obfs2::{self, INIT_LEN, TAG_SECURE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < INIT_LEN + 16 {
        return;
    }
    let mut init = [0u8; INIT_LEN];
    init.copy_from_slice(&data[..INIT_LEN]);
    let mut secret = [0u8; 16];
    secret.copy_from_slice(&data[INIT_LEN..INIT_LEN + 16]);
    let rest = &data[INIT_LEN + 16..];

    // Arbitrary bytes as a client init: parse, or reject, without panicking.
    let _ = obfs2::replay_key(&init);
    let _ = obfs2::is_reserved_prefix(&init);
    let keys = obfs2::derive_client_keys(&init, &secret);
    if let Ok(parsed) = obfs2::parse_client_init(&init, &secret) {
        assert!(parsed.keys == keys);
    }

    // Arbitrary bytes as a client's seed: the proxy must parse what the client
    // builds, recover the DC index, and agree on both stream ciphers.
    let dc_idx = i16::from_le_bytes([data[0], data[1]]);
    let mut client = obfs2::client_init(init, &secret, dc_idx);
    assert_eq!(client.wire[..56], init[..56]);
    let mut proxy = match obfs2::parse_client_init(&client.wire, &secret) {
        Ok(proxy) => proxy,
        Err(err) => panic!("proxy rejected a well-formed init: {err}"),
    };
    assert_eq!(proxy.dc_idx, dc_idx);

    let mut up = rest.to_vec();
    client.enc.apply(&mut up);
    proxy.dec.apply(&mut up);
    assert_eq!(up, rest);
    let mut down = rest.to_vec();
    proxy.enc.apply(&mut down);
    client.dec.apply(&mut down);
    assert_eq!(down, rest);

    // Upstream init with fresh keys and with the client's keys (fast mode):
    // a DC decrypting it must find the transport tag.
    for reuse in [None, Some((&proxy.keys.enc_key, &proxy.keys.enc_iv))] {
        let upstream = obfs2::upstream_init(init, reuse);
        assert_eq!(upstream.wire[..8], init[..8]);
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&upstream.wire[8..40]);
        iv.copy_from_slice(&upstream.wire[40..56]);
        let mut plain = upstream.wire;
        echo_mtproxy::cipher::AesCtr::new(&key, &iv).apply(&mut plain);
        assert_eq!(plain[56..60], TAG_SECURE);
        if let Some((enc_key, enc_iv)) = reuse {
            let mut material = upstream.wire[8..56].to_vec();
            material.reverse();
            assert_eq!(material[..32], enc_key[..]);
            assert_eq!(material[32..], enc_iv[..]);
        }
    }
});
