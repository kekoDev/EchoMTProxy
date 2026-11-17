//! Known-answer tests against vectors produced by alexbers/mtprotoproxy.
//! Regenerate with `tests/vectors/gen_vectors.py`.

use echo_mtproxy::cipher::Ctr;
use echo_mtproxy::config::Secret;
use echo_mtproxy::obfs2;
use echo_mtproxy::tls::{self, SkewPolicy};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;

const SKEW: SkewPolicy = SkewPolicy {
    behind_secs: 600,
    ahead_secs: 1200,
    accept_uptime: true,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/mtprotoproxy.json")).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn array<const N: usize>(value: &Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn secrets(v: &Value) -> Vec<(String, Secret)> {
    let domain = v["domain"].as_str().unwrap();
    v["secrets"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(user, key)| {
            let secret = Secret {
                key: array(key),
                domain: domain.to_owned(),
            };
            (user.clone(), secret)
        })
        .collect()
}

fn keystream(cipher: &mut impl Ctr) -> Vec<u8> {
    let mut out = vec![0u8; 48];
    cipher.apply(&mut out);
    out
}

#[test]
fn client_hello_digest_matches_reference() {
    let v = vectors();
    let now = v["now"].as_u64().unwrap();
    let named = secrets(&v);
    let all: Vec<Secret> = named.iter().map(|(_, s)| s.clone()).collect();
    let cases = v["handshakes"].as_array().unwrap();
    assert!(cases.len() >= 5);

    for case in cases {
        let record = bytes(&case["client_hello"]);
        let hello = tls::verify_client_hello(&record, &all, now, &SKEW).unwrap();
        assert_eq!(named[hello.secret_index].0, case["user"].as_str().unwrap());
        assert_eq!(
            u64::from(hello.timestamp),
            case["timestamp"].as_u64().unwrap()
        );
        assert_eq!(hello.sni, v["domain"].as_str());

        // Re-signing the reference hello reproduces its random byte for byte.
        let mut resigned = record.clone();
        resigned[11..43].fill(0);
        tls::sign_client_hello(&mut resigned, &all[hello.secret_index].key, hello.timestamp);
        assert_eq!(resigned, record);
    }
}

#[test]
fn server_hello_matches_reference() {
    let v = vectors();
    let now = v["now"].as_u64().unwrap();
    let all: Vec<Secret> = secrets(&v).into_iter().map(|(_, s)| s).collect();

    for case in v["handshakes"].as_array().unwrap() {
        let record = bytes(&case["client_hello"]);
        let reference = bytes(&case["server_response"]);
        let hello = tls::verify_client_hello(&record, &all, now, &SKEW).unwrap();
        let key = &all[hello.secret_index].key;

        assert!(tls::verify_server_hello(
            key,
            &hello.client_random,
            &reference
        ));

        let cert_len = reference.len() - 138;
        let mut ours = tls::build_server_hello(
            key,
            &hello.client_random,
            hello.session_id,
            cert_len,
            &mut StdRng::seed_from_u64(1),
        );
        assert_eq!(ours.len(), reference.len());
        assert!(tls::verify_server_hello(key, &hello.client_random, &ours));

        // Everything except the digest, the key share and the random payload is fixed.
        let mut theirs = reference.clone();
        for buf in [&mut ours, &mut theirs] {
            buf[11..43].fill(0);
            buf[89..121].fill(0);
            buf[138..].fill(0);
        }
        assert_eq!(ours, theirs);
    }
}

#[test]
fn obfs2_client_keys_match_reference() {
    let v = vectors();
    let named = secrets(&v);

    for case in v["handshakes"].as_array().unwrap() {
        let user = case["user"].as_str().unwrap();
        let secret = &named.iter().find(|(name, _)| name == user).unwrap().1;
        let init: [u8; 64] = array(&case["obfs2_init"]);

        let mut parsed = obfs2::parse_client_init(&init, &secret.key).unwrap();
        assert_eq!(i64::from(parsed.dc_idx), case["dc_idx"].as_i64().unwrap());
        assert_eq!(case["proto_tag"].as_str().unwrap(), "dddddddd");

        let mut enc_key_iv = parsed.keys.enc_key.to_vec();
        enc_key_iv.extend_from_slice(&parsed.keys.enc_iv);
        assert_eq!(enc_key_iv, bytes(&case["enc_key_iv"]));

        assert_eq!(keystream(&mut parsed.dec), bytes(&case["dec_keystream"]));
        assert_eq!(keystream(&mut parsed.enc), bytes(&case["enc_keystream"]));

        for (_, other) in named.iter().filter(|(name, _)| name != user) {
            assert!(obfs2::parse_client_init(&init, &other.key).is_err());
        }
    }
}

#[test]
fn obfs2_upstream_init_matches_reference() {
    let v = vectors();
    let cases = v["upstream"].as_array().unwrap();
    assert!(cases.iter().any(|c| c["reuse_key_iv"].is_null()));
    assert!(cases.iter().any(|c| !c["reuse_key_iv"].is_null()));

    for case in cases {
        let seed: [u8; 64] = array(&case["seed"]);
        let reuse = (!case["reuse_key_iv"].is_null()).then(|| bytes(&case["reuse_key_iv"]));
        let reuse_parts = reuse.as_ref().map(|material| {
            let key: [u8; 32] = material[..32].try_into().unwrap();
            let iv: [u8; 16] = material[32..].try_into().unwrap();
            (key, iv)
        });

        let mut up = obfs2::upstream_init(seed, reuse_parts.as_ref().map(|(k, i)| (k, i)));
        assert_eq!(up.wire.to_vec(), bytes(&case["wire"]));
        assert_eq!(keystream(&mut up.enc), bytes(&case["enc_keystream"]));
        assert_eq!(keystream(&mut up.dec), bytes(&case["dec_keystream"]));
        assert!(!obfs2::is_reserved_prefix(&up.wire));
    }
}

#[test]
fn fast_mode_upstream_key_is_the_client_enc_key() {
    let v = vectors();
    let handshakes = v["handshakes"].as_array().unwrap();
    let reused: Vec<&Value> = v["upstream"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| !c["reuse_key_iv"].is_null())
        .collect();
    assert_eq!(handshakes.len(), reused.len());
    for (handshake, upstream) in handshakes.iter().zip(reused) {
        assert_eq!(handshake["enc_key_iv"], upstream["reuse_key_iv"]);
        // The DC→proxy keystream equals the proxy→client one, so bytes pass through.
        assert_eq!(handshake["enc_keystream"], upstream["dec_keystream"]);
    }
}
