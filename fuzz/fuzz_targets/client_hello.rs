#![no_main]

use echo_mtproxy::config::Secret;
use echo_mtproxy::tls::{self, HelloError, SkewPolicy};
use libfuzzer_sys::fuzz_target;

// Same clock and keys as tests/vectors, so the seed hello from mtprotoproxy verifies.
const NOW: u64 = 1_800_000_000;
const KEYS: [[u8; 16]; 2] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90,
    ],
];
const SKEW: SkewPolicy = SkewPolicy {
    behind_secs: 600,
    ahead_secs: 1200,
    accept_uptime: true,
};

/// Minimal deterministic generator; the fake certificate bytes do not matter here.
struct Counter(u64);

impl rand_core::RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = (self.next_u64() >> 56) as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn check_accepted(record: &[u8], secrets: &[Secret]) {
    match tls::verify_client_hello(record, secrets, NOW, &SKEW) {
        Ok(hello) => {
            assert!(hello.secret_index < secrets.len());
            assert!(hello.session_id.len() <= 32);
            assert_eq!(hello.client_random[..], record[11..43]);
            assert!(SKEW.allows(NOW, hello.timestamp));
            assert_eq!(hello.sni, tls::client_hello_sni(record));

            let key = &secrets[hello.secret_index].key;
            let cert_len = 1024 + usize::from(record[record.len() - 1]) * 8;
            let response = tls::build_server_hello(
                key,
                &hello.client_random,
                hello.session_id,
                cert_len,
                &mut Counter(1),
            );
            assert_eq!(response.len(), 106 + hello.session_id.len() + cert_len);
            assert!(tls::verify_server_hello(key, &hello.client_random, &response));
        }
        Err(HelloError::BadTimestamp { .. }) | Err(HelloError::BadDigest) => {}
        Err(HelloError::Malformed) => assert!(tls::parse_client_hello(record).is_err()),
    }
}

fuzz_target!(|data: &[u8]| {
    let secrets = KEYS.map(|key| Secret {
        key,
        domain: "www.example.com".to_owned(),
    });

    // Raw input: almost always rejected, must never panic.
    let _ = tls::client_hello_sni(data);
    check_accepted_or_rejected(data, &secrets);

    // Framed and signed input: gets past the size, framing and digest checks so
    // the session id, SNI and timestamp handling see arbitrary bytes.
    if data.len() >= 4 {
        let key = &secrets[usize::from(data[0] & 1)].key;
        let timestamp = match data[1] % 3 {
            0 => NOW as u32,
            1 => u32::from_le_bytes([data[2], data[3], 0, 0]),
            _ => (NOW as u32).wrapping_add(u32::from(data[2]) * 16).wrapping_sub(2048),
        };
        let mut record = vec![0x16, 0x03, 0x01, 0, 0, 0x01];
        record.extend_from_slice(&data[4..]);
        if record.len() < 517 {
            record.resize(517, 0);
        }
        record.truncate(5 + 16384);
        let len = (record.len() - 5) as u16;
        record[3..5].copy_from_slice(&len.to_be_bytes());
        tls::sign_client_hello(&mut record, key, timestamp);

        match tls::verify_client_hello(&record, &secrets, NOW, &SKEW) {
            // A signed hello can only fail on structure or on its timestamp.
            Err(HelloError::BadDigest) => panic!("signed hello failed the digest check"),
            Err(HelloError::Malformed) => assert!(record[43] > 32),
            Err(HelloError::BadTimestamp { skew_secs }) => {
                assert!(!SKEW.allows(NOW, timestamp));
                assert_eq!(skew_secs, i64::from(timestamp) - NOW as i64);
            }
            Ok(hello) => assert_eq!(hello.timestamp, timestamp),
        }
        check_accepted(&record, &secrets);
    }
});

fn check_accepted_or_rejected(record: &[u8], secrets: &[Secret]) {
    if tls::parse_client_hello(record).is_ok() {
        check_accepted(record, secrets);
    } else {
        assert!(tls::verify_client_hello(record, secrets, NOW, &SKEW).is_err());
    }
}
