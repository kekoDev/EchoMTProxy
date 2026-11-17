use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::Context;
use rand::RngCore;
use serde::Deserialize;

pub const SECRET_KEY_LEN: usize = 16;
const FAKE_TLS_PREFIX: u8 = 0xee;
const SECURE_PREFIX: u8 = 0xdd;
const MAX_DOMAIN_LEN: usize = 253;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    #[error("secret is not valid hex")]
    NotHex,
    #[error("classic secrets are not supported, use a fake-tls (ee) secret")]
    Classic,
    #[error("secure (dd) secrets are not supported, use a fake-tls (ee) secret")]
    Secure,
    #[error("secret must start with ee")]
    BadPrefix,
    #[error("secret is too short: expected ee + 32 hex chars + hex domain")]
    TooShort,
    #[error("secret has no domain")]
    NoDomain,
    #[error("secret domain is not a valid hostname")]
    BadDomain,
}

/// A fake-tls (`ee`) secret: 16-byte key plus the domain used as SNI and mask target.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    pub key: [u8; SECRET_KEY_LEN],
    pub domain: String,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("key", &"<redacted>")
            .field("domain", &self.domain)
            .finish()
    }
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= MAX_DOMAIN_LEN
        && domain
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

impl Secret {
    pub fn parse(text: &str) -> Result<Self, SecretError> {
        let raw = hex::decode(text.trim()).map_err(|_| SecretError::NotHex)?;
        match (raw.first(), raw.len()) {
            (_, SECRET_KEY_LEN) => return Err(SecretError::Classic),
            (Some(&SECURE_PREFIX), 17) => return Err(SecretError::Secure),
            (Some(&FAKE_TLS_PREFIX), _) => {}
            _ => return Err(SecretError::BadPrefix),
        }
        let body = &raw[1..];
        if body.len() < SECRET_KEY_LEN {
            return Err(SecretError::TooShort);
        }
        let (key, domain) = body.split_at(SECRET_KEY_LEN);
        if domain.is_empty() {
            return Err(SecretError::NoDomain);
        }
        let domain = std::str::from_utf8(domain).map_err(|_| SecretError::BadDomain)?;
        if !valid_domain(domain) {
            return Err(SecretError::BadDomain);
        }
        let mut out = [0u8; SECRET_KEY_LEN];
        out.copy_from_slice(key);
        Ok(Self {
            key: out,
            domain: domain.to_owned(),
        })
    }

    pub fn generate(domain: &str) -> Result<Self, SecretError> {
        if !valid_domain(domain) {
            return Err(SecretError::BadDomain);
        }
        let mut key = [0u8; SECRET_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Ok(Self {
            key,
            domain: domain.to_owned(),
        })
    }

    pub fn to_hex(&self) -> String {
        format!(
            "ee{}{}",
            hex::encode(self.key),
            hex::encode(self.domain.as_bytes())
        )
    }

    pub fn tg_link(&self, server: &str, port: u16) -> String {
        format!(
            "tg://proxy?server={server}&port={port}&secret={}",
            self.to_hex()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    Fast,
    Obfuscated,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CipherBackend {
    Rustcrypto,
    Openssl,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    /// 0 means one worker per CPU.
    pub workers: usize,
    pub secrets: Vec<String>,
    /// Empty means the domain embedded in the secret.
    pub mask_host: String,
    pub upstream_mode: UpstreamMode,
    pub prefer_ipv6_upstream: bool,
    pub time_skew_behind_secs: u64,
    pub time_skew_ahead_secs: u64,
    pub accept_uptime_timestamps: bool,
    /// Capacity of one replay-cache generation.
    pub replay_cache_entries: usize,
    pub handshake_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_connections: usize,
    pub metrics_listen: String,
    pub cipher_backend: CipherBackend,
    /// DC id ("1".."5") to upstream address.
    pub dc_override: BTreeMap<String, SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: vec![
                SocketAddr::from(([0, 0, 0, 0], 443)),
                SocketAddr::from(([0u16; 8], 443)),
            ],
            workers: 0,
            secrets: Vec::new(),
            mask_host: String::new(),
            upstream_mode: UpstreamMode::Fast,
            prefer_ipv6_upstream: true,
            time_skew_behind_secs: 600,
            time_skew_ahead_secs: 1200,
            accept_uptime_timestamps: true,
            replay_cache_entries: 2_000_000,
            handshake_timeout_secs: 10,
            idle_timeout_secs: 900,
            max_connections: 2_000_000,
            metrics_listen: "127.0.0.1:9100".to_owned(),
            cipher_backend: CipherBackend::Rustcrypto,
            dc_override: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let config: Config = toml::from_str(text)?;
        anyhow::ensure!(!config.listen.is_empty(), "`listen` must not be empty");
        anyhow::ensure!(!config.secrets.is_empty(), "`secrets` must not be empty");
        anyhow::ensure!(
            config.replay_cache_entries > 0,
            "`replay_cache_entries` must be greater than 0"
        );
        anyhow::ensure!(
            config.cipher_backend == CipherBackend::Rustcrypto,
            "cipher_backend \"openssl\" is not available in this build"
        );
        config.parsed_secrets()?;
        config.parsed_dc_overrides()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn parsed_secrets(&self) -> anyhow::Result<Vec<Secret>> {
        self.secrets
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // The position, not the value: secrets must not end up in logs.
                Secret::parse(s).with_context(|| format!("secrets[{i}]"))
            })
            .collect()
    }

    /// Overrides as (zero-based DC index, address).
    pub fn parsed_dc_overrides(&self) -> anyhow::Result<Vec<(usize, SocketAddr)>> {
        self.dc_override
            .iter()
            .map(|(id, addr)| match id.parse::<usize>() {
                Ok(n @ 1..=5) => Ok((n - 1, *addr)),
                _ => anyhow::bail!("dc_override key {id:?} is not a DC id (1-5)"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    fn ee(domain: &str) -> String {
        format!("ee{KEY_HEX}{}", hex::encode(domain))
    }

    #[test]
    fn secret_parses_key_and_domain() {
        let secret = Secret::parse(&ee("www.example.com")).unwrap();
        assert_eq!(
            secret.key,
            *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        );
        assert_eq!(secret.domain, "www.example.com");
    }

    #[test]
    fn secret_accepts_uppercase_hex_and_whitespace() {
        let text = format!("  {}\n", ee("example.org").to_uppercase());
        assert_eq!(Secret::parse(&text).unwrap().domain, "example.org");
    }

    #[test]
    fn secret_round_trips_through_hex() {
        let text = ee("cdn.example.net");
        assert_eq!(Secret::parse(&text).unwrap().to_hex(), text);
    }

    #[test]
    fn secret_rejects_other_formats() {
        assert_eq!(Secret::parse(KEY_HEX), Err(SecretError::Classic));
        // A classic secret that happens to start with ee is still classic.
        assert_eq!(
            Secret::parse("ee0102030405060708090a0b0c0d0e0f"),
            Err(SecretError::Classic)
        );
        assert_eq!(
            Secret::parse(&format!("dd{KEY_HEX}")),
            Err(SecretError::Secure)
        );
        assert_eq!(
            Secret::parse(&format!("ab{KEY_HEX}{}", hex::encode("a.com"))),
            Err(SecretError::BadPrefix)
        );
    }

    #[test]
    fn secret_rejects_malformed_input() {
        assert_eq!(Secret::parse(""), Err(SecretError::BadPrefix));
        assert_eq!(Secret::parse("zz"), Err(SecretError::NotHex));
        assert_eq!(Secret::parse("eea"), Err(SecretError::NotHex));
        assert_eq!(Secret::parse("ee"), Err(SecretError::TooShort));
        assert_eq!(Secret::parse("ee0011"), Err(SecretError::TooShort));
        assert_eq!(
            Secret::parse(&format!("ee{KEY_HEX}")),
            Err(SecretError::NoDomain)
        );
    }

    #[test]
    fn secret_rejects_bad_domains() {
        for domain in ["exa mple.com", "a..b", ".com", "ex/ample.com", "пример.рф"] {
            assert_eq!(
                Secret::parse(&ee(domain)),
                Err(SecretError::BadDomain),
                "{domain}"
            );
        }
        assert_eq!(
            Secret::parse(&format!("ee{KEY_HEX}ff")),
            Err(SecretError::BadDomain)
        );
        let long = format!("{}.com", "a".repeat(64));
        assert_eq!(Secret::parse(&ee(&long)), Err(SecretError::BadDomain));
        let oversized = vec!["abcdefgh"; 40].join(".");
        assert_eq!(Secret::parse(&ee(&oversized)), Err(SecretError::BadDomain));
    }

    #[test]
    fn generated_secret_is_parseable_and_random() {
        let a = Secret::generate("www.example.com").unwrap();
        let b = Secret::generate("www.example.com").unwrap();
        assert_ne!(a.key, b.key);
        assert_eq!(Secret::parse(&a.to_hex()).unwrap(), a);
        assert_eq!(Secret::generate("bad domain"), Err(SecretError::BadDomain));
    }

    #[test]
    fn tg_link_format() {
        let secret = Secret::parse(&ee("a.com")).unwrap();
        assert_eq!(
            secret.tg_link("proxy.example.org", 443),
            format!("tg://proxy?server=proxy.example.org&port=443&secret=ee{KEY_HEX}612e636f6d")
        );
    }

    #[test]
    fn debug_output_hides_the_key() {
        let secret = Secret::parse(&ee("a.com")).unwrap();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("0001"));
        assert!(debug.contains("a.com"));
    }

    #[test]
    fn example_config_parses() {
        let config = Config::parse(include_str!("../config.example.toml")).unwrap();
        assert_eq!(config.listen.len(), 2);
        assert_eq!(config.upstream_mode, UpstreamMode::Fast);
        assert_eq!(config.time_skew_behind_secs, 600);
        assert_eq!(config.time_skew_ahead_secs, 1200);
        assert!(config.accept_uptime_timestamps);
        let secrets = config.parsed_secrets().unwrap();
        assert_eq!(secrets[0].domain, "www.example.com");
    }

    #[test]
    fn defaults_apply_to_missing_keys() {
        let config = Config::parse(&format!("secrets = [\"{}\"]", ee("a.com"))).unwrap();
        assert_eq!(config.upstream_mode, UpstreamMode::Fast);
        assert_eq!(config.handshake_timeout_secs, 10);
        assert_eq!(config.idle_timeout_secs, 900);
        assert!(config.prefer_ipv6_upstream);
        assert!(config.dc_override.is_empty());
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        let base = format!("secrets = [\"{}\"]\n", ee("a.com"));
        assert!(Config::parse(&format!("{base}bogus = 1")).is_err());
        assert!(Config::parse(&format!("{base}upstream_mode = \"tls\"")).is_err());
        assert!(Config::parse(&format!("{base}listen = [\"nope\"]")).is_err());
        assert!(Config::parse(&format!("{base}listen = []")).is_err());
        assert!(Config::parse(&format!("{base}cipher_backend = \"openssl\"")).is_err());
        assert!(Config::parse(&format!("{base}replay_cache_entries = 0")).is_err());
        assert!(Config::parse("").is_err());
    }

    #[test]
    fn rejects_non_fake_tls_secrets() {
        assert!(Config::parse(&format!("secrets = [\"{KEY_HEX}\"]")).is_err());
        assert!(Config::parse(&format!("secrets = [\"dd{KEY_HEX}\"]")).is_err());
    }

    #[test]
    fn config_errors_do_not_echo_the_secret() {
        let bad = format!("ee{KEY_HEX}");
        let err = Config::parse(&format!("secrets = [\"{bad}\"]")).unwrap_err();
        assert!(!format!("{err:#}").contains(KEY_HEX));
    }

    #[test]
    fn dc_overrides() {
        let base = format!("secrets = [\"{}\"]\n", ee("a.com"));
        let config =
            Config::parse(&format!("{base}[dc_override]\n2 = \"127.0.0.1:1443\"")).unwrap();
        assert_eq!(
            config.parsed_dc_overrides().unwrap(),
            vec![(1, "127.0.0.1:1443".parse().unwrap())]
        );
        assert!(Config::parse(&format!("{base}[dc_override]\n6 = \"127.0.0.1:1\"")).is_err());
        assert!(Config::parse(&format!("{base}[dc_override]\nx = \"127.0.0.1:1\"")).is_err());
    }
}
