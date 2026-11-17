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
const DEFAULT_MASK_PORT: u16 = 443;

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

    /// The same key presented under another domain. The domain is not part of
    /// the handshake MAC, so every such secret is accepted wherever the key is.
    pub fn with_domain(&self, domain: &str) -> Result<Self, SecretError> {
        let domain = domain.to_ascii_lowercase();
        if !valid_domain(&domain) {
            return Err(SecretError::BadDomain);
        }
        Ok(Self {
            key: self.key,
            domain,
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

/// One `(domain, tg:// link)` per domain, all carrying `secret`'s key.
pub fn links_for_domains<'a>(
    secret: &Secret,
    domains: impl IntoIterator<Item = &'a str>,
    server: &str,
    port: u16,
) -> Result<Vec<(String, String)>, SecretError> {
    let mut out: Vec<(String, String)> = Vec::new();
    for domain in domains {
        let variant = secret.with_domain(domain)?;
        if out.iter().all(|(seen, _)| *seen != variant.domain) {
            out.push((variant.domain.clone(), variant.tg_link(server, port)));
        }
    }
    Ok(out)
}

/// Where a masked connection is forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskTarget {
    /// Hostname or IP literal.
    pub host: String,
    pub port: u16,
}

impl MaskTarget {
    /// Parses `host`, `host:port`, `ip`, `ip:port` or `[ipv6]:port`.
    /// The port defaults to 443.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let text = text.trim();
        if let Ok(addr) = text.parse::<SocketAddr>() {
            return Ok(Self {
                host: addr.ip().to_string(),
                port: addr.port(),
            });
        }
        if let Ok(ip) = text.parse::<std::net::IpAddr>() {
            return Ok(Self {
                host: ip.to_string(),
                port: DEFAULT_MASK_PORT,
            });
        }
        let (host, port) = match text.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .with_context(|| format!("bad port in mask target {text:?}"))?;
                (host, port)
            }
            None => (text, DEFAULT_MASK_PORT),
        };
        let host = host.to_ascii_lowercase();
        anyhow::ensure!(valid_domain(&host), "bad host in mask target {text:?}");
        Ok(Self { host, port })
    }
}

/// An allowlisted SNI and the address its masked connections go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskDomain {
    pub domain: String,
    pub target: MaskTarget,
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
    /// Default mask target, `host` or `host:port`. Empty means the domain of
    /// the first secret.
    pub mask_host: String,
    /// SNI allowlist: `domain` or `domain=host:port`.
    pub mask_domains: Vec<String>,
    pub mask_max_connections: usize,
    pub mask_idle_timeout_secs: u64,
    /// 0 resolves the mask host on every masked connection.
    pub mask_dns_ttl_secs: u64,
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
            mask_domains: Vec::new(),
            mask_max_connections: 4096,
            mask_idle_timeout_secs: 120,
            mask_dns_ttl_secs: 300,
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
            config.mask_idle_timeout_secs > 0,
            "`mask_idle_timeout_secs` must be greater than 0"
        );
        anyhow::ensure!(
            config.max_connections > 0,
            "`max_connections` must be greater than 0"
        );
        anyhow::ensure!(
            config.replay_cache_entries > 0,
            "`replay_cache_entries` must be greater than 0"
        );
        anyhow::ensure!(
            config.cipher_backend == CipherBackend::Rustcrypto,
            "cipher_backend \"openssl\" is not available in this build"
        );
        let secrets = config.parsed_secrets()?;
        config.parsed_dc_overrides()?;
        config.parsed_mask_domains()?;
        config.default_mask(&secrets)?;
        if !config.metrics_listen.is_empty() {
            config
                .metrics_listen
                .parse::<SocketAddr>()
                .context("`metrics_listen` must be empty or ip:port")?;
        }
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

    pub fn parsed_mask_domains(&self) -> anyhow::Result<Vec<MaskDomain>> {
        let mut out: Vec<MaskDomain> = Vec::with_capacity(self.mask_domains.len());
        for entry in &self.mask_domains {
            let (domain, target) = match entry.split_once('=') {
                Some((domain, target)) => (domain.trim(), Some(target)),
                None => (entry.trim(), None),
            };
            let domain = domain.to_ascii_lowercase();
            anyhow::ensure!(
                valid_domain(&domain),
                "mask_domains entry {entry:?} is not a valid hostname"
            );
            anyhow::ensure!(
                out.iter().all(|d| d.domain != domain),
                "mask_domains lists {domain:?} twice"
            );
            let target = match target {
                Some(target) => MaskTarget::parse(target)
                    .with_context(|| format!("mask_domains entry {entry:?}"))?,
                None => MaskTarget {
                    host: domain.clone(),
                    port: DEFAULT_MASK_PORT,
                },
            };
            out.push(MaskDomain { domain, target });
        }
        Ok(out)
    }

    /// The target for handshakes whose SNI is not allowlisted, with the name
    /// it is reported under.
    pub fn default_mask(&self, secrets: &[Secret]) -> anyhow::Result<MaskDomain> {
        if self.mask_host.trim().is_empty() {
            let domain = secrets
                .first()
                .map(|s| s.domain.to_ascii_lowercase())
                .context("no secret to take the default mask host from")?;
            return Ok(MaskDomain {
                target: MaskTarget {
                    host: domain.clone(),
                    port: DEFAULT_MASK_PORT,
                },
                domain,
            });
        }
        let target = MaskTarget::parse(&self.mask_host).context("`mask_host`")?;
        Ok(MaskDomain {
            domain: target.host.clone(),
            target,
        })
    }

    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics_listen.parse().ok()
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
        assert_eq!(config.mask_idle_timeout_secs, 120);
        assert_eq!(config.mask_dns_ttl_secs, 300);
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
        assert!(Config::parse(&format!("{base}max_connections = 0")).is_err());
        assert!(Config::parse(&format!("{base}mask_idle_timeout_secs = 0")).is_err());
        assert!(Config::parse(&format!("{base}mask_dns_ttl_secs = 0")).is_ok());
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
    fn with_domain_keeps_the_key() {
        let secret = Secret::parse(&ee("a.com")).unwrap();
        let other = secret.with_domain("Google.COM").unwrap();
        assert_eq!(other.key, secret.key);
        assert_eq!(other.domain, "google.com");
        assert_eq!(other.to_hex(), ee("google.com"));
        assert_eq!(secret.with_domain("no pe"), Err(SecretError::BadDomain));
    }

    #[test]
    fn links_share_one_key_across_domains() {
        let secret = Secret::parse(&ee("a.com")).unwrap();
        let links = links_for_domains(
            &secret,
            ["google.com", "Facebook.com", "google.com", "a.com"],
            "198.51.100.7",
            443,
        )
        .unwrap();
        let domains: Vec<&str> = links.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(domains, ["google.com", "facebook.com", "a.com"]);
        for (domain, link) in &links {
            let hex_secret = link.rsplit("secret=").next().unwrap();
            let parsed = Secret::parse(hex_secret).unwrap();
            assert_eq!(parsed.key, secret.key);
            assert_eq!(&parsed.domain, domain);
            assert!(link.starts_with("tg://proxy?server=198.51.100.7&port=443&secret=ee"));
        }
        assert!(links_for_domains(&secret, ["bad domain"], "h", 1).is_err());
        assert!(links_for_domains(&secret, [], "h", 1).unwrap().is_empty());
    }

    #[test]
    fn mask_target_forms() {
        let parse = |s: &str| MaskTarget::parse(s).map(|t| (t.host, t.port));
        assert_eq!(parse("example.com").unwrap(), ("example.com".into(), 443));
        assert_eq!(
            parse("Example.com:8443").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(parse("127.0.0.1").unwrap(), ("127.0.0.1".into(), 443));
        assert_eq!(parse("127.0.0.1:8443").unwrap(), ("127.0.0.1".into(), 8443));
        assert_eq!(parse("[::1]:8443").unwrap(), ("::1".into(), 8443));
        assert_eq!(parse("::1").unwrap(), ("::1".into(), 443));
        for bad in [
            "",
            ":443",
            "host:",
            "host:0",
            "host:99999",
            "ho st",
            "a/b:1",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mask_domains_allowlist() {
        let base = format!("secrets = [\"{}\"]\n", ee("first.example"));
        let config = Config::parse(&format!(
            "{base}mask_domains = [\"Google.com\", \"local.example = 127.0.0.1:8443\"]"
        ))
        .unwrap();
        let domains = config.parsed_mask_domains().unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].domain, "google.com");
        assert_eq!(
            domains[0].target,
            MaskTarget {
                host: "google.com".into(),
                port: 443
            }
        );
        assert_eq!(domains[1].domain, "local.example");
        assert_eq!(
            domains[1].target,
            MaskTarget {
                host: "127.0.0.1".into(),
                port: 8443
            }
        );

        for bad in [
            "[\"a.com\", \"A.com\"]",
            "[\"bad domain\"]",
            "[\"a.com=\"]",
            "[\"a.com=host:0\"]",
            "[\"\"]",
        ] {
            assert!(
                Config::parse(&format!("{base}mask_domains = {bad}")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn default_mask_host() {
        let base = format!(
            "secrets = [\"{}\", \"{}\"]\n",
            ee("First.example"),
            ee("b.com")
        );
        let config = Config::parse(&base).unwrap();
        let secrets = config.parsed_secrets().unwrap();
        let mask = config.default_mask(&secrets).unwrap();
        assert_eq!(mask.domain, "first.example");
        assert_eq!(mask.target.port, 443);

        let config = Config::parse(&format!("{base}mask_host = \"127.0.0.1:8080\"")).unwrap();
        let mask = config.default_mask(&secrets).unwrap();
        assert_eq!(mask.domain, "127.0.0.1");
        assert_eq!(mask.target.port, 8080);

        assert!(Config::parse(&format!("{base}mask_host = \"bad host\"")).is_err());
    }

    #[test]
    fn metrics_listen_may_be_disabled() {
        let base = format!("secrets = [\"{}\"]\n", ee("a.com"));
        let config = Config::parse(&format!("{base}metrics_listen = \"\"")).unwrap();
        assert_eq!(config.metrics_addr(), None);
        let config = Config::parse(&base).unwrap();
        assert_eq!(config.metrics_addr(), "127.0.0.1:9100".parse().ok());
        assert!(Config::parse(&format!("{base}metrics_listen = \"nope\"")).is_err());
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
