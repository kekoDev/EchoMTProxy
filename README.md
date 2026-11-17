# EchoMTProxy

High-performance MTProto proxy in Rust — Fake-TLS, built for hundreds of thousands of users per server.

Status: early. The proxy accepts Fake-TLS (`ee`) secrets, relays to Telegram DCs
in direct mode, forwards failed handshakes to a mask site and exports metrics.
Connection limits, idle timeouts and the buffer pool are not implemented yet;
`idle_timeout_secs` and `max_connections` are accepted but have no effect.

## Build

Requires a stable Rust toolchain (https://rustup.rs).

```sh
cargo build --release
# binary: target/release/echo-mtproxy
```

## Generate a secret

```sh
echo-mtproxy --gen-secret www.example.com --server proxy.example.org --port 443
```

This prints a new `ee` secret and the matching `tg://proxy?...` link. The domain
is what the connection claims to be in its TLS ClientHello; pick a real,
TLS 1.3 capable site that is plausible for your server's network.

With `mask_domains` set in the config (see below), one key serves every listed
domain:

```sh
echo-mtproxy --config config.toml --gen-secret --server proxy.example.org   # new key, one link per domain
echo-mtproxy --config config.toml --print-links --server proxy.example.org  # links for the existing keys
```

Put the printed `secret:` value into `secrets`. The domain inside a secret is
not part of the handshake check, so a single entry accepts all of the links.

## Configure

Copy `config.example.toml` to `config.toml` and put the generated secret into
`secrets`. `config.toml` is gitignored. Every key is documented in the example.

`upstream_mode` selects how the proxy talks to Telegram:

| mode         | AES passes, client→DC | AES passes, DC→client | notes                         |
|--------------|-----------------------|-----------------------|-------------------------------|
| `fast`       | 2                     | 0                     | default                       |
| `obfuscated` | 2                     | 2                     |                               |
| `plain`      | 1                     | 1                     | experimental                  |

## Masking

A connection that fails the handshake (wrong key, replay, clock skew, or not
Fake-TLS at all) is forwarded to a real TLS site together with the bytes already
read, and then spliced in both directions. A probe therefore sees that site's
certificate and answers.

- `mask_domains` is an allowlist. If the failed ClientHello's SNI is listed
  (exact match, case-insensitive; subdomains do not match), the connection goes
  to that entry. Write `"domain"` to forward to `domain:443`, or
  `"domain=host:port"` to forward elsewhere, for example to a site hosted on
  the same server.
- Any other SNI, or none, goes to `mask_host` (default: the domain of the first
  secret).
- The SNI only selects among configured targets. The proxy never connects to a
  name supplied by a client.
- `mask_max_connections` caps concurrent masked connections. Beyond it, failed
  handshakes get no reply.

A handshake that fails after the proxy has already sent its ServerHello (a bad
obfuscated2 init) cannot be masked and gets no further reply.

## Metrics

`metrics_listen` (default `127.0.0.1:9100`, `""` to disable) serves Prometheus
text at `/metrics`:

| metric | labels | meaning |
|---|---|---|
| `echo_mtproxy_handshakes_total` | `sni`, `result` | handshakes by outcome: `accepted`, `malformed`, `bad_digest`, `bad_timestamp`, `replay`, `bad_init`, `timeout` |
| `echo_mtproxy_sessions_active` | `sni` | relayed sessions currently open |
| `echo_mtproxy_mask_connections_total` | `target`, `result` | masked connections: `forwarded`, `connect_failed`, `limited` |
| `echo_mtproxy_skew_rejected_seconds` | `direction` | histogram of clock offsets of skew rejections, `behind` or `ahead` |

`sni` takes only names known at startup: the `mask_domains` entries, the default
mask host and the secrets' domains. Every other SNI is counted as `_other`, so
clients cannot create new series.

## Run

```sh
echo-mtproxy --config /etc/echo-mtproxy/config.toml
```

Logging goes to stderr; set `RUST_LOG=debug` for per-connection detail. Secrets,
keys and client addresses are never logged.

Binding port 443 needs root or `CAP_NET_BIND_SERVICE`, and every client uses two
file descriptors, so raise the open-file limit. A systemd unit that does both:

```ini
[Unit]
Description=EchoMTProxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/echo-mtproxy --config /etc/echo-mtproxy/config.toml
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
```

## Connect a Telegram client

1. Open the `tg://proxy?...` link on a device with Telegram installed, or add it
   manually: Settings → Data and Storage → Proxy → Add Proxy → MTProto, with the
   server, port and the full `ee...` secret.
2. Enable the proxy. The status should change from "connecting" to "connected",
   and the proxy entry shows a ping time.
3. Send a message and load some media to exercise both directions.

If it stays on "connecting", run the proxy with `RUST_LOG=debug` and look at the
rejection reason. The usual causes are a wrong secret, a device clock outside
the allowed window, or the server being unable to reach Telegram.

## Tests

```sh
cargo test                                   # unit, property, vector and integration tests
cargo test --test integration -- --ignored   # also talk to real Telegram DCs
```

The ignored tests send the first message of an MTProto handshake through the
proxy to each DC, once per upstream mode. Run them on the server to check that
Telegram is reachable from there.

`tests/vectors/mtprotoproxy.json` holds known-answer vectors produced by
[alexbers/mtprotoproxy](https://github.com/alexbers/mtprotoproxy);
`tests/vectors/gen_vectors.py` regenerates them.

## License

Apache-2.0.
