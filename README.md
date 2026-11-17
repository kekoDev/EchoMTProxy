# EchoMTProxy

High-performance MTProto proxy in Rust — Fake-TLS, built for hundreds of thousands of users per server.

Status: phase 1. The proxy accepts Fake-TLS (`ee`) secrets and relays to Telegram
DCs in direct mode. Masking of failed handshakes, connection limits, the buffer
pool and metrics are not implemented yet; several config keys are accepted but
have no effect until then (`mask_host`, `idle_timeout_secs`, `max_connections`,
`metrics_listen`).

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

## Configure

Copy `config.example.toml` to `config.toml` and put the generated secret into
`secrets`. `config.toml` is gitignored. Every key is documented in the example.

`upstream_mode` selects how the proxy talks to Telegram:

| mode         | AES passes, client→DC | AES passes, DC→client | notes                         |
|--------------|-----------------------|-----------------------|-------------------------------|
| `fast`       | 2                     | 0                     | default                       |
| `obfuscated` | 2                     | 2                     |                               |
| `plain`      | 1                     | 1                     | experimental                  |

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
