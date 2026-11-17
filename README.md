# EchoMTProxy

High-performance MTProto proxy in Rust — Fake-TLS, built for hundreds of thousands of users per server.

Status: early. The proxy accepts Fake-TLS (`ee`) secrets, relays to Telegram DCs
in direct mode, forwards failed handshakes to a mask site, enforces connection
and idle limits and exports metrics. Idle sessions hold no relay buffer: on
the target server an idle session costs about 4.1 KiB of resident memory in
the proxy (measured by `tests/rss.rs`). Per-core listeners are not implemented yet.

## Build

Requires a stable Rust toolchain (https://rustup.rs) and a C compiler (for
mimalloc).

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
- `mask_idle_timeout_secs` drops a masked connection when either direction is
  silent that long; `mask_dns_ttl_secs` is how long a resolved mask host is reused.

A handshake that fails after the proxy has already sent its ServerHello (a bad
obfuscated2 init) cannot be masked and gets no further reply.

## Metrics

`metrics_listen` (default `127.0.0.1:9100`, `""` to disable) serves Prometheus
text at `/metrics`:

| metric | labels | meaning |
|---|---|---|
| `echo_mtproxy_connections_open` | | client connections open, in any state |
| `echo_mtproxy_connections_accepted_total` | | connections taken off the listeners, admitted or not |
| `echo_mtproxy_connections_over_limit_total` | | connections refused because `max_connections` were open |
| `echo_mtproxy_pool_buffers_in_use` | | relay buffers borrowed right now; idle sessions hold none |
| `echo_mtproxy_relay_bytes_total` | `lane` | bytes relayed, both directions, `media` or `chat` |
| `echo_mtproxy_egress_bits_per_second` | | relay egress over the last 200 ms congestion-control tick; an instantaneous sample that reads 0 between bursts |
| `echo_mtproxy_congestion_scale` | | share of the media rate currently allowed (1 = no congestion) |
| `echo_mtproxy_media_connections_throttled` | | media connections waiting on their rate limit right now |
| `echo_mtproxy_upstream_retries_total` | `result` | DC connections reset before answering and retried: `reconnected`, `failed` |
| `echo_mtproxy_handshakes_total` | `sni`, `result` | handshakes by outcome: `accepted`, `malformed`, `bad_digest`, `bad_timestamp`, `replay`, `bad_init`, `timeout` |
| `echo_mtproxy_sessions_active` | `sni` | relayed sessions currently open |
| `echo_mtproxy_mask_connections_total` | `target`, `result` | masked connections: `forwarded`, `connect_failed`, `limited` |
| `echo_mtproxy_skew_rejected_seconds` | `direction` | histogram of clock offsets of skew rejections, `behind` or `ahead` |

`sni` takes only names known at startup: the `mask_domains` entries, the default
mask host and the secrets' domains. Every other SNI is counted as `_other`, so
clients cannot create new series.

## Media limiting and congestion control

Telegram clients mark media connections with a negative DC index. Those are the
media lane; everything else is chat. **Chat is never limited.**

- Each media connection may relay `media_burst_bytes` (default 2 MB) at full
  speed, then `media_rate_bps` (default 1 Mbit/s), upload and download counted
  together. `media_rate_bps = 0` turns limiting off.
- Both are per connection, not per user. A Telegram client fetches one file
  over several media connections in parallel (4 in a real-device test), each with its
  own burst and rate, so a user gets roughly the configured values times the
  number of connections: about 8 MB of burst and 4 Mbit/s with the defaults and
  4 connections.
- A limited connection is slowed by reading from it later, so TCP backpressure
  does the work and nothing is dropped. Once its burst is spent the kernel also
  paces its client socket at the same rate (`SO_MAX_PACING_RATE`, Linux); the
  pacing is lifted again when the connection has earned its full burst back.
- `link_capacity_bps` (default 5 Gbit/s; set it to the measured real throughput
  of your uplink) and `congestion_threshold` (default 0.85) drive congestion
  control. Every 200 ms the proxy measures its relay egress; above
  threshold x capacity it scales every media rate down by the same proportion
  (to no less than 5%), and below it the scale recovers 10% per tick.
  `link_capacity_bps = 0` turns it off.

## Upstream connections

- `upstream_bind_addrs` lists local source addresses for connections to
  Telegram, rotated per address family. One source address can only hold a
  limited number of connections to one DC address, so list every address the
  server has. They are bound with `IP_BIND_ADDRESS_NO_PORT` (Linux) so no port
  is reserved until connect. An address not assigned to the host fails startup.
- If a DC connection is reset before the DC has sent anything, the proxy
  reconnects once to the same DC over the other address family and replays the
  handshake and the client's first payload (up to 16 KiB). The client notices
  nothing. A reset after the DC has answered ends the session as before.
- `listen` takes any number of addresses and ports; all share one set of
  secrets, limits and counters.

## Limits

- `max_connections` counts every open client connection. Connections beyond it
  never get a reply: up to 1/16 of the limit (16 to 4096) are held silently
  until the handshake timeout, the rest are closed immediately.
- `idle_timeout_secs` closes a relayed session after that long without a byte
  in either direction (checked four times per period, so up to 25% late).
  `0` disables it.
- `replay_cache_entries` sizes the replay cache. Its memory is fixed:
  85.3 bytes per entry, 171 MB at the default of 2 000 000.
- The binary uses mimalloc as its allocator (the default `mimalloc` feature).
  On the target server it measured 4.1 KiB of resident memory per idle session
  against 4.6 KiB with glibc malloc, and 6% more handshakes per second. Build
  with `--no-default-features` to use the system allocator.

## Run

```sh
echo-mtproxy --config /etc/echo-mtproxy/config.toml
```

Logging goes to stderr; set `RUST_LOG=debug` for per-connection detail. At
debug level every session leaves one "session ended" line: who closed it
(`client`, `dc` or `idle`), bytes each way, duration and lane. Secrets, keys
and client addresses are never logged.

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
cargo test --workspace                       # everything below plus the load generator's tests
cargo test                                   # unit, property, vector, integration and 10k-session soak tests
cargo test --test integration -- --ignored   # also talk to real Telegram DCs
cargo test --release --test rss -- --ignored --nocapture   # memory per idle session (Linux)
cargo bench                                  # cipher, handshake and relay benchmarks
cargo bench --bench limiting_ab              # cost of media limiting when it never limits
cargo test --release --test storm -- --ignored --nocapture # accept and handshake rate under a connection storm (Linux)
```

The storm test drives the real binary and prints accepted connections per
second and full handshakes per second. Use it to compare builds and settings,
for example `--no-default-features` or
`STORM_EXTRA_CONFIG='upstream_mode = "obfuscated"'`.

The soak test opens 10 000 concurrent sessions and needs about 40 500 file
descriptors; it raises its own soft limit and says so if the hard limit is too
low. `SOAK_CONNECTIONS` changes the count.

The memory test starts the real binary, opens 1 000 and then 50 000 idle
sessions (`RSS_BASELINE_SESSIONS`, `RSS_SESSIONS`), and compares the proxy's
VmRSS between the two, reporting kernel socket memory separately. It needs
about 101 000 descriptors per process, so run it with `ulimit -n 200000`. It
fails above 5 KiB per idle session at that scale. CI runs it at 1 000 to 5 000
sessions with an 8 KiB limit, because readings over so few sessions vary.

To see which allocation sites idle sessions keep alive (dhat, needs symbols):

```sh
CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 \
    cargo test --release --test heap_profile -- --ignored --nocapture
cargo test --lib per_connection_state_sizes -- --nocapture   # size of the per-connection task
```

Fuzzing needs a nightly toolchain and `cargo install cargo-fuzz`:

```sh
cd fuzz
mkdir -p corpus/client_hello
cargo +nightly fuzz run client_hello corpus/client_hello seeds/client_hello -- -max_total_time=600
```

The targets are `client_hello`, `record_reader` and `obfs2_init`.

The ignored tests send the first message of an MTProto handshake through the
proxy to each DC, once per upstream mode. Run them on the server to check that
Telegram is reachable from there.

`tests/vectors/mtprotoproxy.json` holds known-answer vectors produced by
[alexbers/mtprotoproxy](https://github.com/alexbers/mtprotoproxy);
`tests/vectors/gen_vectors.py` regenerates them.

## Load testing

`tools/loadgen` builds `echo-loadgen`, which plays both ends of the proxy: fake
Telegram clients in front and a fake DC behind.

```sh
cargo build --release --workspace     # target/release/echo-loadgen

# 1. Fake DC, where the proxy can reach it:
echo-loadgen dc --listen 10.0.0.2:9001 --listen 10.0.0.2:9002

# 2. Point ALL five of the proxy's DCs at it (config.toml), then start the proxy:
#      [dc_override]
#      1 = "10.0.0.2:9001"
#      2 = "10.0.0.2:9002"
#      ... 3, 4, 5

# 3. Clients, from another machine if possible:
echo-loadgen client --target PROXY:443 --secret ee... \
    --connections 200000 --active 500 --mode download --payload 65536 \
    --media-share 0.2 --hold-secs 120
```

- **It never loads Telegram.** The first five sessions are probes, one per DC
  index, opened one at a time. If any of them does not get the fake DC's
  answer, the run stops before opening anything else. So override all five
  DCs: one left at its default is caught by its probe, at the cost of a single
  connection.
- `--active N` sessions move data (`echo`, `download` or `upload`); the rest
  stay idle and cost the tool about 1.3 KiB each on the client side and 0.5 KiB
  on the fake DC. Active sessions start once every session is open.
- `--media-share` puts that share of sessions on the media lane, so media
  limiting and congestion control are exercised.
- Progress lines show open sessions, failures by kind, sessions closed by the
  proxy, throughput and handshake and request latency percentiles.

### Many connections on one machine

One (source address, destination address, destination port) pair can carry
about 28,000 connections with the default Linux port range, and only about
14,000 before new connections become slow, because the kernel hands out the
even half of the range first. That applies to both legs:

- clients to proxy: add `--target` addresses or ports and `--bind` source
  addresses; `echo-loadgen client` warns when a pair would exceed 14,000;
- proxy to fake DC: add `upstream_bind_addrs` to the proxy and `--listen`
  addresses to the fake DC, spread over the five `[dc_override]` entries.

In a test with 100,000 sessions on one host, 4 client pairs and 5 upstream
pairs took 45 s to open them with handshakes of up to 2 s; 10 and 20 pairs took
4.5 s with a 99th-percentile handshake of 123 ms.

Kernel settings for runs in the hundreds of thousands and above, on every
machine involved:

```sh
sysctl -w fs.nr_open=4000000 fs.file-max=8000000
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535
ulimit -n 4000000          # and LimitNOFILE= in the proxy's systemd unit
```

Connection tracking (`nf_conntrack`) must be off or sized for the connection
count on these hosts, or it will drop connections long before the proxy does.

## License

Apache-2.0.
