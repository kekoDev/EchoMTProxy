"""Generate middle-proxy known-answer vectors with alexbers/mtprotoproxy's own code.

usage: python3 -I gen_middle_vectors.py <path to mtprotoproxy checkout> <output.json>
"""
import json, socket, sys

sys.path.insert(0, sys.argv[1])
OUTPUT = sys.argv[2]
# mtprotoproxy reads sys.argv when it loads its config.
sys.argv = sys.argv[:1]
import mtprotoproxy as m

AD_TAG = bytes(range(0xa0, 0xb0))
SECRET = m.PROXY_SECRET


class Sink:
    """Stands in for the socket writer at the bottom of the writer stack."""

    def __init__(self):
        self.data = b""

    def write(self, data, extra={}):
        self.data += data


def seq(n, salt):
    return bytes((i * 7 + salt) % 256 for i in range(n))


def keys(v6):
    nonce_srv, nonce_clt, ts = seq(16, 1), seq(16, 2), bytes.fromhex("5fe1d76a")
    if v6:
        srv, clt = ("2001:db8::d", 8888), ("2001:db8::1", 40123)
        args = dict(srv_ip=None, clt_ip=None,
                    clt_ipv6=socket.inet_pton(socket.AF_INET6, clt[0]),
                    srv_ipv6=socket.inet_pton(socket.AF_INET6, srv[0]))
    else:
        srv, clt = ("192.0.2.10", 8888), ("198.51.100.7", 40123)
        args = dict(srv_ip=socket.inet_pton(socket.AF_INET, srv[0])[::-1],
                    clt_ip=socket.inet_pton(socket.AF_INET, clt[0])[::-1])
    out = dict(nonce_server=nonce_srv.hex(), nonce_client=nonce_clt.hex(), timestamp=ts.hex(),
               server_addr="[%s]:%d" % srv if v6 else "%s:%d" % srv,
               client_addr="[%s]:%d" % clt if v6 else "%s:%d" % clt)
    for purpose in (b"CLIENT", b"SERVER"):
        key, iv = m.get_middleproxy_aes_key_and_iv(
            nonce_srv=nonce_srv, nonce_clt=nonce_clt, clt_ts=ts,
            clt_port=int.to_bytes(clt[1], 2, "little"), purpose=purpose,
            srv_port=int.to_bytes(srv[1], 2, "little"), middleproxy_secret=SECRET, **args)
        out[purpose.decode().lower()] = dict(key=key.hex(), iv=iv.hex())
    return out


def frames():
    out = []
    for n, msg in ((-2, seq(32, 3)), (0, seq(36, 4)), (7, seq(200, 5))):
        sink = Sink()
        m.MTProtoFrameStreamWriter(sink, n).write(msg)
        out.append(dict(seq=n, msg=msg.hex(), wire=sink.data.hex()))
    return out


def upstream(ad_tag, client, proxy):
    """Client messages through the request, frame and CBC writers."""
    conf = dict(AD_TAG=ad_tag)
    m.config = type("config", (dict,), conf)(conf)
    key, iv = seq(32, 9), seq(16, 10)
    sink = Sink()
    crypto = m.CryptoWrappedStreamWriter(sink, m.create_aes_cbc(key, iv), block_size=16)
    framer = m.MTProtoFrameStreamWriter(crypto, 0)
    req = m.ProxyReqStreamWriter(framer, client[0], client[1], proxy[0], proxy[1],
                                 m.PROTO_TAG_SECURE)
    # (message, quick-ack requested, client-side padding)
    messages = [(b"\x00" * 8 + seq(32, 11), False, 0), (seq(40, 12), False, 3),
                (seq(16, 13), True, 1), (seq(2000, 14), False, 2), (seq(8, 15), False, 0)]
    stream = b""
    for msg, quickack, pad in messages:
        req.write(msg, {"QUICKACK_FLAG": True} if quickack else {})
        word = len(msg) + pad + (0x80000000 if quickack else 0)
        stream += int.to_bytes(word, 4, "little") + msg + seq(pad, 16)
    return dict(ad_tag=ad_tag.hex(), key=key.hex(), iv=iv.hex(), conn_id=req.out_conn_id.hex(),
                client="%s:%d" % client if ":" not in client[0] else "[%s]:%d" % client,
                proxy="%s:%d" % proxy if ":" not in proxy[0] else "[%s]:%d" % proxy,
                client_stream=stream.hex(), wire=sink.data.hex())


def downstream():
    """Answers as a middle proxy would send them, written with the frame and CBC writers."""
    key, iv = seq(32, 20), seq(16, 21)
    sink = Sink()
    framer = m.MTProtoFrameStreamWriter(
        m.CryptoWrappedStreamWriter(sink, m.create_aes_cbc(key, iv), block_size=16), 0)
    conn_id = seq(8, 22)
    ans, ack, unknown = b"\x0d\xda\x03\x44", b"\x9b\x40\xac\x3b", b"\xdf\xa2\x30\x57"
    expected = []
    for data in (seq(40, 23), seq(4, 24), seq(3000, 25)):
        framer.write(ans + b"\x00" * 4 + conn_id + data)
        expected.append(dict(kind="message", data=data.hex()))
    framer.write(ack + conn_id + b"\x11\x22\x33\x44")
    expected.append(dict(kind="ack", data="11223344"))
    framer.write(unknown + seq(12, 26))
    framer.write(ans + b"\x00" * 4 + conn_id + seq(64, 27))
    expected.append(dict(kind="message", data=seq(64, 27).hex()))
    return dict(key=key.hex(), iv=iv.hex(), wire=sink.data.hex(), expected=expected)


vectors = dict(
    source="alexbers/mtprotoproxy",
    secret=SECRET.hex(),
    keys=[keys(False), keys(True)],
    frames=frames(),
    upstream=[upstream(AD_TAG, ("203.0.113.9", 51000), ("198.51.100.7", 40123)),
              upstream(b"", ("2001:db8::99", 51000), ("2001:db8::1", 40123))],
    downstream=downstream(),
)
with open(OUTPUT, "w") as f:
    json.dump(vectors, f, indent=1)
    f.write("\n")
