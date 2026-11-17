"""Generate known-answer vectors by driving alexbers/mtprotoproxy's own handshake code.

usage: python3 -I gen_vectors.py <path to mtprotoproxy checkout> <output.json>
"""
import asyncio, hashlib, hmac, json, sys, time

sys.path.insert(0, sys.argv[1])
OUTPUT = sys.argv[2]
# mtprotoproxy reads sys.argv when it loads its config.
sys.argv = sys.argv[:1]
import mtprotoproxy as m

NOW = 1_800_000_000
SECRETS = {"first": "000102030405060708090a0b0c0d0e0f", "second": "a1b2c3d4e5f60718293a4b5c6d7e8f90"}
DOMAIN = "www.example.com"

conf = dict(USERS=SECRETS, IGNORE_TIME_SKEW=False, REPLAY_CHECK_LEN=65536, CLIENT_IPS_LEN=0,
            MODES={"classic": False, "secure": False, "tls": True}, PROXY_PROTOCOL=False,
            MASK=False, PREFER_IPV6=False, FAST_MODE=True)
m.config = type("config", (dict,), conf)(conf)
m.my_ip_info = {"ipv4": "192.0.2.1", "ipv6": None}
time.time = lambda: NOW


class Transport:
    def is_closing(self):
        return False

    def abort(self):
        pass


class Reader:
    def __init__(self, data=b""):
        self.data = data

    async def readexactly(self, n):
        if len(self.data) < n:
            raise asyncio.IncompleteReadError(self.data, n)
        out, self.data = self.data[:n], self.data[n:]
        return out

    async def read(self, n):
        out, self.data = self.data[:n], self.data[n:]
        return out


class Writer:
    def __init__(self):
        self.out = bytearray()
        self.transport = Transport()

    def write(self, data, extra={}):
        self.out += data

    async def drain(self):
        pass

    def get_extra_info(self, name):
        return ("127.0.0.1", 40000) if name == "peername" else None


def sign_client_hello(hello, secret, timestamp):
    zeroed = hello[:11] + b"\x00" * 32 + hello[43:]
    digest = bytearray(hmac.new(secret, zeroed, hashlib.sha256).digest())
    for i, b in enumerate(timestamp.to_bytes(4, "little")):
        digest[28 + i] ^= b
    return hello[:11] + bytes(digest) + hello[43:]


def client_obfs2_init(secret, dc_idx):
    while True:
        rnd = bytearray(m.myrandom.getrandbytes(64))
        if rnd[0] != 0xef and rnd[4:8] != b"\x00" * 4:
            break
    rnd[56:60] = m.PROTO_TAG_SECURE
    rnd[60:62] = dc_idx.to_bytes(2, "little", signed=True)
    key = hashlib.sha256(bytes(rnd[8:40]) + secret).digest()
    enc = m.create_aes_ctr(key=key, iv=int.from_bytes(rnd[40:56], "big"))
    return bytes(rnd[:56]) + enc.encrypt(bytes(rnd))[56:]


async def client_case(user, timestamp, dc_idx, split):
    secret = bytes.fromhex(SECRETS[user])
    hello = sign_client_hello(m.gen_tls_client_hello_msg(DOMAIN), secret, timestamp)
    init = client_obfs2_init(secret, dc_idx)
    stream = hello + b"\x14\x03\x03\x00\x01\x01"
    for part in (init[:split], init[split:]):
        if part:
            stream += b"\x17\x03\x03" + len(part).to_bytes(2, "big") + part
    writer = Writer()
    result = await m.handle_handshake(Reader(stream), writer)
    assert result, "reference rejected the handshake"
    rd, wr, proto_tag, got_user, got_dc, enc_key_iv, _ = result
    assert got_user == user
    return {
        "user": user,
        "timestamp": timestamp,
        "client_hello": hello.hex(),
        "server_response": bytes(writer.out).hex(),
        "obfs2_init": init.hex(),
        "proto_tag": proto_tag.hex(),
        "dc_idx": got_dc,
        "enc_key_iv": enc_key_iv.hex(),
        "dec_keystream": rd.decryptor.decrypt(b"\x00" * 48).hex(),
        "enc_keystream": wr.encryptor.encrypt(b"\x00" * 48).hex(),
    }, enc_key_iv


async def upstream_case(reuse):
    writer = Writer()

    async def get_connection(host, port, init_func=None):
        return Reader(), writer

    m.tg_connection_pool = type("Pool", (), {"get_connection": staticmethod(get_connection)})()
    rd, wr = await m.do_direct_handshake(m.PROTO_TAG_SECURE, 2, dec_key_and_iv=reuse)
    wire = bytes(writer.out)
    assert len(wire) == 64
    plain = m.create_aes_ctr(key=wire[8:40], iv=int.from_bytes(wire[40:56], "big")).decrypt(wire)
    return {
        "seed": (wire[:56] + plain[56:]).hex(),
        "reuse_key_iv": reuse.hex() if reuse else None,
        "wire": wire.hex(),
        "enc_keystream": wr.encryptor.encrypt(b"\x00" * 48).hex(),
        "dec_keystream": rd.decryptor.decrypt(b"\x00" * 48).hex(),
    }


async def main():
    cases = [("first", NOW, 2, 64), ("second", NOW - 599, -3, 10), ("first", NOW + 1199, 5, 0),
             ("second", 12345, 1, 63), ("first", NOW + 7, -5, 32)]
    handshakes, upstream = [], []
    for case in cases:
        vector, enc_key_iv = await client_case(*case)
        handshakes.append(vector)
        upstream.append(await upstream_case(enc_key_iv))
        upstream.append(await upstream_case(None))

    P = 2**255 - 19
    ns = [0, 1, 2, 19, P - 1, P, P + 1, 2**255, 2**256 - 1, 2**128 + 12345]
    ns += [int.from_bytes(m.myrandom.getrandbytes(32), "little") for _ in range(16)]
    squares = [{"n": n.to_bytes(32, "little").hex(), "square": ((n * n) % P).to_bytes(32, "little").hex()}
               for n in ns]

    out = {
        "source": "alexbers/mtprotoproxy, generated by driving handle_handshake and do_direct_handshake",
        "now": NOW,
        "domain": DOMAIN,
        "secrets": SECRETS,
        "handshakes": handshakes,
        "upstream": upstream,
        "x25519_squares": squares,
    }
    with open(OUTPUT, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    asyncio.run(main())
