#!/usr/bin/env python3
"""The tests this fork needs: what it changed, measured where it shows.

Each scenario builds the shape the fork actually runs in - a plaintext sender,
a client tunnel, a server tunnel, a plaintext endpoint - and reads its verdict
off the logs and off the data that arrived.  Run it as root where the
CryptoPro CSP is installed and licensed:

    python3 msspi/run.py                 # the matrix and every scenario
    python3 msspi/run.py "source port"   # only scenarios named like that

STUNNEL names the binary under test, STUNNEL_REFERENCE the upstream stunnel
the matrix measures against.  Identities come from ../pki and go into the
provider as containers; the suite also puts the provider into a state where
DTLS works at all before it starts.
"""

import base64
import hashlib
import os
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
PKI = os.path.join(TESTS, "pki")
STUNNEL = os.environ.get("STUNNEL", os.path.join(TESTS, os.pardir, "src", "stunnel-msspi"))
CERTMGR = "/opt/cprocsp/bin/amd64/certmgr"
# the reference peers: stunnel as upstream builds it, and OpenSSL itself
REFERENCE = os.environ.get("STUNNEL_REFERENCE", "/usr/local/bin/stunnel-reference")
OPENSSL = os.environ.get("OPENSSL", "openssl")
CPCONFIG = "/opt/cprocsp/sbin/amd64/cpconfig"
DSRF = "/var/opt/cprocsp/dsrf"
DSRF_KIT = os.environ.get("CSP_DSRF")
PFX_PASSWORD = "stunnel-test"
IDENTITIES = {}  # leaf name -> thumbprint, imported once per run


def cpconfig(*args):
    return subprocess.run([CPCONFIG] + list(args),
                          capture_output=True, check=False).returncode


def prepare_csp():
    """Two things the provider needs before it will do DTLS at all.

    It ships with DTLS switched off, and without a random source it cannot
    make a session key - a fresh container has neither, so the suite puts
    them there rather than inheriting them from whatever ran before it.
    The pool has a shape of its own - the provider refuses random bytes - so
    it comes from the provider's own kit, named by CSP_DSRF.
    """
    for side in ("Client", "Server"):
        cpconfig("-ini", f"\\config\\parameters\\Protocols\\DTLS 1.2\\{side}",
                 "-add", "long", "Enabled", "1")

    if os.path.exists(os.path.join(DSRF, "db1", "kis_1")):
        return
    if not DSRF_KIT:
        raise SystemExit("no random source: point CSP_DSRF at the dsrf.tar "
                         "of the provider kit")
    cpconfig("-hardware", "rndm", "-add", "cpsd", "-name", "cpsd rng", "-level", "2")
    os.makedirs(DSRF, exist_ok=True)
    subprocess.run(["tar", "-xf", DSRF_KIT, "-C", DSRF], check=True)
    for db in ("db1", "db2"):
        cpconfig("-hardware", "rndm", "-configure", "cpsd", "-add", "string",
                 f"/{db}/kis_1", os.path.join(DSRF, db, "kis_1"))


def free_port(kind=socket.SOCK_DGRAM):
    """A port nobody holds - of the kind that is about to be bound to it."""
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def in_store(dn):
    out = subprocess.run(
        [CERTMGR, "-list", "-store", "uRoot", "-dn", dn],
        capture_output=True, check=False)
    return b"SHA1 Thumbprint" in out.stdout


def trust(name, dn):
    """Put a root where the CSP chain engine will find it."""
    subprocess.run(
        [CERTMGR, "-install", "-store", "uRoot", "-file", os.path.join(PKI, name)],
        input=b"o\n", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if not in_store(dn):
        raise RuntimeError(f"could not put {name} in the root store")


def untrust(dn):
    subprocess.run(
        [CERTMGR, "-delete", "-all", "-store", "uRoot", "-dn", dn],
        input=b"o\n", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def thumbprint(cer):
    """A certificate is named by the SHA1 of its DER, whichever form it is in."""
    raw = open(cer, "rb").read()
    if raw.lstrip().startswith(b"-----BEGIN"):
        body = raw.split(b"-----BEGIN CERTIFICATE-----", 1)[1].split(b"-----END", 1)[0]
        raw = base64.b64decode(body)
    return hashlib.sha1(raw).hexdigest()


def bound_to_key(thumb):
    out = subprocess.run(
        [CERTMGR, "-list", "-store", "uMy", "-thumbprint", thumb],
        capture_output=True, check=False)
    return b"PrivateKey Link" in out.stdout and b"Yes" in out.stdout


def identity(name, provtype=None):
    """Install a leaf the way the product does, and name it the way it does.

    The PKCS#12 goes into the CSP once, as a container with the certificate
    beside it in uMy; from then on the configuration carries the thumbprint,
    never the key material.  The import is what tags the container with a
    provider type, and the tag has to match the key: an RSA key left under the
    GOST default is taken for a GOST one and refused when it is first used.
    """
    if name in IDENTITIES:
        return IDENTITIES[name]
    thumb = thumbprint(os.path.join(PKI, name + ".cer"))
    if not bound_to_key(thumb):
        done = subprocess.run(
            [CERTMGR, "-install", "-pfx", "-silent",
             "-file", os.path.join(PKI, name + ".pfx"),
             "-pin", PFX_PASSWORD, "-newpin", ""]
            + (["-provtype", str(provtype)] if provtype else []),
            capture_output=True, check=False)
        if not bound_to_key(thumb):
            raise RuntimeError(
                f"{name}.pfx did not become a container: "
                + done.stdout.decode(errors="replace").strip().replace("\n", " | "))
    IDENTITIES[name] = thumb
    return thumb


class Tunnel:
    """One stunnel process and its log."""

    def __init__(self, tmpd, name, body, binary=None):
        self.log = os.path.join(tmpd, name + ".log")
        self.conf = os.path.join(tmpd, name + ".conf")
        with open(self.conf, "w", encoding="utf-8") as fh:
            fh.write("foreground = yes\ndebug = debug\nsyslog = no\n"
                     f"output = {self.log}\n{body}")
        self.err = os.path.join(tmpd, name + ".err")
        with open(self.err, "wb") as errfh:
            self.proc = subprocess.Popen(
                [binary or STUNNEL, self.conf], stdout=errfh, stderr=errfh)

    def text(self):
        try:
            with open(self.log, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except FileNotFoundError:
            return ""

    def wait_for(self, needle, seconds=10):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if needle in self.text():
                return True
            time.sleep(0.2)
        return False

    def signals(self):
        """The lines that carry a verdict rather than bookkeeping."""
        keep = [ln.split("]: ", 1)[-1] for ln in self.text().splitlines()
                if "msspi:" in ln or "SSL_" in ln or "error" in ln.lower()]
        return " | ".join(keep[-6:]) or "(nothing said)"

    def tail(self, lines=8):
        text = self.text()
        if not text.strip():
            with open(self.err, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        return " | ".join(text.strip().splitlines()[-lines:])

    def stop(self):
        """Ask first: a killed stunnel leaves the tail of its log unwritten."""
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class Echo:
    """The plaintext endpoint at the far end of a cascade.

    It answers with the datagram it was given under a prefix, so a reply
    proves the payload reached the far end rather than turning round early.
    """

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.received = []
        self.running = True
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def pump(self):
        while self.running:
            if not select.select([self.sock], [], [], 0.2)[0]:
                continue
            data, peer = self.sock.recvfrom(65535)
            self.received.append(data)
            self.sock.sendto(b"echo:" + data, peer)

    def wait(self, count, seconds=6):
        """The datagrams that reached the far end, once there are count of them."""
        deadline = time.time() + seconds
        while len(self.received) < count and time.time() < deadline:
            time.sleep(0.05)
        return list(self.received)

    def stop(self):
        self.running = False
        self.thread.join(timeout=2)
        self.sock.close()


class Relay:
    """Sits between the tunnels, measures what passes and can drop a datagram.

    A DTLS record names what it carries in its first byte, so the sizes split
    into what the handshake cost and what the data cost without decrypting
    anything.  Each peer gets a socket of its own towards the server, so the
    server still tells the sessions apart by address as it would without a
    relay in the way.
    """

    HANDSHAKE, DATA = 22, 23

    def __init__(self, port, upstream, drop_nth=0, delay=0.0):
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", port))
        self.upstream = upstream
        self.drop_nth = drop_nth
        self.delay = delay      # applied once the ServerHello has gone by
        self.delayed = False
        self.up = {}      # peer address -> socket towards the server
        self.peer = {}    # that socket -> the peer address
        self.back = 0     # datagrams counted on the way back
        self.seen = []    # (direction, record type, length) in flight order
        self.hs = []      # (direction, handshake message type), unencrypted
        self.running = True
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def pump(self):
        while self.running:
            ready, _, _ = select.select([self.front] + list(self.up.values()),
                                        [], [], 0.2)
            for sock in ready:
                data, addr = sock.recvfrom(65535)
                if not data:
                    continue
                way = "out" if sock is self.front else "back"
                self.seen.append((way, data[0], len(data)))
                self.note_handshake(way, data)
                server_hello = (sock is not self.front and data[0] == 22 and
                                len(data) > 13 and data[13] == 2)
                if self.delay and self.delayed:
                    time.sleep(self.delay)
                if sock is self.front:
                    if addr not in self.up:
                        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        up.connect(("127.0.0.1", self.upstream))
                        self.up[addr] = up
                        self.peer[up] = addr
                    try:
                        self.up[addr].send(data)
                    except OSError:
                        continue  # the far end went away; keep relaying
                else:
                    self.back += 1
                    if self.back == self.drop_nth:
                        continue
                    try:
                        self.front.sendto(data, self.peer[sock])
                    except OSError:
                        continue
                    if server_hello:
                        self.delayed = True

    def note_handshake(self, way, data):
        """Name the handshake messages a datagram carries in the clear.

        A datagram holds whole records back to back, and a record holds whole
        messages, so both walk by their own length.  An encrypted record
        (epoch above zero) says nothing about its contents and is skipped.
        """
        at = 0
        while at + 13 <= len(data):
            kind = data[at]
            epoch = int.from_bytes(data[at + 3:at + 5], "big")
            length = int.from_bytes(data[at + 11:at + 13], "big")
            body = data[at + 13:at + 13 + length]
            at += 13 + length
            if kind != self.HANDSHAKE or epoch:
                continue
            pos = 0
            while pos + 12 <= len(body):
                self.hs.append((way, body[pos]))
                pos += 12 + int.from_bytes(body[pos + 9:pos + 12], "big")

    def largest(self, record_type, direction=None):
        sizes = [n for way, kind, n in self.seen
                 if kind == record_type and direction in (None, way)]
        return max(sizes) if sizes else 0

    def stop(self):
        self.running = False
        self.thread.join(timeout=2)
        self.front.close()
        for sock in self.up.values():
            sock.close()


def gost_pair():
    """The identities a cascade runs on, with their root trusted."""
    trust("gost_ca.cer", "CN=stunnel test GOST CA")
    return identity("gost_server"), identity("gost_client")


def tls_round_trip(tmpd):
    """The same cascade over TCP, carrying a stream rather than datagrams.

    The volume is the one the fork has always been measured on, and it has to
    arrive byte for byte: a stream that is short by a record would still look
    like a working tunnel from the outside.
    """
    source_port, tunnel_port, entry_port = (
        free_port(socket.SOCK_STREAM), free_port(socket.SOCK_STREAM),
        free_port(socket.SOCK_STREAM))
    server_thumb, client_thumb = gost_pair()
    payload = (b"0123456789abcdefghijklmnopqrstuvwxyz"
               b"ABCDEFGHIJKLMNOPQRSTUVWXYZ.\n") * 1500

    source = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    source.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    source.bind(("127.0.0.1", source_port))
    source.listen(1)

    def serve():
        try:
            conn, _ = source.accept()
        except OSError:
            return
        with conn:
            conn.sendall(payload)
    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()

    server = Tunnel(tmpd, "server", f"""
[tls-server]
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{source_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    client = Tunnel(tmpd, "client", f"""
[tls-client]
client = yes
accept = 127.0.0.1:{entry_port}
connect = 127.0.0.1:{tunnel_port}
cert = {client_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()

        got = b""
        with socket.create_connection(("127.0.0.1", entry_port), timeout=20) as sock:
            sock.settimeout(20)
            while len(got) < len(payload):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                got += chunk
        if got != payload:
            return False, (f"{len(got)} of {len(payload)} bytes arrived; "
                           f"client: {client.signals()}")
        return True, f"{len(payload)} bytes arrived unchanged"
    finally:
        client.stop()
        server.stop()
        source.close()
        server_thread.join(timeout=2)


def dtls_round_trips(tmpd, drop_nth=0):
    """Datagrams through the cascade, from one peer and then from a second.

    Ten go through the session the first peer opens.  A second peer reaches
    the same client tunnel and gets a session of its own; the relay names the
    handshake messages that pass, so the run says whether the provider opened
    that session from scratch or resumed it.  With drop_nth set the relay
    swallows that many-th datagram on its way back, so a flight has to be sent
    again for anything to arrive at all.
    """
    echo_port, tunnel_port, sender_port = free_port(), free_port(), free_port()
    relay_port = free_port()
    server_thumb, client_thumb = gost_pair()

    echo = Echo(echo_port)
    relay = Relay(relay_port, tunnel_port, drop_nth)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{sender_port}
connect = 127.0.0.1:{relay_port}
cert = {client_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()

        def exchange(sock, first, last):
            lost = []
            for i in range(first, last + 1):
                message = f"msg-{i}".encode()
                sock.sendto(message, ("127.0.0.1", sender_port))
                try:
                    reply, _ = sock.recvfrom(65535)
                except socket.timeout:
                    reply = b"(nothing)"
                if reply != b"echo:" + message:
                    lost.append(f"{message.decode()} came back as {reply!r}")
            return lost

        fresh = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fresh.settimeout(15)
        lost = exchange(fresh, 1, 10)
        first_handshake = len(relay.hs)
        resumed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        resumed.settimeout(15)
        lost += exchange(resumed, 11, 12)

        if lost:
            return False, (f"{len(lost)} of 12 lost: {lost[0]}; "
                           f"client: {client.signals()}")
        if relay.back < drop_nth:
            return False, (f"the relay never reached datagram {drop_nth} to drop it, "
                           f"only {relay.back} came back")

        # CERTIFICATE is 11: a server sends one to open a session and none to
        # resume it, so the second handshake names its own shape.
        second = relay.hs[first_handshake:]
        if not [1 for way, msg in second if way == "back" and msg == 2]:
            return False, "the second peer got no ServerHello of its own"
        shape = "full" if [1 for way, msg in second
                           if way == "back" and msg == 11] else "abbreviated"
        dropped = f", datagram {drop_nth} back was dropped" if drop_nth else ""
        return True, (f"12 of 12 round trips, the second session {shape}"
                      + dropped)
    finally:
        client.stop()
        server.stop()
        relay.stop()
        echo.stop()


def abandoned_peer(tmpd, noisy):
    """A handshake nobody carries through must not hold the session open.

    TIMEOUThandshake bounds the handshake as a whole, whether the peer says nothing
    at all or keeps the socket readable with datagrams the handshake cannot
    use.  The log timestamps are the measurement: how long the accepted
    session lived before the tunnel gave up on it.
    """
    busy = 3
    peer_port, wake_port = free_port(), free_port()

    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", peer_port))
    running = True

    def answer():
        # a DTLS record of application data: the handshake discards it without
        # failing, so the socket stays readable while nothing advances
        early = b"\x17\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x01\x00\x04idle"
        while running:
            if not select.select([peer], [], [], 0.2)[0]:
                continue
            _, addr = peer.recvfrom(65535)
            if noisy:
                for _ in range(4):
                    peer.sendto(early, addr)
    peer_thread = threading.Thread(target=answer, daemon=True)
    peer_thread.start()

    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{wake_port}
connect = 127.0.0.1:{peer_port}
TIMEOUThandshake = {busy}
verify = 0
""")
    try:
        if not client.wait_for("Accepting new connections"):
            return False, "the client tunnel never came up: " + client.tail()

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.sendto(b"wake", ("127.0.0.1", wake_port))

        if not client.wait_for("the handshake ran out of time", seconds=busy + 15):
            return False, "the tunnel never gave up: " + client.tail()
        if not client.wait_for("finished", seconds=5):
            return False, "the session did not finish: " + client.tail()

        def stamp(needle):
            for line in client.text().splitlines():
                if needle in line:
                    hh, mm, ss = line.split()[1].split(":")
                    return int(hh) * 3600 + int(mm) * 60 + int(ss)
            return None

        accepted, gave_up = stamp("accepted connection"), stamp("the handshake ran out of time")
        if accepted is None or gave_up is None:
            return False, "the log does not say when the session began or ended"
        held = gave_up - accepted
        if held < busy:
            return False, f"gave up after {held}s, sooner than TIMEOUThandshake of {busy}s"
        if held > busy + 2:
            return False, f"held {held}s, which TIMEOUThandshake of {busy}s did not bound"
        return True, f"the session was held {held}s, TIMEOUThandshake is {busy}s"
    finally:
        client.stop()
        running = False
        peer_thread.join(timeout=2)
        peer.close()


def mutual_auth(tmpd, trusted, family="gost"):
    """A DTLS cascade where the server asks for a client certificate.

    Both ends hold their key in a CSP container and name their certificate by
    thumbprint, which is how the product is deployed.  With the root trusted
    the client verifies the server and the datagram goes through; without it
    the client's certificate callback aborts, and what the tunnel does with
    that abort is the thing under test.
    """
    echo_port, tunnel_port, sender_port = free_port(), free_port(), free_port()

    # the root the chain has to reach; whether it is trusted is what the
    # scenario varies, and the CSP builds the chain from what the store holds
    ca_file, ca_dn, leaf, provtype = {
        "gost": ("gost_ca.cer", "CN=stunnel test GOST CA", "gost", None),
        "rsa": ("rsa_ca.cer", "CN=stunnel test RSA CA", "rsa_cpro", 24),
    }[family]
    server_thumb = identity(leaf + "_server", provtype)
    client_thumb = identity(leaf + "_client", provtype)

    untrust(ca_dn)
    if trusted:
        trust(ca_file, ca_dn)

    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{sender_port}
connect = 127.0.0.1:{tunnel_port}
cert = {client_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    try:
        if not client.wait_for("Accepting new connections"):
            return False, "the client tunnel never came up: " + client.tail()
        if not server.wait_for("Accepting new connections"):
            return False, "the server tunnel never came up: " + server.tail()

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.settimeout(6)
        sender.sendto(b"through", ("127.0.0.1", sender_port))
        try:
            got, _ = sender.recvfrom(4096)
        except socket.timeout:
            got = b""

        log = client.text()
        if trusted:
            if got != b"echo:through":
                return False, (f"nothing came back ({got!r}); client: {client.signals()}"
                               f" || server: {server.signals()}")
            return True, "the datagram went through"

        if got:
            return False, f"the tunnel carried data after the callback aborted ({got!r})"
        verdict = [ln.split("]: ", 1)[-1].strip() for ln in log.splitlines()
                   if "msspi: verify" in ln]
        if not verdict:
            return False, "the client never reported why it stopped"
        if verdict[-1] != "msspi: verify failed (0x800B010A)":
            return False, f"expected an untrusted chain, got {verdict[-1]!r}"
        return True, "the handshake stopped: " + verdict[-1]
    finally:
        client.stop()
        server.stop()
        echo.stop()


def mtu_bounds(tmpd, mtu):
    """What DTLSmtu bounds, and what it deliberately does not.

    The setting is a link MTU, as -mtu is to OpenSSL, so the datagrams of the
    handshake have to stay within it less what IP and UDP take.  Application
    data is not bounded by it at all - a datagram travels in one record
    whatever the MTU, and the record is what limits it - so the payload here
    is three times the MTU on purpose, and has to arrive whole, in one
    datagram larger than the MTU.
    """
    link = mtu or 1300       # the default, see options.c
    expected = link - 28     # over IPv4, what IP and UDP take off a link MTU
    echo_port, relay_port, tunnel_port, sender_port = (
        free_port(), free_port(), free_port(), free_port())
    server_thumb, client_thumb = gost_pair()

    setting = f"DTLSmtu = {mtu}\n" if mtu else ""
    echo = Echo(echo_port)
    relay = Relay(relay_port, tunnel_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = auto
{setting}""")
    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{sender_port}
connect = 127.0.0.1:{relay_port}
cert = {client_thumb}
verifyChain = yes
verifyRevocation = auto
{setting}""")
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()

        payload = bytes(range(256)) * (3 * expected // 256)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.settimeout(8)
        sender.sendto(payload, ("127.0.0.1", sender_port))
        arrived = echo.wait(1, 8)

        time.sleep(0.3)
        handshake = relay.largest(Relay.HANDSHAKE)
        data = relay.largest(Relay.DATA, "out")  # the reply carries a prefix
        if not arrived or arrived[0] != payload:
            got = len(arrived[0]) if arrived else 0
            return False, (f"{got} of {len(payload)} bytes arrived; "
                           f"client: {client.signals()}")
        if not handshake:
            return False, f"the relay saw no handshake, only {relay.seen[:6]}"
        if handshake > expected:
            return False, (f"a handshake datagram of {handshake} bytes exceeds "
                           f"{expected}, the {link}-byte link less IP and UDP")
        if data != len(payload) + 29:
            return False, (f"{len(payload)} bytes of payload went out in a "
                           f"datagram of {data}, not one record's worth")
        return True, (f"handshake within {handshake} of {expected} "
                      f"({link} less IP and UDP), "
                      f"{len(payload)} bytes of data out whole in {data}")
    finally:
        client.stop()
        server.stop()
        relay.stop()
        echo.stop()


def record_limit(tmpd):
    """The one size a datagram cannot be: larger than a record.

    16384 bytes is what a DTLS record carries, and a datagram is carried in
    one record.  A datagram of exactly that size has to go through; a larger
    one has to be refused and said so, and the session has to survive it.
    """
    limit = 16384
    echo_port, tunnel_port, sender_port = free_port(), free_port(), free_port()
    server_thumb, client_thumb = gost_pair()

    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{sender_port}
connect = 127.0.0.1:{tunnel_port}
cert = {client_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.settimeout(8)
        full = bytes(range(256)) * (limit // 256)
        sender.sendto(full, ("127.0.0.1", sender_port))
        if echo.wait(1, 10)[:1] != [full]:
            return False, (f"a datagram of exactly {limit} bytes did not arrive; "
                           f"client: {client.signals()}")

        sender.sendto(bytes(limit + 616), ("127.0.0.1", sender_port))
        if not client.wait_for("larger than DTLS maximum plaintext", seconds=5):
            return False, "an oversized datagram was not refused: " + client.signals()

        sender.sendto(b"after", ("127.0.0.1", sender_port))
        got = echo.wait(2, 8)
        if len(got) < 2 or got[1] != b"after":
            return False, "the session did not survive the refusal: " + client.signals()
        return True, f"{limit} bytes carried, a larger datagram refused, session kept"
    finally:
        client.stop()
        server.stop()
        echo.stop()



def revocation(tmpd, mode):
    """What each verifyRevocation setting makes of a certificate with no CRL.

    The test certificates name neither a CRL nor an OCSP responder, which is
    the case the setting exists for: full has to refuse them, auto has to let
    them through and say why, and no switches the check off at the provider,
    after which there is no revocation status left to judge at all.
    """
    carries, said = {
        "full": (False, "msspi: verify failed (0x80092012)"),
        "auto": (True, "msspi: verify OK (CRYPT_E_NO_REVOCATION_CHECK)"),
        "no": (True, "msspi: verify OK"),
    }[mode]
    echo_port, tunnel_port, sender_port = free_port(), free_port(), free_port()
    server_thumb, client_thumb = gost_pair()

    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = {mode}
""")
    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{sender_port}
connect = 127.0.0.1:{tunnel_port}
cert = {client_thumb}
verifyChain = yes
verifyRevocation = {mode}
""")
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.settimeout(6)
        sender.sendto(b"through", ("127.0.0.1", sender_port))
        try:
            got, _ = sender.recvfrom(4096)
        except socket.timeout:
            got = b""
        verdict = [ln.split("]: ", 1)[-1].strip() for ln in client.text().splitlines()
                   if "msspi: verify" in ln]
        if not verdict:
            return False, "the client said nothing about verification"
        if verdict[-1] != said:
            return False, f"expected {said!r}, got {verdict[-1]!r}"
        if carries and got != b"echo:through":
            return False, f"nothing came back ({got!r}) though the chain verified"
        if not carries and got:
            return False, f"the tunnel carried data ({got!r}) after refusing the chain"
        return True, said + (", datagram through" if carries else ", nothing carried")
    finally:
        client.stop()
        server.stop()
        echo.stop()



def plaintext_burst(tmpd):
    """Two datagrams from the sender before the tunnel has accepted it.

    The first is what wakes the client tunnel; the rest are drained off the
    listening socket so they do not look like new peers. Both are plaintext
    and both belong to the far end, so both have to arrive there.
    """
    echo_port, tunnel_port, sender_port = free_port(), free_port(), free_port()
    server_thumb, client_thumb = gost_pair()

    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{sender_port}
connect = 127.0.0.1:{tunnel_port}
cert = {client_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.settimeout(8)
        sender.sendto(b"first", ("127.0.0.1", sender_port))
        sender.sendto(b"second", ("127.0.0.1", sender_port))

        got = echo.wait(2, 10)
        if got != [b"first", b"second"]:
            return False, (f"the far end saw {got}; client: {client.signals()}")
        return True, "both datagrams of the burst arrived, in order"
    finally:
        client.stop()
        server.stop()
        echo.stop()



class TcpEcho:
    """The plaintext endpoint of a TCP cascade."""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(4)
        self.received = []
        self.running = True
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def pump(self):
        while self.running:
            if not select.select([self.sock], [], [], 0.2)[0]:
                continue
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                try:
                    data = conn.recv(65536)
                except (socket.timeout, OSError):
                    continue
                if data:
                    self.received.append(data)
                    conn.sendall(b"echo:" + data)

    def stop(self):
        self.running = False
        self.sock.close()
        self.thread.join(timeout=2)


# What the matrix varies. A peer names who stands at the other end of the
# wire, and which end of the cascade it stands at.
TRANSPORTS = ("tcp", "udp")
FAMILIES = ("gost", "rsa")
AUTHS = ("server", "mutual")
PEERS = ("fork", "upstream-server", "upstream-client",
         "openssl-server", "openssl-client")

LEAF = {"gost": "gost", "rsa": "rsa_cpro"}
ROOT = {"gost": ("gost_ca.cer", "CN=stunnel test GOST CA"),
        "rsa": ("rsa_ca.cer", "CN=stunnel test RSA CA")}


def ours(tmpd, name, transport, role, accept, connect, thumb, verify):
    """One end of the cascade, built by this fork."""
    lines = [f"[{name}]"]
    if role == "client":
        lines.append("client = yes")
    if transport == "udp":
        lines.append("transport = udp")
    lines += [f"accept = 127.0.0.1:{accept}",
              f"connect = 127.0.0.1:{connect}",
              f"cert = {thumb}",
              "verifyRevocation = auto"]
    if verify:
        lines.append("verifyChain = yes")
    return Tunnel(tmpd, name, "\n".join(lines) + "\n")


def reference(tmpd, name, transport, role, accept, connect, who, verify):
    """The same end, built by upstream stunnel against OpenSSL."""
    lines = [f"[{name}]"]
    if role == "client":
        lines.append("client = yes")
    if transport == "udp":
        lines.append("transport = udp")
    lines += [f"accept = 127.0.0.1:{accept}",
              f"connect = 127.0.0.1:{connect}",
              f"cert = {PKI}/rsa_ossl_{who}.cer",
              f"key = {PKI}/rsa_ossl_{who}.key"]
    if verify:
        lines += ["verifyChain = yes", f"CAfile = {PKI}/rsa_ca.cer"]
    return Tunnel(tmpd, name, "\n".join(lines) + "\n", binary=REFERENCE)


def carry(transport, entry, payload=b"through"):
    """Put the payload into the near end of a cascade, take what comes back."""
    if transport == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(8)
        sock.sendto(payload, ("127.0.0.1", entry))
        try:
            back, _ = sock.recvfrom(65536)
        except socket.timeout:
            back = b""
        sock.close()
        return back
    try:
        with socket.create_connection(("127.0.0.1", entry), timeout=8) as sock:
            sock.settimeout(8)
            sock.sendall(payload)
            return sock.recv(65536)
    except (socket.timeout, OSError):
        return b""


def openssl_peer(tmpd, name, args, stdin=None):
    """A raw OpenSSL endpoint, kept with its output for the verdict."""
    out = open(os.path.join(tmpd, name + ".out"), "w+b")
    proc = subprocess.Popen([OPENSSL] + args, stdin=subprocess.PIPE,
                            stdout=out, stderr=subprocess.STDOUT)
    if stdin:
        proc.stdin.write(stdin)
        proc.stdin.flush()
    return proc, out


def matrix_cell(tmpd, transport, family, auth, peer):
    """One cell: a cascade of the given shape, carrying one payload."""
    if peer != "fork" and family != "rsa":
        return "skip", "stock OpenSSL has no GOST"
    if peer.startswith("upstream") and not os.access(REFERENCE, os.X_OK):
        return "FAIL", f"no reference stunnel at {REFERENCE} (STUNNEL_REFERENCE)"

    root, dn = ROOT[family]
    trust(root, dn)
    provtype = 24 if family == "rsa" else None
    server_thumb = identity(LEAF[family] + "_server", provtype)
    client_thumb = identity(LEAF[family] + "_client", provtype)
    mutual = auth == "mutual"

    kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
    echo_port, tunnel_port, entry_port = (
        free_port(kind), free_port(kind), free_port(kind))
    echo = Echo(echo_port) if transport == "udp" else TcpEcho(echo_port)
    parts, procs = [], []
    try:
        if peer in ("fork", "upstream-server"):
            far = (reference(tmpd, "far", transport, "server", tunnel_port,
                             echo_port, "server", mutual)
                   if peer == "upstream-server" else
                   ours(tmpd, "far", transport, "server", tunnel_port,
                        echo_port, server_thumb, mutual))
            near = ours(tmpd, "near", transport, "client", entry_port,
                        tunnel_port, client_thumb, True)
            parts += [far, near]
        elif peer == "upstream-client":
            far = ours(tmpd, "far", transport, "server", tunnel_port,
                       echo_port, server_thumb, mutual)
            near = reference(tmpd, "near", transport, "client", entry_port,
                             tunnel_port, "client", True)
            parts += [far, near]
        elif peer == "openssl-server":
            args = ["s_server", "-accept", f"127.0.0.1:{tunnel_port}",
                    "-cert", f"{PKI}/rsa_ossl_server.cer",
                    "-key", f"{PKI}/rsa_ossl_server.key", "-naccept", "1"]
            if transport == "udp":
                args.append("-dtls1_2")
            if mutual:
                args += ["-Verify", "1", "-CAfile", f"{PKI}/rsa_ca.cer"]
            procs.append(openssl_peer(tmpd, "far", args))
            time.sleep(1)
            near = ours(tmpd, "near", transport, "client", entry_port,
                        tunnel_port, client_thumb, True)
            parts.append(near)
        else:  # openssl-client
            far = ours(tmpd, "far", transport, "server", tunnel_port,
                       echo_port, server_thumb, mutual)
            parts.append(far)
            if not far.wait_for("Accepting new connections"):
                return "FAIL", "our server never came up: " + far.tail()
            args = ["s_client", "-connect", f"127.0.0.1:{tunnel_port}",
                    "-CAfile", f"{PKI}/rsa_ca.cer", "-verify_return_error",
                    "-ign_eof"]
            if transport == "udp":
                args.append("-dtls1_2")
            if mutual:
                args += ["-cert", f"{PKI}/rsa_ossl_client.cer",
                         "-key", f"{PKI}/rsa_ossl_client.key"]
            procs.append(openssl_peer(tmpd, "near", args, b"through\n"))

        for part in parts:
            if not part.wait_for("Accepting new connections"):
                return "FAIL", "a tunnel never came up: " + part.tail()

        if peer == "openssl-server":
            carry(transport, entry_port)
            deadline = time.time() + 8
            while time.time() < deadline:
                procs[0][1].seek(0)
                if b"through" in procs[0][1].read():
                    return "ok", "the payload reached the OpenSSL end"
                time.sleep(0.2)
            return "FAIL", "the OpenSSL end never saw the payload"

        if peer == "openssl-client":
            deadline = time.time() + 10
            while time.time() < deadline:
                procs[0][1].seek(0)
                if b"echo:through" in procs[0][1].read():
                    return "ok", "the OpenSSL end got its reply"
                time.sleep(0.2)
            return "FAIL", "the OpenSSL end never got a reply: " + parts[0].signals()

        back = carry(transport, entry_port)
        if back != b"echo:through":
            return "FAIL", (f"got {back!r}; " +
                            " || ".join(p.signals() for p in parts))
        return "ok", "carried"
    finally:
        for part in parts:
            part.stop()
        for proc, out in procs:
            proc.kill()
            proc.wait()
            out.close()
        echo.stop()


MATRIX = [(t, f, a, p) for t in TRANSPORTS for f in FAMILIES
          for a in AUTHS for p in PEERS]



def refused_options(tmpd):
    """Options this build does not enforce have to be refused, not swallowed.

    checkIP and checkEmail would need a certificate taken apart here, which
    is not how verification works in this build. Accepting them would leave
    a configuration that promises a check nobody makes.
    """
    for option, value in (("checkIP", "10.0.0.1"), ("checkEmail", "a@b.c")):
        tunnel = Tunnel(tmpd, "refused", f"""
[refused]
client = yes
accept = 127.0.0.1:{free_port()}
connect = 127.0.0.1:{free_port()}
verifyChain = yes
{option} = {value}
""")
        try:
            tunnel.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            tunnel.stop()
            return False, f"{option} was accepted"
        said = tunnel.text() + open(tunnel.err, encoding="utf-8", errors="replace").read()
        if "Not supported" not in said:
            return False, f"{option} was refused without saying why: {said[-200:]}"
    return True, "checkIP and checkEmail are refused at the configuration"



def starved_timer(tmpd):
    """A peer that keeps the socket readable must not starve the timer.

    RFC 6347 puts the retransmission on a timer, not on the absence of
    input. Here the peer never carries the handshake forward but keeps
    sending records the provider discards, so every poll finds something to
    read. The ClientHello still has to go again.
    """
    busy, watch = 20, 7
    peer_port, wake_port = free_port(), free_port()
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", peer_port))
    hellos = []
    running = True

    def noise():
        # application data: the handshake discards it without failing
        record = b"\x17\xfe\xfd" + bytes(8) + b"\x00\x04idle"
        where = None
        while running:
            ready = select.select([peer], [], [], 0.001)[0]
            if ready:
                data, where = peer.recvfrom(65535)
                if data and data[0] == 22 and len(data) > 13 and data[13] == 1:
                    hellos.append(time.time())
            if where:
                # no gaps: the socket at the other end must never be found
                # empty, which is what a starved timer needs
                for _ in range(50):
                    peer.sendto(record, where)
    thread = threading.Thread(target=noise, daemon=True)
    thread.start()

    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{wake_port}
connect = 127.0.0.1:{peer_port}
TIMEOUThandshake = {busy}
verify = 0
""")
    try:
        if not client.wait_for("Accepting new connections"):
            return False, "the client tunnel never came up: " + client.tail()
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.sendto(b"wake", ("127.0.0.1", wake_port))
        time.sleep(watch)
        if not hellos:
            return False, "the peer never saw a ClientHello"
        if len(hellos) < 2:
            return False, (f"one ClientHello in {watch}s and no more: the timer "
                           "is starved while the socket stays readable")
        return True, f"{len(hellos)} ClientHellos in {watch}s, the timer kept its own time"
    finally:
        client.stop()
        running = False
        thread.join(timeout=2)
        peer.close()


def held_seconds(tunnel):
    """How long the log says the session lasted, or None if it does not say."""
    def stamp(needle):
        for line in tunnel.text().splitlines():
            if needle in line:
                hh, mm, ss = line.split()[1].split(":")
                return int(hh) * 3600 + int(mm) * 60 + int(ss)
        return None

    began, ended = stamp("accepted connection"), stamp("the handshake ran out of time")
    if began is None or ended is None:
        return None
    return ended - began if ended >= began else ended - began + 86400


def unproven_leash(tmpd):
    """A peer that has not answered the cookie is held for seconds, not minutes.

    A first fragment of a ClientHello and a datagram shaped like one are the
    same thing to the listener, so the session starts either way - but until
    the provider answers, it is held on TIMEOUTcookie.
    """
    busy, cookie = 30, 3
    echo_port, tunnel_port = free_port(), free_port()
    server_thumb, _ = gost_pair()
    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
TIMEOUThandshake = {busy}
TIMEOUTcookie = {cookie}
""")
    try:
        if not server.wait_for("Accepting new connections"):
            return False, "the server tunnel never came up: " + server.tail()

        # a record whose fragment is a fragment of nothing
        hm = bytes([1]) + (200).to_bytes(3, "big") + bytes(2) + bytes(3) + \
            (50).to_bytes(3, "big") + bytes(50)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.sendto(b"\x16\xfe\xfd" + bytes(8) + len(hm).to_bytes(2, "big") + hm,
                     ("127.0.0.1", tunnel_port))

        if not server.wait_for("the handshake ran out of time", seconds=busy - 5):
            return False, f"the session outlived TIMEOUTcookie of {cookie}s"

        held = held_seconds(server)
        if held is None:
            return False, "the log does not say when the session began or ended"
        if not cookie <= held <= cookie + 2:
            return False, (f"the session was held {held}s, which is neither "
                           f"TIMEOUTcookie of {cookie}s nor an accident")
        probe.close()
        return True, f"held {held}s on TIMEOUTcookie of {cookie}s, not {busy}s"
    finally:
        server.stop()
        echo.stop()


def port_reuse(tmpd, upstream):
    """What a peer that comes back on the same source port gets.

    A DTLS server tells sessions apart by the peer's address, so a second
    ClientHello from an address that already has a session lands inside that
    session instead of starting one.  The peer is locked out until the old
    session goes idle, which is TIMEOUTidle - the same in the fork and in
    upstream stunnel, so the run says what each of them does.
    """
    idle = 5
    echo_port, tunnel_port = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_DGRAM)
    source_port = free_port(socket.SOCK_DGRAM)
    trust(*ROOT["rsa"])
    echo = Echo(echo_port)
    if upstream:
        if not os.access(REFERENCE, os.X_OK):
            return False, f"no reference stunnel at {REFERENCE}"
        identity_lines = (f"cert = {PKI}/rsa_ossl_server.cer\n"
                          f"key = {PKI}/rsa_ossl_server.key\n")
    else:
        identity_lines = f"cert = {identity('rsa_cpro_server', 24)}\n"
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
{identity_lines}TIMEOUTidle = {idle}
""", binary=REFERENCE if upstream else None)

    def knock(name, seconds):
        """One s_client from the same source port; did a datagram come back?"""
        proc, out = openssl_peer(tmpd, name, [
            "s_client", "-dtls1_2", "-connect", f"127.0.0.1:{tunnel_port}",
            "-bind", f"127.0.0.1:{source_port}",
            "-CAfile", f"{PKI}/rsa_ca.cer", "-verify_return_error", "-ign_eof"],
            stdin=name.encode() + b"\n")
        until = time.time() + seconds
        while time.time() < until:
            out.seek(0)
            if b"echo:" + name.encode() in out.read():
                proc.kill()
                proc.wait()
                return True
            time.sleep(0.2)
        proc.kill()
        proc.wait()
        return False

    try:
        if not server.wait_for("Accepting new connections"):
            return False, "the server tunnel never came up: " + server.tail()
        if not knock("first", 15):
            return False, "the first peer never got its datagram back"
        again = knock("again", idle - 1)
        time.sleep(idle + 2)
        back = knock("back", 15)
        watchdog = "report the problem" in server.text()

        which = "upstream stunnel" if upstream else "the fork"
        if again:
            return False, (f"{which} let the source port be reused while the "
                           "session was still alive")
        if not back:
            return False, (f"{which} did not let the peer back after "
                           f"TIMEOUTidle of {idle}s")
        return True, (f"{which}: locked out while the session lived, back in "
                      f"after TIMEOUTidle of {idle}s"
                      + (", and its watchdog asked for a bug report"
                         if watchdog else ""))
    finally:
        server.stop()
        echo.stop()


def flooded_leash(tmpd):
    """A peer that never lets the socket run dry must not hold the session.

    The leash is checked between calls into the provider.  The provider reads
    and discards application records for as long as one is waiting, so a peer
    that keeps the socket readable can keep the call from ever returning.
    What this measures is what a handful of unbatched senders on the loopback
    can do: they send one datagram per system call, while a peer that batches
    them into the kernel would push harder.
    """
    busy, cookie, flood_seconds, senders = 30, 3, 10, 8
    echo_port, tunnel_port = free_port(), free_port()
    server_thumb, _ = gost_pair()
    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
TIMEOUThandshake = {busy}
TIMEOUTcookie = {cookie}
""")
    try:
        if not server.wait_for("Accepting new connections"):
            return False, "the server tunnel never came up: " + server.tail()

        # a first fragment: enough to buy a session, never enough to finish
        hm = bytes([1]) + (200).to_bytes(3, "big") + bytes(2) + bytes(3) + \
            (50).to_bytes(3, "big") + bytes(50)
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer = ("127.0.0.1", tunnel_port)
        probe.sendto(b"\x16\xfe\xfd" + bytes(8) + len(hm).to_bytes(2, "big") + hm,
                     peer)

        # separate processes rather than threads: sending is a system call
        # per datagram, and threads of one interpreter take turns at it
        source = """
import os, socket, sys, time
fd, seconds, size = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_DGRAM)
record = b"\\x17\\xfe\\xfd" + bytes(8) + size.to_bytes(2, "big") + bytes(size)
until, sent = time.time() + seconds, 0
try:
    while time.time() < until:
        for _ in range(200):
            sock.send(record)
            sent += 1
except OSError:
    pass
os.write(1, str(sent).encode())
"""
        probe.connect(peer)
        pumps = [subprocess.Popen(
            [sys.executable, "-c", source, str(probe.fileno()),
             str(flood_seconds), "1400"],
            stdout=subprocess.PIPE, pass_fds=(probe.fileno(),))
            for _ in range(senders)]
        time.sleep(0.3)

        held = None
        if server.wait_for("the handshake ran out of time", seconds=busy - 5):
            held = held_seconds(server)
        under = 0
        for pump in pumps:
            out, _ = pump.communicate(timeout=flood_seconds + 5)
            under += int(out or 0)
        probe.close()

        if under < 10000:
            return False, f"the flood never got going: {under} records sent"
        if held is None:
            return False, (f"the session outlived the flood entirely "
                           f"({under} records sent)")
        if held > cookie + 2:
            return False, (f"the flood held the session {held}s on a "
                           f"TIMEOUTcookie of {cookie}s ({under} records sent)")
        return True, (f"held {held}s on TIMEOUTcookie of {cookie}s "
                      f"under {under} records from {senders} processes")
    finally:
        server.stop()
        echo.stop()


def harvest_client_hello(tmpd):
    """One real ClientHello, taken off a client tunnel that has nobody to talk to."""
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer_port = peer.getsockname()[1]
    wake_port = free_port()
    client = Tunnel(tmpd, "harvest", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{wake_port}
connect = 127.0.0.1:{peer_port}
verify = 0
""")
    try:
        if not client.wait_for("Accepting new connections"):
            return None
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(
            b"wake", ("127.0.0.1", wake_port))
        peer.settimeout(8)
        try:
            data, _ = peer.recvfrom(65535)
        except socket.timeout:
            return None
        return data
    finally:
        client.stop()
        peer.close()


def unproven_after_hello(tmpd):
    """A whole ClientHello without a cookie answers nothing about the peer.

    The provider replies to it with a HelloVerifyRequest, which is exactly
    what it sends to a peer that has proved nothing - so that reply must not
    take the leash off. Sent in two fragments so that the session starts
    before the provider has anything to say.
    """
    busy, cookie = 30, 3
    hello = harvest_client_hello(tmpd)
    if not hello:
        return False, "could not take a ClientHello off a client tunnel"

    echo_port, tunnel_port = free_port(), free_port()
    server_thumb, _ = gost_pair()
    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
TIMEOUThandshake = {busy}
TIMEOUTcookie = {cookie}
""")
    try:
        if not server.wait_for("Accepting new connections"):
            return False, "the server tunnel never came up: " + server.tail()

        body = hello[25:]                      # the ClientHello itself
        msg_len = len(body)
        cut = msg_len // 2

        def fragment(seq, offset, piece):
            hm = (bytes([1]) + msg_len.to_bytes(3, "big") + bytes(2) +
                  offset.to_bytes(3, "big") + len(piece).to_bytes(3, "big") + piece)
            return (b"\x16\xfe\xfd" + bytes(6) + seq.to_bytes(2, "big") +
                    len(hm).to_bytes(2, "big") + hm)

        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        attacker.settimeout(5)
        attacker.sendto(fragment(0, 0, body[:cut]), ("127.0.0.1", tunnel_port))
        time.sleep(0.5)
        attacker.sendto(fragment(1, cut, body[cut:]), ("127.0.0.1", tunnel_port))

        # HELLO_VERIFY_REQUEST is 3, and it is the answer being tested: any
        # other one would mean the scenario proved something else.
        try:
            reply, _ = attacker.recvfrom(65535)
        except socket.timeout:
            return False, "the provider answered the whole ClientHello with nothing"
        if len(reply) < 14 or reply[0] != 22 or reply[13] != 3:
            return False, (f"the answer was not a HelloVerifyRequest: "
                           f"record {reply[0]}, message {reply[13] if len(reply) > 13 else None}")

        if not server.wait_for("the handshake ran out of time", seconds=busy - 5):
            return False, (f"the session outlived TIMEOUTcookie of {cookie}s: a "
                           "HelloVerifyRequest took the leash off")
        held = held_seconds(server)
        attacker.close()
        if held is None or held > cookie + 2:
            return False, (f"the session was held {held}s, which is not the "
                           f"TIMEOUTcookie of {cookie}s")
        return True, (f"a HelloVerifyRequest did not take the leash off: "
                      f"held {held}s of {cookie}s")
    finally:
        server.stop()
        echo.stop()


def leash_lifts(tmpd):
    """A peer that answers the cookie stops being held on the short one.

    The reference client fragments its ClientHello, so its session starts
    before the provider has said anything and is held on TIMEOUTcookie. A
    relay lets the cookie come back at once and then slows everything after
    the ServerHello, so the handshake outlives the leash and can only finish
    if the ServerHello took it off.
    """
    if not os.access(REFERENCE, os.X_OK):
        return False, f"no reference stunnel at {REFERENCE} (STUNNEL_REFERENCE)"

    cookie, busy = 1, 30
    echo_port, relay_port, tunnel_port, entry_port = (
        free_port(), free_port(), free_port(), free_port())
    trust("rsa_ca.cer", "CN=stunnel test RSA CA")
    server_thumb = identity("rsa_cpro_server", 24)

    echo = Echo(echo_port)
    relay = Relay(relay_port, tunnel_port, delay=0.6)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
TIMEOUThandshake = {busy}
TIMEOUTcookie = {cookie}
""")
    client = reference(tmpd, "client", "udp", "client", entry_port, relay_port,
                       "client", True)
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()

        began = time.monotonic()
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.sendto(b"through", ("127.0.0.1", entry_port))

        if not server.wait_for("DTLSv1.2 accepted", seconds=busy - 5):
            return False, (f"the handshake never finished; the leash of "
                           f"{cookie}s was never taken off: " + server.signals())
        took = time.monotonic() - began
        sender.close()
        if took <= cookie:
            return False, f"the handshake took {took:.1f}s, under the leash of {cookie}s"
        return True, f"handshake finished after {took:.1f}s, past the leash of {cookie}s"
    finally:
        client.stop()
        server.stop()
        relay.stop()
        echo.stop()


def spoofed_hellos(tmpd):
    """A datagram that only looks like a ClientHello must buy nothing.

    The cookie exchange exists so that a source proves it can receive before
    anything is allocated for it. Two shapes get as far as the listener: a
    record too short to hold a handshake header, and a fragment that claims
    to continue a message rather than to begin one.
    """
    echo_port, tunnel_port = free_port(), free_port()
    server_thumb, _ = gost_pair()
    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
""")
    try:
        if not server.wait_for("Accepting new connections"):
            return False, "the server tunnel never came up: " + server.tail()

        def record(hm):
            return b"\x16\xfe\xfd" + bytes(8) + len(hm).to_bytes(2, "big") + hm

        stubs = {
            # record type 22 and handshake type 1 where the listener looks for
            # them, and nothing else
            "truncated": b"\x16\xfe\xfd" + bytes(8) + b"\x00\x01" + b"\x01",
            # a fragment that claims to continue a message: it belongs to a
            # session that exists, and must not start another one
            "a later fragment": record(
                bytes([1]) + (200).to_bytes(3, "big") + bytes(2) +
                (100).to_bytes(3, "big") + (50).to_bytes(3, "big") + bytes(50)),
        }
        for stub in stubs.values():
            for _ in range(10):
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe.sendto(stub, ("127.0.0.1", tunnel_port))
                probe.close()
        time.sleep(2)

        started = [ln for ln in server.text().splitlines()
                   if "accepted connection from" in ln]
        if started:
            return False, (f"{len(started)} session(s) started for a datagram "
                           "that is not a ClientHello")
        return True, "neither a truncated record nor a later fragment bought a session"
    finally:
        server.stop()
        echo.stop()



def fallback_name(tmpd, names, carries):
    """A name from checkHost has to answer the name question and only it.

    The provider returns one status, and a name mismatch outranks whatever
    else the chain has to say. Once a name from checkHost matches, what is
    left is for verifyRevocation to judge - and these certificates name no
    way to check revocation, which auto is meant to accept.
    """
    echo_port, tunnel_port, sender_port = free_port(), free_port(), free_port()
    server_thumb, client_thumb = gost_pair()
    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
""")
    checks = "".join(f"checkHost = {name}\n" for name in names)
    client = Tunnel(tmpd, "client", f"""
[dtls-client]
client = yes
transport = udp
accept = 127.0.0.1:{sender_port}
connect = 127.0.0.1:{tunnel_port}
cert = {client_thumb}
sni = a.name.the.certificate.does.not.carry
verifyChain = yes
verifyRevocation = auto
{checks}""")
    try:
        for tunnel, which in ((client, "client"), (server, "server")):
            if not tunnel.wait_for("Accepting new connections"):
                return False, f"the {which} tunnel never came up: " + tunnel.tail()
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.settimeout(6)
        sender.sendto(b"through", ("127.0.0.1", sender_port))
        try:
            got, _ = sender.recvfrom(4096)
        except socket.timeout:
            got = b""
        verdict = [ln.split("]: ", 1)[-1].strip() for ln in client.text().splitlines()
                   if "msspi: verify" in ln]
        said = verdict[-1] if verdict else "(nothing)"
        if carries and got != b"echo:through":
            return False, f"nothing came back ({got!r}); the client said {said!r}"
        if not carries and got:
            return False, f"the tunnel carried data ({got!r}) though no name matched"
        return True, said
    finally:
        client.stop()
        server.stop()
        echo.stop()



def server_rejects_client(tmpd):
    """Our server has to refuse a client certificate it cannot chain.

    Every other scenario gives the server a peer it should accept, so a
    server that stopped verifying at all would pass them. Here the root of
    the client's certificate is trusted nowhere while the client presents
    its certificate anyway, and what must not happen is the payload
    arriving.
    """
    root, dn = "rsa_ca.cer", "CN=stunnel test RSA CA"
    trust(root, dn)                       # the identities go in while it is trusted
    server_thumb = identity("rsa_cpro_server", 24)
    echo_port, tunnel_port = free_port(), free_port()
    untrust(dn)

    echo = Echo(echo_port)
    server = Tunnel(tmpd, "server", f"""
[dtls-server]
transport = udp
accept = 127.0.0.1:{tunnel_port}
connect = 127.0.0.1:{echo_port}
cert = {server_thumb}
verifyChain = yes
verifyRevocation = auto
""")
    proc = None
    try:
        if not server.wait_for("Accepting new connections"):
            return False, "the server tunnel never came up: " + server.tail()

        proc = openssl_peer(tmpd, "client", [
            "s_client", "-dtls1_2", "-connect", f"127.0.0.1:{tunnel_port}",
            "-cert", f"{PKI}/rsa_ossl_client.cer",
            "-key", f"{PKI}/rsa_ossl_client.key",
            "-CAfile", f"{PKI}/rsa_ca.cer", "-ign_eof"], b"through\n")

        if not server.wait_for("msspi: verify", seconds=10):
            return False, "the server said nothing about the certificate it was given"
        verdict = [ln.split("]: ", 1)[-1].strip() for ln in server.text().splitlines()
                   if "msspi: verify" in ln][-1]
        # the PFX import leaves the root in uMy, so the chain still builds -
        # and ends at a root trusted nowhere
        if verdict != "msspi: verify failed (0x800B0109)":
            return False, f"expected an untrusted root, got {verdict!r}"
        if echo.received:
            return False, f"the payload reached the far end anyway: {echo.received[0]!r}"
        return True, verdict
    finally:
        if proc:
            proc[0].kill()
            proc[0].wait()
            proc[1].close()
        server.stop()
        echo.stop()
        trust(root, dn)


SCENARIOS = [
    ("TLS round trip", tls_round_trip),
    ("DTLS round trips", dtls_round_trips),
    ("DTLS round trips, a handshake datagram dropped",
     lambda d: dtls_round_trips(d, drop_nth=3)),
    ("a peer that never answers", lambda d: abandoned_peer(d, noisy=False)),
    ("a peer that answers without progressing", lambda d: abandoned_peer(d, noisy=True)),
    ("a plaintext burst into the client tunnel", plaintext_burst),
    ("a peer that starves the retransmission timer", starved_timer),
    ("datagrams that only look like a ClientHello", spoofed_hellos),
    ("a peer that has not answered the cookie", unproven_leash),
    ("a cookie-less ClientHello in fragments", unproven_after_hello),
    ("a peer that floods records at the handshake", flooded_leash),
    ("a peer that comes back on the same source port",
     lambda d: port_reuse(d, upstream=False)),
    ("upstream stunnel, the same source port again",
     lambda d: port_reuse(d, upstream=True)),
    ("a peer that answers the cookie", leash_lifts),
    ("our server refuses a client it cannot chain", server_rejects_client),
    ("GOST mutual auth, root trusted", lambda d: mutual_auth(d, True, "gost")),
    ("GOST mutual auth, root not trusted", lambda d: mutual_auth(d, False, "gost")),
    ("RSA mutual auth, root trusted", lambda d: mutual_auth(d, True, "rsa")),
    ("RSA mutual auth, root not trusted", lambda d: mutual_auth(d, False, "rsa")),
    ("DTLSmtu default", lambda d: mtu_bounds(d, None)),
    ("DTLSmtu = 400", lambda d: mtu_bounds(d, 400)),
    ("DTLSmtu = 1400", lambda d: mtu_bounds(d, 1400)),
    ("a datagram at the record limit and past it", record_limit),
    ("options this build does not enforce", refused_options),
    ("checkHost names the certificate carries",
     lambda d: fallback_name(d, ["127.0.0.1"], True)),
    ("checkHost names it does not",
     lambda d: fallback_name(d, ["nowhere.example"], False)),
    ("verifyRevocation = full", lambda d: revocation(d, "full")),
    ("verifyRevocation = auto", lambda d: revocation(d, "auto")),
    ("verifyRevocation = no", lambda d: revocation(d, "no")),
]


def main():
    only = sys.argv[1:]
    prepare_csp()
    failed = skipped = 0

    matrix = [] if only else MATRIX
    scenarios = [(name, run) for name, run in SCENARIOS
                 if not only or any(word in name for word in only)]

    if only and not scenarios:
        print(f"no scenario matches {' '.join(only)}", flush=True)
        return 1

    print("=== matrix ===", flush=True)
    for transport, family, auth, peer in matrix:
        shape = f"{transport:3} {family:4} {auth:6} {peer:15}"
        with tempfile.TemporaryDirectory(prefix="msspi-cell.") as tmpd:
            try:
                status, why = matrix_cell(tmpd, transport, family, auth, peer)
            except Exception as exc:
                status, why = "FAIL", f"{type(exc).__name__}: {exc}"
        print(f"{status:4}  {shape} {why}", flush=True)
        failed += 1 if status == "FAIL" else 0
        skipped += 1 if status == "skip" else 0

    print("\n=== torture ===", flush=True)
    for name, run in scenarios:
        with tempfile.TemporaryDirectory(prefix="msspi-test.") as tmpd:
            try:
                ok, why = run(tmpd)
            except Exception as exc:  # a scenario must not take the run down
                ok, why = False, f"{type(exc).__name__}: {exc}"
            print(f"{'ok  ' if ok else 'FAIL'}  {name}: {why}", flush=True)
            failed += 0 if ok else 1
    total = len(matrix) + len(scenarios)
    print(f"\n{total - failed - skipped} of {total} passed, "
          f"{skipped} skipped, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
