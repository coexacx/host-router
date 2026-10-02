#!/usr/bin/env python3
"""Real Linux netem/DNS fault tests. Run only in private network + mount namespaces.

sudo unshare --net --mount --propagation private \
    .venv/bin/python tests/network_faults.py /absolute/path/to/host-router

No host interfaces, routes, sysctls or services are modified. All router listeners
and synthetic targets exist only inside the temporary namespaces.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import pathlib
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

from aioquic.asyncio import connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion
from dnslib import A, DNSRecord, QTYPE, RCODE, RR
from integration import cert_files

RESULTS = []


def run(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True)


async def ready(path, process):
    for _ in range(250):
        if path.exists():
            return
        assert process.poll() is None, f"child exited: {process.returncode}"
        await asyncio.sleep(.02)
    raise TimeoutError(str(path))


async def backend(root):
    (root / "namespace-ready").touch()
    while not (root / "network-ready").exists():
        await asyncio.sleep(.01)

    async def echo(reader, writer):
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            path = header.split(b" ")[1]
            if path == b"/reset":
                writer.get_extra_info("socket").setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                writer.transport.abort()
                return
            if path == b"/slow":
                await asyncio.sleep(1.5)
            tag = b"B:" if writer.get_extra_info("sockname")[0].endswith(".3") else b"A:"
            if path == b"/half":
                data = await reader.read()
                writer.write(tag + header + data)
                await writer.drain()
            else:
                writer.write(tag + header)
                await writer.drain()
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def qecho(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(), 30)
            writer.write(b"Q:" + data)
            writer.write_eof()
            await writer.drain()
        except (Exception, asyncio.CancelledError):
            pass

    servers = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(root / "cert.pem", root / "key.pem")
    for ip in ["10.203.0.2", "10.203.0.3"]:
        servers.append(await asyncio.start_server(echo, ip, 29401))
        servers.append(await asyncio.start_server(echo, ip, 29402, ssl=ctx))
    cfg = QuicConfiguration(is_client=False, alpn_protocols=["fault-test"], idle_timeout=12)
    cfg.load_cert_chain(root / "cert.pem", root / "key.pem")
    servers.append(await serve("10.203.0.2", 29401, configuration=cfg,
                               stream_handler=lambda r, w: asyncio.create_task(qecho(r, w))))
    (root / "backend-ready").touch()
    try:
        await asyncio.Event().wait()
    finally:
        for server in servers:
            server.close()


class Dns(asyncio.DatagramProtocol):
    def __init__(self):
        self.mode = "ok"
        self.addresses = ["10.203.0.2"]
        self.delay = 0
        self.queries = 0
        self.transport = None
        self.handles = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        request = DNSRecord.parse(data)
        self.queries += 1
        if self.mode == "drop":
            return
        reply = request.reply()
        if self.mode == "nxdomain":
            reply.header.rcode = RCODE.NXDOMAIN
        elif self.mode == "servfail":
            reply.header.rcode = RCODE.SERVFAIL
        elif request.q.qtype == QTYPE.A:
            for address in self.addresses:
                reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=1, rdata=A(address)))
        packet = reply.pack()
        self.handles.append(asyncio.get_running_loop().call_later(
            self.delay, self.transport.sendto, packet, peer))


class Suite:
    def __init__(self, binary, root, backend_process, router_process, dns):
        self.binary = binary
        self.root = root
        self.backend = backend_process
        self.router = router_process
        self.dns = dns
        self.path = root / "config.json"

    def status(self):
        return json.loads(run(self.binary, "-c", self.path, "status").stdout)

    def netem(self, *args, ingress=False):
        if ingress:
            if args:
                run("tc", "qdisc", "replace", "dev", "lo", "root", "netem", "limit", 4096, *args)
            else:
                subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], capture_output=True)
            return
        for prefix, device in [([], "hr-front"), (["nsenter", "-t", str(self.backend.pid), "-n"], "hr-back")]:
            if args:
                run(*prefix, "tc", "qdisc", "replace", "dev", device,
                    "root", "netem", "limit", 4096, *args)
            else:
                subprocess.run(prefix + ["tc", "qdisc", "del", "dev", device, "root"], capture_output=True)

    async def tcp_open(self, host="a.test", path="/", tls=False):
        ctx = None
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            host = "tls.test"
        r, w = await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", 29301, ssl=ctx, server_hostname=host if ctx else None), 8)
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
        try:
            w.write(request)
            await w.drain()
            response = await asyncio.wait_for(r.readexactly(2 + len(request)), 10)
            assert response in [b"A:" + request, b"B:" + request], response
            return r, w, response[:2]
        except BaseException:
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
            raise

    async def tcp_exchange(self, host="a.test", tls=False, size=65536, path="/"):
        r, w, tag = await self.tcp_open(host, path, tls)
        data = os.urandom(size)
        try:
            w.write(data)
            await w.drain()
            received = await asyncio.wait_for(r.readexactly(len(data)), 20)
            assert hashlib.sha256(received).digest() == hashlib.sha256(data).digest()
            return tag
        finally:
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()

    def qconfig(self, version=QuicProtocolVersion.VERSION_1):
        return QuicConfiguration(is_client=True, alpn_protocols=["fault-test"],
            server_name="a.test", verify_mode=ssl.CERT_NONE, supported_versions=[version],
            idle_timeout=12, quantum_readiness_test=True)

    async def qexchange(self, q, size=16384):
        r, w = await q.create_stream()
        payload = os.urandom(size)
        w.write(payload)
        w.write_eof()
        await w.drain()
        reply = await asyncio.wait_for(r.read(), 20)
        assert reply == b"Q:" + payload

    async def quic(self, version=QuicProtocolVersion.VERSION_1):
        async with connect("127.0.0.1", 29301, configuration=self.qconfig(version)) as q:
            await self.qexchange(q)

    async def clean(self, seconds=12):
        deadline = time.monotonic() + seconds
        while True:
            stats = self.status()
            keys = ["tcp_active", "udp_active", "pending_handshakes", "queued_udp_bytes", "tracked_ips"]
            if all(stats[k] == 0 for k in keys):
                return {k: stats[k] for k in keys}
            assert self.router.poll() is None, "router exited"
            assert time.monotonic() < deadline, stats
            await asyncio.sleep(.1)

    async def normal(self):
        await self.tcp_exchange()
        await self.tcp_exchange(tls=True)
        await self.quic()
        return await self.clean()

    async def weak_network(self):
        self.netem("delay", "40ms", "10ms", "loss", "2%", "duplicate", "1%", "reorder", "20%", "50%")
        try:
            await self.tcp_exchange()
            await self.tcp_exchange(tls=True)
            await self.quic(QuicProtocolVersion.VERSION_1)
            await self.quic(QuicProtocolVersion.VERSION_2)
        finally:
            self.netem()
        return await self.clean()

    async def ingress_loss(self):
        self.netem("delay", "20ms", "loss", "1%", ingress=True)
        try:
            await self.tcp_exchange()
            await self.quic()
        finally:
            self.netem(ingress=True)
        return await self.clean()

    async def recover_same_sessions(self):
        r, w, _ = await self.tcp_open()
        try:
            async with connect("127.0.0.1", 29301, configuration=self.qconfig()) as q:
                await self.qexchange(q)
                self.netem("loss", "100%")
                payload = os.urandom(8192)
                w.write(payload)
                await w.drain()
                read = asyncio.create_task(r.readexactly(len(payload)))
                quic = asyncio.create_task(self.qexchange(q))
                await asyncio.sleep(2)
                assert not read.done(), "blackhole did not suppress TCP traffic"
                self.netem()
                assert await asyncio.wait_for(read, 15) == payload
                await asyncio.wait_for(quic, 15)
        finally:
            self.netem()
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
        return await self.clean()

    async def target_faults(self):
        # Refused target and blackholed target must release every admission token.
        for host in ["refused.test", "blackhole.test"]:
            started = time.monotonic()
            results = await asyncio.gather(*(self.tcp_exchange(host, size=64) for _ in range(12)),
                                           return_exceptions=True)
            assert all(isinstance(x, Exception) for x in results), results
            assert time.monotonic() - started < 4, host
            await self.tcp_exchange()
        # Reset on a live backend is an error, not a service crash.
        results = await asyncio.gather(*(self.tcp_exchange(path="/reset") for _ in range(12)),
                                       return_exceptions=True)
        assert all(isinstance(x, Exception) for x in results), results
        await self.tcp_exchange()
        return await self.clean()

    async def half_close_and_backpressure(self):
        r, w = await asyncio.open_connection("127.0.0.1", 29301)
        header = b"GET /half HTTP/1.1\r\nHost: a.test\r\n\r\n"
        payload = os.urandom(256 * 1024)
        w.write(header + payload)
        await w.drain()
        w.write_eof()
        assert await asyncio.wait_for(r.read(), 10) == b"A:" + header + payload
        w.close()
        await w.wait_closed()
        # Queue the body before waiting for the response. The backend deliberately
        # stops consuming for 1.5 s, exercising relay backpressure rather than just
        # a delayed response followed by an ordinary upload.
        r, w = await asyncio.open_connection("127.0.0.1", 29301)
        header = b"GET /slow HTTP/1.1\r\nHost: a.test\r\n\r\n"
        payload = os.urandom(8 * 1024 * 1024)
        started = time.monotonic()
        w.write(header + payload)
        _, reply = await asyncio.wait_for(
            asyncio.gather(w.drain(), r.readexactly(2 + len(header) + len(payload))), 15)
        assert reply == b"A:" + header + payload
        assert time.monotonic() - started >= 1.4
        w.close()
        await w.wait_closed()
        # A client that disappears during sniffing must not hold a slot.
        for _ in range(32):
            _, w = await asyncio.open_connection("127.0.0.1", 29301)
            w.write(b"GET ")
            await w.drain()
            w.transport.abort()
        return await self.clean()

    async def dns_outage(self):
        self.dns.mode = "ok"
        self.dns.addresses = ["10.203.0.2"]
        assert await self.tcp_exchange("dns.test") == b"A:"
        r, w, _ = await self.tcp_open("dns.test")
        try:
            await asyncio.sleep(1.1)
            self.dns.mode = "drop"
            started = time.monotonic()
            tasks = [asyncio.create_task(self.tcp_exchange("dns.test", size=16)) for _ in range(24)]
            await self.tcp_exchange()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert all(isinstance(x, Exception) for x in results), results
            assert time.monotonic() - started < 4.5
            w.write(b"existing")
            await w.drain()
            assert await asyncio.wait_for(r.readexactly(8), 2) == b"existing"
            self.dns.mode = "ok"
            self.dns.addresses = ["10.203.0.3"]
            await asyncio.sleep(2.2)
            assert await self.tcp_exchange("dns.test") == b"B:"
            w.write(b"pinned")
            await w.drain()
            assert await asyncio.wait_for(r.readexactly(6), 2) == b"pinned"
        finally:
            self.dns.mode = "ok"
            self.dns.addresses = ["10.203.0.2"]
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
        return await self.clean()

    async def dns_fallback(self):
        # DNS consumes part of the *same* overall connect timeout. The first
        # address blackholes; a healthy second address must still get a turn.
        self.dns.mode = "ok"
        self.dns.addresses = ["10.203.0.99", "10.203.0.2"]
        self.dns.delay = 1.25
        started = time.monotonic()
        try:
            tag = await self.tcp_exchange("multi.test", size=64)
            elapsed = time.monotonic() - started
            assert tag == b"A:" and elapsed < 2.2, (tag, elapsed)
            return {"seconds": round(elapsed, 3)}
        finally:
            self.dns.delay = 0
            self.dns.addresses = ["10.203.0.2"]
            await self.clean()

    async def short_deadline(self):
        original = json.loads(self.path.read_text())
        candidate = dict(original, dial_timeout_ms=200)
        temporary = self.root / "candidate.json"
        temporary.write_text(json.dumps(candidate))
        run(self.binary, "-c", self.path, "apply", "--file", temporary)
        self.dns.addresses = [f"10.203.0.{n}" for n in range(91, 96)] + ["10.203.0.2"]
        started = time.monotonic()
        try:
            assert await self.tcp_exchange("multi.test", size=64) == b"A:"
            elapsed = time.monotonic() - started
            assert elapsed < .45, elapsed
            return {"seconds": round(elapsed, 3), "addresses": 6, "budget_ms": 200}
        finally:
            self.dns.addresses = ["10.203.0.2"]
            temporary.write_text(json.dumps(original))
            run(self.binary, "-c", self.path, "apply", "--file", temporary)
            await self.clean()

    async def diagnostics(self):
        for host in ["unknown.test", "nx.test"]:
            self.dns.mode = "nxdomain" if host == "nx.test" else "ok"
            result = await asyncio.gather(self.tcp_exchange(host), return_exceptions=True)
            assert isinstance(result[0], Exception), result
        self.dns.mode = "ok"
        r, w = await asyncio.open_connection("127.0.0.1", 29301)
        w.write(b"GET ")
        await w.drain()
        assert await asyncio.wait_for(r.read(), 3) == b""
        w.close()
        await w.wait_closed()
        await self.clean()
        stats = self.status()
        reasons = stats["tcp_failure_reasons"]
        assert sum(reasons.values()) == stats["tcp_failed"], stats
        for key in ["handshake_timeout", "handshake_rejected", "route_missing",
                    "dns_error", "connect_timeout", "connect_error", "relay_error"]:
            assert reasons[key] > 0, (key, reasons)
        return reasons

    async def interface_recovery(self):
        for _ in range(3):
            run("ip", "link", "set", "hr-front", "down")
            try:
                failed = await asyncio.gather(self.tcp_exchange(size=32), return_exceptions=True)
                assert isinstance(failed[0], Exception), failed
            finally:
                run("ip", "link", "set", "hr-front", "up")
            await self.tcp_exchange(size=8192)
            await self.quic()
            await self.clean()
        return {"cycles": 3, "resources": await self.clean()}

    async def small_mtu(self):
        try:
            run("ip", "link", "set", "hr-front", "mtu", 1280)
            run("nsenter", "-t", self.backend.pid, "-n", "ip", "link", "set", "hr-back", "mtu", 1280)
            await self.tcp_exchange(tls=True, size=256 * 1024)
            await self.quic()
        finally:
            run("ip", "link", "set", "hr-front", "mtu", 1500)
            run("nsenter", "-t", self.backend.pid, "-n", "ip", "link", "set", "hr-back", "mtu", 1500)
        return await self.clean()


async def main(args):
    assert os.geteuid() == 0, "private namespace setup needs root"
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net"), "use unshare --net"
    assert os.readlink("/proc/self/ns/mnt") != os.readlink("/proc/1/ns/mnt"), "use unshare --mount"
    binary = str(pathlib.Path(args.binary).resolve())
    root = pathlib.Path(tempfile.mkdtemp(prefix="host-router-network-"))
    root.chmod(0o700)
    cert_files(root)
    run("ip", "link", "set", "lo", "up")
    log = (root / "backend.log").open("w")
    backend_process = subprocess.Popen(["unshare", "--net", sys.executable, __file__,
                                       binary, "--backend", str(root)], stdout=log, stderr=log)
    router = None
    dns_transport = None
    router_log = None
    dns = Dns()
    try:
        await ready(root / "namespace-ready", backend_process)
        run("ip", "link", "add", "hr-front", "type", "veth", "peer", "name", "hr-back")
        run("ip", "link", "set", "hr-back", "netns", backend_process.pid)
        run("ip", "addr", "add", "10.203.0.1/24", "dev", "hr-front")
        run("ip", "link", "set", "hr-front", "up")
        for command in [["link", "set", "lo", "up"],
                        ["addr", "add", "10.203.0.2/24", "dev", "hr-back"],
                        ["addr", "add", "10.203.0.3/24", "dev", "hr-back"],
                        ["link", "set", "hr-back", "up"]]:
            run("nsenter", "-t", backend_process.pid, "-n", "ip", *command)
        (root / "network-ready").touch()
        await ready(root / "backend-ready", backend_process)
        resolv = root / "resolv.conf"
        resolv.write_text("nameserver 127.0.0.53\noptions timeout:2 attempts:1\n")
        run("mount", "--bind", resolv, "/etc/resolv.conf")
        dns_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: dns, local_addr=("127.0.0.53", 53))
        config = {"dns_refresh_seconds": 1, "dial_timeout_ms": 2000, "sniff_timeout_ms": 1500,
                  "udp_idle_seconds": 4, "max_connections_per_ip": 128, "rules": [
                      {"listen": "127.0.0.1:29301", "domain": name, "target": target}
                      for name, target in [("a.test", "10.203.0.2:29401"),
                          ("tls.test", "10.203.0.2:29402"), ("dns.test", "fault-target.test:29401"),
                          ("multi.test", "multi-target.test:29401"), ("nx.test", "nx-target.test:29401"),
                          ("refused.test", "10.203.0.2:29409"), ("blackhole.test", "10.203.0.99:29401")]]}
        (root / "config.json").write_text(json.dumps(config))
        router_log = (root / "router.log").open("w")
        router = subprocess.Popen([binary, "-c", str(root / "config.json"), "serve"],
                                  stdout=router_log, stderr=router_log)
        await ready(root / "config.sock", router)
        suite = Suite(binary, root, backend_process, router, dns)
        fd_baseline = len(list(pathlib.Path(f"/proc/{router.pid}/fd").iterdir()))
        def resources():
            stat = pathlib.Path(f"/proc/{router.pid}/stat").read_text().rsplit(") ", 1)[1].split()
            status = pathlib.Path(f"/proc/{router.pid}/status").read_text().splitlines()
            return {"cpu_seconds": (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"),
                    "fds": len(list(pathlib.Path(f"/proc/{router.pid}/fd").iterdir())),
                    "rss_kib": int(next(line for line in status if line.startswith("VmRSS:")).split()[1])}
        cases = [("normal TCP/TLS/QUIC", suite.normal),
                 ("delay/loss/duplicate/reorder TCP/TLS/QUIC v1+v2", suite.weak_network),
                 ("ingress delay and loss", suite.ingress_loss),
                 ("2-second blackhole: same TCP and QUIC sessions recover", suite.recover_same_sessions),
                 ("target refused/timeout/reset", suite.target_faults),
                 ("TCP half-close/backpressure/early disconnect", suite.half_close_and_backpressure),
                 ("DNS outage/DDNS recovery/established flow preserved", suite.dns_outage),
                 ("slow DNS plus blackholed first address", suite.dns_fallback),
                 ("short total deadline with six target addresses", suite.short_deadline),
                 ("interface down/up; three recovery cycles", suite.interface_recovery),
                 ("1280-byte path MTU", suite.small_mtu)]
        if not args.baseline:
            cases.append(("failure reasons stay bounded and distinguish causes", suite.diagnostics))
        if args.only_dns:
            cases = [("slow DNS plus blackholed first address", suite.dns_fallback)]
        for name, method in cases:
            started = time.monotonic()
            before = resources()
            try:
                detail = await asyncio.wait_for(method(), 100)
                result = {"name": name, "result": "PASS", "detail": detail}
            except Exception as error:
                result = {"name": name, "result": "FAIL", "error": repr(error)}
            result["seconds"] = round(time.monotonic() - started, 3)
            after = resources()
            result["resources"] = after
            result["cpu_percent_one_core"] = round(
                100 * (after["cpu_seconds"] - before["cpu_seconds"]) / max(result["seconds"], .001), 3)
            RESULTS.append(result)
            print(json.dumps(result), flush=True)
        stats = suite.status()
        assert resources()["fds"] <= fd_baseline + 2, (fd_baseline, resources())
        (root / "result.json").write_text(json.dumps({"results": RESULTS, "status": stats}, indent=2))
        print("Artifacts:", root, flush=True)
        assert all(r["result"] == "PASS" for r in RESULTS), "network fault regression failed"
    finally:
        for process in [router, backend_process]:
            if process is not None:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for handle in dns.handles:
            handle.cancel()
        if dns_transport:
            dns_transport.close()
        if router_log:
            router_log.close()
        log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--backend")
    parser.add_argument("--only-dns", action="store_true")
    parser.add_argument("--baseline", action="store_true", help="omit new status-field assertions")
    arguments = parser.parse_args()
    if arguments.backend:
        asyncio.run(backend(pathlib.Path(arguments.backend)))
    else:
        asyncio.run(main(arguments))
