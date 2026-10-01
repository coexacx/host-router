#!/usr/bin/env python3
import asyncio,json,os,pathlib,socket,ssl,subprocess,sys,tempfile,time
from integration import cert_files,quic_stream,http_server,http,cli
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted,StreamDataReceived,ConnectionTerminated
from aioquic.quic.packet import pull_quic_header
from aioquic.buffer import Buffer

class Mux(asyncio.DatagramProtocol):
    def __init__(self,addr):
        self.addr=addr;self.conn=[];self.transport=None;self.done=asyncio.get_running_loop().create_future()
        for host,tag in [("a.test",b"A"),("b.test",b"B")]:
            cfg=QuicConfiguration(is_client=True,alpn_protocols=["hr-test"],server_name=host,verify_mode=ssl.CERT_NONE,
                 quantum_readiness_test=True,idle_timeout=6)
            q=QuicConnection(configuration=cfg)
            self.conn.append({"q":q,"tag":tag,"result":bytearray(),"sent":False,"done":False})
    def connection_made(self,tr):
        self.transport=tr
        for c in self.conn:
            c["q"].connect(self.addr,now=time.monotonic())
            # Reverse the first Initial packets to exercise CRYPTO offset reassembly.
            self.flush(c,reverse=True)
    def flush(self,c,reverse=False):
        packets=c["q"].datagrams_to_send(now=time.monotonic())
        if reverse:packets.reverse()
        for data,addr in packets:self.transport.sendto(data,addr)
    def datagram_received(self,data,addr):
        try:header=pull_quic_header(Buffer(data=data),host_cid_length=8)
        except ValueError:return
        for c in self.conn:
            q=c["q"]
            if header.destination_cid not in [x.cid for x in q._host_cids]:continue
            q.receive_datagram(data,addr,now=time.monotonic())
            while (event:=q.next_event()) is not None:
                if isinstance(event,HandshakeCompleted) and not c["sent"]:
                    c["sent"]=True;q.send_stream_data(q.get_next_available_stream_id(),b"same-socket",end_stream=True)
                elif isinstance(event,StreamDataReceived):
                    c["result"].extend(event.data)
                    if event.end_stream:
                        assert c["result"]==c["tag"]+b":same-socket",c["result"]
                        c["done"]=True
                elif isinstance(event,ConnectionTerminated) and not c["done"]:
                    if not self.done.done():self.done.set_exception(RuntimeError(str(event)))
            self.flush(c)
        if all(c["done"] for c in self.conn) and not self.done.done():self.done.set_result(True)
    async def timers(self):
        while not self.done.done():
            now=time.monotonic()
            for c in self.conn:
                t=c["q"].get_timer()
                if t is not None and t<=now:c["q"].handle_timer(now=now);self.flush(c)
            await asyncio.sleep(.005)

async def main():
    binary=sys.argv[1];root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-advanced-"));cert,key=cert_files(root)
    servers=[]
    for port,tag in [(29621,b"A"),(29622,b"B")]:
        cfg=QuicConfiguration(is_client=False,alpn_protocols=["hr-test"]);cfg.load_cert_chain(cert,key)
        servers.append(await serve("127.0.0.1",port,configuration=cfg,stream_handler=lambda r,w,t=tag:asyncio.create_task(quic_stream(r,w,t))))
    servers.append(await asyncio.start_server(lambda r,w:asyncio.create_task(http_server(r,w,b"A")),"127.0.0.1",29621))
    cfg={"udp_idle_seconds":1,"sniff_timeout_ms":1000,"max_connections_per_ip":64,
        "rules":[{"listen":"127.0.0.1:29520","domain":h,"target":"127.0.0.1:"+str(port)} for h,port in [("a.test",29621),("b.test",29622)]]}
    path=root/"config.json";path.write_text(json.dumps(cfg));log=(root/"router.log").open("w")
    p=subprocess.Popen([binary,"-c",str(path),"serve"],stdout=log,stderr=log)
    try:
        for _ in range(100):
            if path.with_suffix(".sock").exists():break
            await asyncio.sleep(.02)
        tr,mux=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Mux(("127.0.0.1",29520)),local_addr=("127.0.0.1",0))
        timers=asyncio.create_task(mux.timers())
        try:await asyncio.wait_for(mux.done,8)
        finally:timers.cancel();tr.close()
        print("PASS two QUIC domains on the same UDP source port; fragmented/out-of-order CRYPTO",flush=True)
        # A stale configuration transaction must never overwrite a newer one.
        old=json.loads(path.read_text())
        candidate=root/"change.json";updated=json.loads(json.dumps(old));updated["dns_refresh_seconds"]=2;candidate.write_text(json.dumps(updated))
        cli(path,"apply","--file",candidate)
        reader,writer=await asyncio.open_unix_connection(str(path.with_suffix(".sock")))
        request=json.dumps({"action":"apply","config":old,"base":old}).encode()
        writer.write(len(request).to_bytes(4,"big")+request);await writer.drain()
        n=int.from_bytes(await reader.readexactly(4),"big");response=json.loads(await reader.readexactly(n));writer.close()
        assert not response["ok"] and "concurrently" in response["message"],response
        assert json.loads(path.read_text())["dns_refresh_seconds"]==2
        print("PASS stale configuration update rejected",flush=True)
        # Random/malformed datagrams must not panic or leave pending sessions behind.
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.setblocking(False)
        for i in range(20000):
            payload=(b"\xc0\x00\x00\x00\x01\x08"+os.urandom(8)+b"\x00\x00\x44\x9e"+os.urandom(1182)) if i%3==0 else os.urandom(i%1400+1)
            try:udp.sendto(payload,("127.0.0.1",29520))
            except BlockingIOError:pass
            if i%64==0:await asyncio.sleep(.001)
        udp.close();await asyncio.sleep(2)
        assert (await http(29520)).startswith(b"A:")
        stats=json.loads(cli(path,"status").stdout)
        assert stats["pending_handshakes"]==0 and stats["udp_active"]==0 and stats["queued_udp_bytes"]==0,stats
        print("PASS 20000 malformed/random UDP packets; service remains healthy",flush=True)
        # Spoofed or replayed PROXY headers never select a route.
        r,w=await asyncio.open_connection("127.0.0.1",29520);w.write(b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n");await w.drain()
        try:result=await asyncio.wait_for(r.read(),2);assert result==b""
        except ConnectionResetError:pass
        w.close()
        print("PASS unconfigured TCP/PROXY input rejected",flush=True)
        # IPv4-mapped IPv6 cannot bypass loop detection and recursively dial ingress.
        before=json.loads(cli(path,"status").stdout)["tcp_accepted"]
        loop_cfg=json.loads(path.read_text())
        loop_cfg["rules"][0]["target"]="[::ffff:127.0.0.1]:29520"
        candidate.write_text(json.dumps(loop_cfg));cli(path,"apply","--file",candidate)
        r,w=await asyncio.open_connection("127.0.0.1",29520)
        w.write(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n");await w.drain()
        try:assert await asyncio.wait_for(r.read(),2)==b""
        except ConnectionResetError:pass
        w.close();await asyncio.sleep(.1)
        after=json.loads(cli(path,"status").stdout)["tcp_accepted"]
        assert after==before+1,(before,after)
        print("PASS IPv4-mapped self-forwarding blocked before recursive connections",flush=True)
        print("Artifacts:",root,flush=True)
    finally:
        p.terminate();p.wait(5);log.close()
        for s in servers:s.close()
asyncio.run(main())
