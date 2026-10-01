#!/usr/bin/env python3
import asyncio,json,os,pathlib,random,signal,socket,ssl,subprocess,sys,tempfile,time
from integration import cert_files,quic_stream,cli
from aioquic.asyncio import connect,serve
from aioquic.quic.configuration import QuicConfiguration
async def main():
    binary=sys.argv[1];seconds=int(sys.argv[2]) if len(sys.argv)>2 else 600
    root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-soak-"));servers=[]
    cert,key=cert_files(root);failures=[];stats=[];counts={"tcp":0,"quic":0,"reconnects":0}
    async def echo(r,w):
        try:
            while b:=await r.read(65536):w.write(b);await w.drain()
            w.write_eof()
        except (Exception,asyncio.CancelledError):pass
        finally:w.close()
    servers.append(await asyncio.start_server(echo,"127.0.0.1",29610))
    cfg=QuicConfiguration(is_client=False,alpn_protocols=["hr-test"]);cfg.load_cert_chain(cert,key)
    servers.append(await serve("127.0.0.1",29610,configuration=cfg,stream_handler=lambda r,w:asyncio.create_task(quic_stream(r,w,b"Q"))))
    config={"max_connections_per_ip":512,"max_pending_handshakes":128,"udp_idle_seconds":3,
        "rules":[{"listen":"127.0.0.1:29510","domain":"a.test","target":"127.0.0.1:29610"}]}
    path=root/"config.json";path.write_text(json.dumps(config));log=(root/"router.log").open("w")
    p=subprocess.Popen([binary,"-c",str(path),"serve"],stdout=log,stderr=log)
    start=time.monotonic();end=start+seconds
    async def tcp_worker(i):
        while time.monotonic()<end:
            try:
                r,w=await asyncio.open_connection("127.0.0.1",29510)
                h=b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";w.write(h);await w.drain();assert await r.readexactly(len(h))==h
                until=min(end,time.monotonic()+(seconds if i<32 else random.uniform(2,5)))
                while time.monotonic()<until:
                    data=os.urandom(4096);w.write(data);await w.drain()
                    assert await asyncio.wait_for(r.readexactly(len(data)),5)==data;counts["tcp"]+=1
                    await asyncio.sleep(.1)
                w.write_eof();await asyncio.wait_for(r.read(),3);w.close();await w.wait_closed();counts["reconnects"]+=1
            except Exception as e:failures.append({"type":"tcp","error":repr(e)});await asyncio.sleep(.2)
    async def quic_worker(i):
        while time.monotonic()<end:
            try:
                cfg=QuicConfiguration(is_client=True,alpn_protocols=["hr-test"],server_name="a.test",verify_mode=ssl.CERT_NONE,idle_timeout=10)
                async with connect("127.0.0.1",29510,configuration=cfg) as q:
                    until=min(end,time.monotonic()+(seconds if i<16 else random.uniform(3,6)))
                    while time.monotonic()<until:
                        r,w=await q.create_stream();data=os.urandom(2048);w.write(data);w.write_eof()
                        assert await asyncio.wait_for(r.read(),5)==b"Q:"+data;counts["quic"]+=1
                        await asyncio.sleep(.2)
                    counts["reconnects"]+=1
            except Exception as e:failures.append({"type":"quic","error":repr(e)});await asyncio.sleep(.2)
    async def observe():
        while time.monotonic()<end:
            await asyncio.sleep(5)
            s=json.loads(cli(path,"status").stdout)
            proc=pathlib.Path(f"/proc/{p.pid}/status").read_text()
            s["rss_kib"]=int(next(x for x in proc.splitlines() if x.startswith("VmRSS:")).split()[1])
            s["fds"]=len(os.listdir(f"/proc/{p.pid}/fd"));s["elapsed"]=round(time.monotonic()-start,1);stats.append(s)
            if len(stats)%6==0:
                p.send_signal(signal.SIGHUP)
                print(json.dumps({"elapsed":s["elapsed"],"rss_kib":s["rss_kib"],"counts":counts,"failures":len(failures)}),flush=True)
    try:
        for _ in range(100):
            if path.with_suffix(".sock").exists():break
            await asyncio.sleep(.02)
        tasks=[]
        for i in range(64):
            tasks.append(asyncio.create_task(tcp_worker(i)));await asyncio.sleep(.005)
        for i in range(32):
            tasks.append(asyncio.create_task(quic_worker(i)));await asyncio.sleep(.025)
        await asyncio.gather(*tasks,observe())
        await asyncio.sleep(4)
        final=json.loads(cli(path,"status").stdout)
        assert not failures,failures[:10]
        assert final["tcp_active"]==final["udp_active"]==final["queued_udp_bytes"]==final["tracked_ips"]==0,final
        report={"seconds":seconds,"counts":counts,"failures":failures,"samples":stats,"final":final}
        (root/"result.json").write_text(json.dumps(report,indent=2))
        print(json.dumps({"result":"PASS","root":str(root),"seconds":seconds,"counts":counts,"final":final}),flush=True)
    finally:
        p.terminate();p.wait(5);log.close()
        for s in servers:s.close()
if __name__=="__main__":asyncio.run(main())
