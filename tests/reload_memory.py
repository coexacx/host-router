#!/usr/bin/env python3
import asyncio,json,os,pathlib,subprocess,sys,tempfile
from integration import cli
async def main():
    binary=sys.argv[1];root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-reload-memory-"))
    async def echo(r,w):
        try:
            while b:=await r.read(65536):w.write(b);await w.drain()
        except Exception:pass
        finally:w.close()
    server=await asyncio.start_server(echo,"127.0.0.1",29641)
    path=root/"config.json";candidate=root/"candidate.json"
    cfg={"max_connections_per_ip":128,"rules":[{"listen":"127.0.0.1:29541","domain":"anchor.test","target":"127.0.0.1:29641"}]}
    path.write_text(json.dumps(cfg));log=(root/"router.log").open("w")
    p=subprocess.Popen([binary,"-c",str(path),"serve"],stdout=log,stderr=log)
    connections=[];samples=[]
    def rss():
        s=pathlib.Path(f"/proc/{p.pid}/status").read_text()
        return int(next(x for x in s.splitlines() if x.startswith("VmRSS:")).split()[1])
    try:
        for _ in range(100):
            if path.with_suffix(".sock").exists():break
            await asyncio.sleep(.02)
        for generation in range(24):
            cfg["rules"]=cfg["rules"][:1]+[{"listen":"127.0.0.1:29541","domain":f"d{i}.g{generation}.test",
                "target":f"unused-{i}.g{generation}.example:443"} for i in range(1800)]
            candidate.write_text(json.dumps(cfg));cli(path,"apply","--file",candidate)
            r,w=await asyncio.open_connection("127.0.0.1",29541)
            payload=b"GET / HTTP/1.1\r\nHost: anchor.test\r\n\r\n";w.write(payload);await w.drain()
            assert await r.readexactly(len(payload))==payload
            connections.append((r,w));samples.append(rss())
        # Active connections from every old generation still work, without retaining 24 full tables.
        for r,w in connections:
            w.write(b"still-live");await w.drain();assert await r.readexactly(10)==b"still-live";w.write_eof()
            await asyncio.wait_for(r.read(),2);w.close()
        growth=max(samples[5:])-min(samples[5:])
        assert growth<12*1024,{"rss_kib":samples,"growth":growth}
        print(json.dumps({"result":"PASS","test":"24 routing generations with 1801 rules and persistent connections",
             "rss_kib":samples,"growth_kib_after_warmup":growth,"root":str(root)}),flush=True)
    finally:
        for _,w in connections:w.close()
        p.terminate();p.wait(5);log.close();server.close()
asyncio.run(main())
