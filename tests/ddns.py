#!/usr/bin/env python3
"""Run in a private mount namespace with a writable temporary /etc/hosts bind."""
import asyncio,json,os,pathlib,ssl,subprocess,sys,tempfile
from integration import cert_files,http_server,quic_stream,http,quic_client,record
from aioquic.asyncio import connect,serve
from aioquic.quic.configuration import QuicConfiguration
async def main():
    binary,hostsfile=sys.argv[1:3];root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-ddns-"));servers=[]
    cert,key=cert_files(root)
    for ip,tag in [("127.0.0.1",b"A"),("127.0.0.2",b"B")]:
        servers.append(await asyncio.start_server(lambda r,w,t=tag:asyncio.create_task(http_server(r,w,t)),ip,29604))
        cfg=QuicConfiguration(is_client=False,alpn_protocols=["hr-test"]);cfg.load_cert_chain(cert,key)
        servers.append(await serve(ip,29604,configuration=cfg,stream_handler=lambda r,w,t=tag:asyncio.create_task(quic_stream(r,w,t))))
    path=root/"config.json";path.write_text(json.dumps({"dns_refresh_seconds":1,"udp_idle_seconds":10,
        "rules":[{"listen":"127.0.0.1:29504","domain":"a.test","target":"ddns.test:29604"}]}))
    log=(root/"router.log").open("w");p=subprocess.Popen([binary,"-c",str(path),"serve"],stdout=log,stderr=log)
    try:
        for _ in range(100):
            if path.with_suffix(".sock").exists():break
            await asyncio.sleep(.02)
        assert (await http(29504)).startswith(b"A:")
        qcfg=QuicConfiguration(is_client=True,alpn_protocols=["hr-test"],server_name="a.test",verify_mode=ssl.CERT_NONE)
        async with connect("127.0.0.1",29504,configuration=qcfg) as q:
            async def exchange():
                r,w=await q.create_stream();w.write(b"pinned");w.write_eof()
                return await asyncio.wait_for(r.read(),3)
            assert await exchange()==b"A:pinned"
            pathlib.Path(hostsfile).write_text("127.0.0.1 localhost\n127.0.0.2 ddns.test\n")
            await asyncio.sleep(1.2)
            assert (await http(29504)).startswith(b"B:")
            assert await quic_client(29504)==b"B:quic-test"
            assert await exchange()==b"A:pinned"
        record("DDNS new TCP/QUIC flows switch address; active QUIC flow remains pinned")
        print("Artifacts:",root,flush=True)
    finally:
        p.terminate();p.wait(5);log.close()
        for s in servers:s.close()
asyncio.run(main())
