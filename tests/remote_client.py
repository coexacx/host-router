#!/usr/bin/env python3
import asyncio,json,os,pathlib,ssl,subprocess,sys,tempfile,time
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from integration import quic_client
from aioquic.quic.packet import QuicProtocolVersion
async def main():
    binary,backend=sys.argv[1:3]
    root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-remote-"))
    cfg=root/"config.json";cfg.write_text(json.dumps({"rules":[{"listen":"127.0.0.1:29440","domain":"a.test","target":backend}]}))
    log=(root/"router.log").open("w");p=subprocess.Popen([binary,"-c",str(cfg),"serve"],stdout=log,stderr=log)
    try:
        for _ in range(100):
            if cfg.with_suffix(".sock").exists():break
            await asyncio.sleep(.02)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        r,w=await asyncio.open_connection("127.0.0.1",29440,ssl=ctx,server_hostname="a.test")
        data=os.urandom(4*1024*1024)
        async def read():return await r.readexactly(len(data))
        reader=asyncio.create_task(read());start=time.monotonic()
        w.write(data);await w.drain();received=await asyncio.wait_for(reader,30)
        assert received==data;w.close();await w.wait_closed()
        print(json.dumps({"test":"cross-server TLS","bytes":len(data),"seconds":time.monotonic()-start,"result":"PASS"}),flush=True)
        for v in [QuicProtocolVersion.VERSION_1,QuicProtocolVersion.VERSION_2]:
            data=os.urandom(128*1024)
            received=await asyncio.wait_for(quic_client(29440,version=v,payload=data),30)
            assert data==received
            print(json.dumps({"test":"cross-server QUIC "+v.name,"bytes":len(data),"result":"PASS"}),flush=True)
    finally:p.terminate();p.wait(5);log.close()
asyncio.run(main())
