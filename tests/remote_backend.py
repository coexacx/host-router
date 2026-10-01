#!/usr/bin/env python3
"""Temporary TLS and QUIC echo backends, restricted to the supplied test ingress IP."""
import argparse,asyncio,pathlib,ssl,sys
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from integration import cert_files
p=argparse.ArgumentParser();p.add_argument("--allow",required=True);p.add_argument("--port",type=int,default=29443);args=p.parse_args()
async def echo(reader,writer,tls=False):
    try:
        if tls and writer.get_extra_info("peername")[0]!=args.allow:return
        while data:=await asyncio.wait_for(reader.read(65536),30):
            writer.write(data);await writer.drain()
        if not tls:writer.write_eof()
    except (Exception,asyncio.CancelledError):pass
    finally:
        if tls:writer.close()
class FilteredServer(QuicServer):
    def datagram_received(self,data,addr):
        if addr[0]==args.allow:super().datagram_received(data,addr)
async def main():
    root=pathlib.Path(__file__).parent;cert,key=cert_files(root)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
    tls=await asyncio.start_server(lambda r,w:asyncio.create_task(echo(r,w,True)),"0.0.0.0",args.port,ssl=ctx)
    cfg=QuicConfiguration(is_client=False,alpn_protocols=["hr-test"]);cfg.load_cert_chain(cert,key)
    tr,_=await asyncio.get_running_loop().create_datagram_endpoint(
        lambda:FilteredServer(configuration=cfg,stream_handler=lambda r,w:asyncio.create_task(echo(r,w))),
        local_addr=("0.0.0.0",args.port))
    print("READY",flush=True)
    try:await asyncio.sleep(3600)
    finally:tls.close();tr.close()
asyncio.run(main())
