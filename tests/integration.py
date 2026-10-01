#!/usr/bin/env python3
"""End-to-end checks against a real Rust process, with independent TLS/QUIC implementations."""
import asyncio, hashlib, json, os, pathlib, shutil, signal, socket, ssl, subprocess, sys, tempfile, time
from aioquic.asyncio import connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import datetime

BIN=pathlib.Path(sys.argv[1]).resolve()
RESULTS=[]
def record(name, detail="ok"):
    RESULTS.append({"test":name,"result":"PASS","detail":detail})
    print("PASS",name,detail,flush=True)
def config_file(path,cfg):
    path.write_text(json.dumps(cfg))
def cli(cfg,*args,ok=True):
    p=subprocess.run([str(BIN),"-c",str(cfg),*map(str,args)],capture_output=True,text=True)
    if ok and p.returncode: raise AssertionError(p.stderr)
    if not ok and not p.returncode: raise AssertionError("unexpected success: "+p.stdout)
    return p
def cert_files(root):
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"host-router-test")])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName("a.test"),x509.DNSName("b.test"),x509.DNSName("x.wild.test")]),False)
          .sign(key,hashes.SHA256()))
    (root/"key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (root/"cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return root/"cert.pem",root/"key.pem"

async def http_server(reader,writer,tag):
    try:
        data=await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"),4)
        # Echo exact payload to verify no protocol headers or byte changes.
        writer.write(tag+b":"+data);await writer.drain()
    except (Exception,asyncio.CancelledError): pass
    finally: writer.close()
async def quic_stream(reader,writer,tag):
    try:
        data=await asyncio.wait_for(reader.read(),4)
        writer.write(tag+b":"+data);writer.write_eof();await writer.drain()
    except (Exception,asyncio.CancelledError): pass

async def http(port,host="a.test",family="127.0.0.1",secure=False,fragment=False):
    ctx=None
    if secure:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    r,w=await asyncio.wait_for(asyncio.open_connection(family,port,ssl=ctx,server_hostname=host if ctx else None),4)
    data=f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    if fragment:
        for part in [data[:7],data[7:28],data[28:]]:
            w.write(part);await w.drain();await asyncio.sleep(.01)
    else: w.write(data);await w.drain()
    result=await asyncio.wait_for(r.read(),4);w.close();await w.wait_closed()
    return result
async def quic_client(port,host="a.test",version=QuicProtocolVersion.VERSION_1,payload=b"quic-test",addr="127.0.0.1",local_port=0):
    cfg=QuicConfiguration(is_client=True,alpn_protocols=["hr-test"],server_name=host,verify_mode=ssl.CERT_NONE,
        supported_versions=[version],idle_timeout=4,quantum_readiness_test=True)
    async with connect(addr,port,configuration=cfg,local_port=local_port) as p:
        r,w=await p.create_stream();w.write(payload);w.write_eof();await w.drain()
        return await asyncio.wait_for(r.read(),4)
async def main():
    root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-integration-"))
    cert,key=cert_files(root);servers=[];procs=[]
    try:
        for port,tag in [(29601,b"A"),(29602,b"B")]:
            servers.append(await asyncio.start_server(lambda r,w,t=tag:asyncio.create_task(http_server(r,w,t)),"127.0.0.1",port))
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
        servers.append(await asyncio.start_server(lambda r,w:asyncio.create_task(http_server(r,w,b"TLS")),"127.0.0.1",29603,ssl=ctx))
        for port,tag in [(29601,b"A"),(29602,b"B")]:
            q=QuicConfiguration(is_client=False,alpn_protocols=["hr-test"]);q.load_cert_chain(cert,key)
            servers.append(await serve("127.0.0.1",port,configuration=q,
                stream_handler=lambda r,w,t=tag:asyncio.create_task(quic_stream(r,w,t))))
        cfg={"dns_refresh_seconds":1,"udp_idle_seconds":2,"rules":[
          {"listen":"127.0.0.1:29500","domain":"a.test","target":"127.0.0.1:29601"},
          {"listen":"127.0.0.1:29500","domain":"b.test","target":"127.0.0.1:29602"},
          {"listen":"127.0.0.1:29500","domain":"*.wild.test","target":"127.0.0.1:29602"},
          {"listen":"127.0.0.1:29501","domain":"a.test","target":"127.0.0.1:29603","protocol":"tcp"},
          {"listen":"[::1]:29502","domain":"a.test","target":"127.0.0.1:29601"},
        ]}
        path=root/"config.json";config_file(path,cfg)
        logfile=(root/"router.log").open("w")
        p=subprocess.Popen([str(BIN),"-c",str(path),"serve"],stdout=logfile,stderr=logfile);procs.append(p)
        for _ in range(100):
            if path.with_suffix(".sock").exists():break
            assert p.poll() is None,(root/"router.log").read_text()
            await asyncio.sleep(.02)
        assert (await http(29500)).startswith(b"A:")
        assert (await http(29500,"b.test",fragment=True)).startswith(b"B:")
        assert (await http(29500,"x.wild.test")).startswith(b"B:")
        record("HTTP exact / wildcard / fragmented headers")
        assert (await http(29501,secure=True)).startswith(b"TLS:")
        record("TLS SNI passthrough and handshake")
        assert (await http(29502,family="::1")).startswith(b"A:")
        record("IPv6 listener to IPv4 backend")
        assert await quic_client(29502,addr="::1")==b"A:quic-test"
        record("IPv6 QUIC ingress to IPv4 backend")
        for version in [QuicProtocolVersion.VERSION_1,QuicProtocolVersion.VERSION_2]:
            for host,tag in [("a.test",b"A"),("b.test",b"B"),("x.wild.test",b"B")]:
                data=os.urandom(16000)
                result=await asyncio.wait_for(quic_client(29500,host,version,data),6)
                assert result==tag+b":"+data,(host,version,result[:30])
            record("QUIC domain routing "+version.name)
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.setblocking(False)
        udp.sendto(b"ordinary-udp-must-not-forward",("127.0.0.1",29500))
        try: await asyncio.wait_for(asyncio.get_running_loop().sock_recv(udp,128),.2);raise AssertionError("raw UDP accepted")
        except asyncio.TimeoutError: pass
        udp.close();record("ordinary UDP denied")
        changed=json.loads(json.dumps(cfg));changed["rules"][0]["target"]="127.0.0.1:29602"
        candidate=root/"candidate.json";config_file(candidate,changed)
        cli(path,"apply","--file",candidate)
        assert (await http(29500)).startswith(b"B:");record("transactional live configuration update")
        before=path.read_bytes()
        changed["rules"].append(changed["rules"][0]);config_file(candidate,changed)
        cli(path,"apply","--file",candidate,ok=False)
        assert path.read_bytes()==before and (await http(29500)).startswith(b"B:")
        record("invalid update leaves disk and runtime unchanged")
        # Bind failure must also leave everything intact, including newly prepared listeners.
        changed=json.loads(before);changed["rules"].append({"listen":"127.0.0.1:29601","domain":"busy.test","target":"127.0.0.1:29602"})
        config_file(candidate,changed);cli(path,"apply","--file",candidate,ok=False)
        assert path.read_bytes()==before;record("occupied port rollback")
        batchfile=root/"batch.txt";batchfile.write_text("c.test 127.0.0.1 29601\nd.test 127.0.0.1 29602\n")
        cli(path,"add-batch","--listen","127.0.0.1:29500","--file",batchfile)
        assert (await http(29500,"c.test")).startswith(b"A:")
        cli(path,"delete","6","7");assert len(json.loads(path.read_text())["rules"])==5
        cli(path,"delete","1","999",ok=False);assert len(json.loads(path.read_text())["rules"])==5
        record("batch add / batch delete / all-or-nothing invalid IDs")
        # Startup lock prevents a second process from unlinking the active control socket.
        duplicate=cli(path,"serve",ok=False);assert "lock" in duplicate.stderr
        cli(path,"status");record("single instance and private control socket")
        p.send_signal(signal.SIGHUP);await asyncio.sleep(.1)
        assert (await http(29500)).startswith(b"B:");record("SIGHUP reload")
        await asyncio.sleep(2.5)
        stats=json.loads(cli(path,"status").stdout)
        assert stats["udp_active"]==0 and stats["queued_udp_bytes"]==0 and stats["pending_handshakes"]==0,stats
        record("UDP idle cleanup and resource release",stats)
        print(json.dumps({"results":RESULTS,"root":str(root)},indent=2),flush=True)
        (root/"result.json").write_text(json.dumps(RESULTS,indent=2))
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
        for srv in servers:srv.close()
        print("Artifacts:",root,flush=True)
if __name__=="__main__":asyncio.run(main())
