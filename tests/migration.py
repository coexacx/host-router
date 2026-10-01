#!/usr/bin/env python3
"""Destructive only to a NEW, otherwise absent host-router installation. Requires root."""
import asyncio,hashlib,json,os,pathlib,re,shutil,socket,ssl,subprocess,sys,tempfile
from integration import quic_client
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=pathlib.Path("/usr/local/bin/host-router");CFG=pathlib.Path("/etc/host-router")
UNIT=pathlib.Path("/etc/systemd/system/host-router.service")
def command(*args,ok=True,**kwargs):
    p=subprocess.run(args,capture_output=True,text=True,**kwargs)
    if ok and p.returncode:raise RuntimeError(" ".join(map(str,args))+"\n"+p.stdout+"\n"+p.stderr)
    return p
async def tls():
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    r,w=await asyncio.wait_for(asyncio.open_connection("127.0.0.1",29530,ssl=ctx,server_hostname="a.test"),8)
    w.write(b"migration-test");await w.drain()
    assert await asyncio.wait_for(r.readexactly(14),5)==b"migration-test";w.close();await w.wait_closed()
async def main():
    assert os.geteuid()==0
    go,oldscript,rust,backend=sys.argv[1:5]
    assert not any(p.exists() for p in [BIN,CFG,UNIT]),"Refusing to modify an existing installation"
    work=pathlib.Path(tempfile.mkdtemp(prefix="host-router-migration-"));install=work/"install";install.mkdir()
    (install/"bin").mkdir()
    shutil.copy2(rust,install/"bin/host-router-linux-amd64")
    candidate=work/"new-hostip.sh";s=(ROOT/"hostip.sh").read_text()
    s=re.sub(r"^AMD64_SHA=.*$", "AMD64_SHA="+hashlib.sha256(pathlib.Path(rust).read_bytes()).hexdigest(),s,flags=re.M)
    candidate.write_text(s)
    legacy=install/"hostip.sh"
    s=pathlib.Path(oldscript).read_text().replace("SELF_PATH=/root/hostip.sh","SELF_PATH="+str(legacy))
    s=s.replace("UPDATE_URL=https://pay.vistar.lat/hostip.sh","UPDATE_URL=file://"+str(candidate))
    s=s.replace('cfg_bak="/root/${APP}-rules-${stamp}.json"','cfg_bak="'+str(work)+'/rules-${stamp}.json"')
    legacy.write_text(s)
    rules=[{"listen":"127.0.0.1:29530","domain":"a.test","target":backend},
           {"listen":"127.0.0.1:29530","domain":"b.test","target":backend}]
    config={"default_port":"443","access_log":False,"dial_timeout_ms":5000,"rules":rules}
    CFG.mkdir(mode=0o755);path=CFG/"config.json";path.write_text(json.dumps(config));path.chmod(0o644)
    original_bytes=path.read_bytes()
    shutil.copy2(go,BIN);BIN.chmod(0o755)
    unit="[Unit]\nDescription=Isolated legacy migration test\n[Service]\nType=simple\nExecStart=/usr/local/bin/host-router -c /etc/host-router/config.json\nRestart=no\n[Install]\nWantedBy=multi-user.target\n"
    UNIT.write_text(unit)
    blocked=None
    try:
        command("systemctl","daemon-reload");command("systemctl","start","host-router");await asyncio.sleep(.3)
        await tls();print("PASS original Go service forwards TLS",flush=True)
        # Block only UDP; the old TCP kernel should continue operating after failed migration.
        blocked=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);blocked.bind(("127.0.0.1",29530))
        attempt=install/"candidate.sh";attempt.write_text(candidate.read_text())
        failed=command("bash",str(attempt),"install",ok=False)
        (work/"rollback.log").write_text(failed.stdout+"\n"+failed.stderr)
        assert failed.returncode!=0
        assert hashlib.sha256(BIN.read_bytes()).digest()==hashlib.sha256(pathlib.Path(go).read_bytes()).digest()
        assert path.read_bytes()==original_bytes
        command("systemctl","is-active","--quiet","host-router");await asyncio.sleep(.3)
        await tls();print("PASS occupied UDP port rolls back binary/config/unit and restores Go service",flush=True)
        blocked.close();blocked=None
        env=dict(os.environ,HOSTIP_UPDATE_SHA256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
            PATH=os.environ.get("GO_TOOLCHAIN_BIN","/usr/local/go/bin")+":"+os.environ["PATH"])
        result=command("bash",str(legacy),"update",env=env,ok=False)
        (work/"upgrade.log").write_text(result.stdout+"\n"+result.stderr)
        assert result.returncode==0,(result.stdout,result.stderr)
        await asyncio.sleep(1)
        assert command(str(BIN),"--version").stdout.strip()=="host-router 0.1.0"
        command(str(BIN),"-check","-c",str(path))
        migrated=json.loads(path.read_text())
        assert len(migrated["rules"])==len(rules)
        for old,new in zip(rules,migrated["rules"]):
            assert all(new[k]==v for k,v in old.items())
            assert new["protocol"]=="both"
        await tls()
        assert await asyncio.wait_for(quic_client(29530,payload=b"legacy-quic"),10)==b"legacy-quic"
        assert command("systemctl","show","host-router","--property=User","--value").stdout.strip()=="hostrouter"
        print("PASS original updater entrypoint -> Rust; original rules retained and TCP+UDP enabled",flush=True)
        print("PASS legacy root-owned config restoration and dedicated service user",flush=True)
        print("Artifacts:",work,flush=True)
    finally:
        if blocked:blocked.close()
        command("systemctl","disable","--now","host-router",ok=False)
        BIN.unlink(missing_ok=True);UNIT.unlink(missing_ok=True)
        if CFG.exists():shutil.rmtree(CFG)
        command("systemctl","daemon-reload",ok=False)
        command("systemctl","reset-failed","host-router",ok=False)
asyncio.run(main())
