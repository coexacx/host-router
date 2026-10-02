#!/usr/bin/env python3
"""Isolated cgroup pressure: never changes host limits or another service. Requires root/systemd."""
import asyncio,json,os,pathlib,signal,ssl,subprocess,sys,tempfile,time
from integration import cert_files,quic_stream
from aioquic.asyncio import connect,serve
from aioquic.quic.configuration import QuicConfiguration
binary=str(pathlib.Path(sys.argv[1]).resolve())
unit="host-router-capacity-test-"+str(os.getpid())
root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-capacity-"))
cfg=root/"config.json"
def command(*args):
    return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT)
def status():
    return json.loads(command(binary,"-c",str(cfg),"status"))
def limit(*args):
    command("systemctl","set-property","--runtime",unit,*args)
async def wait_for(predicate,seconds=25):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        s=status()
        if predicate(s):return s
        await asyncio.sleep(.3)
    raise AssertionError(status())
async def main():
    assert os.geteuid()==0,"requires root"
    servers=[];clients=[];hog=None;report={}
    cert,key=cert_files(root)
    async def echo(r,w):
        try:
            while data:=await r.read(65536):w.write(data);await w.drain()
        except Exception:pass
        finally:w.close()
    servers.append(await asyncio.start_server(echo,"127.0.0.1",29670))
    qc=QuicConfiguration(is_client=False,alpn_protocols=["hr-test"]);qc.load_cert_chain(cert,key)
    servers.append(await serve("127.0.0.1",29670,configuration=qc,
        stream_handler=lambda r,w:asyncio.create_task(quic_stream(r,w,b"Q"))))
    cfg.write_text(json.dumps({"udp_idle_seconds":90,
        "rules":[{"listen":"127.0.0.1:29570","domain":"a.test","target":"127.0.0.1:29670"}]}))
    try:
        command("systemd-run","--quiet","--unit",unit,"--property=MemoryHigh=256M",
            "--property=MemoryMax=320M","--property=CPUQuota=50%","--property=LimitNOFILE=2048",
            binary,"-c",str(cfg),"serve")
        for _ in range(100):
            if cfg.with_suffix(".sock").exists():break
            await asyncio.sleep(.05)
        before=status();report["initial"]=before
        r=before["capacity"]["resources"]
        assert r["memory_total_bytes"]<=256*1024**2 and r["cpu_cores"]<=.51 and r["fd_soft_limit"]==2048,r
        for _ in range(3):
            rd,wr=await asyncio.open_connection("127.0.0.1",29570)
            header=b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"
            wr.write(header);await wr.drain();assert await rd.readexactly(len(header))==header
            clients.append((rd,wr))
        client=QuicConfiguration(is_client=True,alpn_protocols=["hr-test"],server_name="a.test",
            verify_mode=ssl.CERT_NONE,idle_timeout=120)
        async with connect("127.0.0.1",29570,configuration=client) as quic:
            async def alive():
                for rd,wr in clients:
                    data=os.urandom(1024);wr.write(data);await wr.drain()
                    assert await asyncio.wait_for(rd.readexactly(len(data)),3)==data
                rd,wr=await quic.create_stream();wr.write(b"still-alive");wr.write_eof()
                assert await asyncio.wait_for(rd.read(),3)==b"Q:still-alive"
            await alive()
            # A low soft threshold creates pressure without imposing an OOM-sized hard limit.
            limit("MemoryHigh=16M")
            low=await wait_for(lambda s:s["capacity"]["pressure"]=="memory_critical")
            report["memory_pressure"]=low
            assert low["capacity"]["effective"]["tcp"]==low["capacity"]["effective"]["udp"]==0
            await alive()
            rd,wr=await asyncio.open_connection("127.0.0.1",29570)
            try:
                wr.write(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n");await wr.drain()
                assert await asyncio.wait_for(rd.read(1),2)==b""
            except (ConnectionResetError,BrokenPipeError):pass
            finally:
                wr.close()
                try:await wr.wait_closed()
                except Exception:pass
            assert status()["capacity"]["admission_rejected"]>0
            print("PASS real cgroup memory pressure blocks new flows, existing TCP/QUIC survive",flush=True)
            limit("MemoryHigh=256M")
            recovered=await wait_for(lambda s:s["capacity"]["capacity_percent"]>0,20)
            report["memory_recovery"]=recovered;await alive()
            cpu_before=await wait_for(lambda s:s["capacity"]["capacity_percent"]>=30,30)
            # Let a small, bounded sibling workload consume this test cgroup's 0.5 CPU.
            cg=command("systemctl","show",unit,"--property=ControlGroup","--value").strip()
            cgfile="/sys/fs/cgroup"+cg+"/cgroup.procs"
            hog=subprocess.Popen([sys.executable,"-c",
                "import os,pathlib,sys;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));exec('while True: pass')",cgfile],
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            busy=await wait_for(lambda s:s["capacity"]["pressure"]=="cpu",25)
            report["cpu_pressure"]=busy
            assert busy["capacity"]["capacity_percent"]<cpu_before["capacity"]["capacity_percent"]
            assert busy["capacity"]["resources"]["cgroup_cpu_percent"]>=90
            await alive();hog.terminate();hog.wait(5);hog=None
            cpu_recovery=await wait_for(lambda s:s["capacity"]["capacity_percent"]>busy["capacity"]["capacity_percent"],25)
            report["cpu_recovery"]=cpu_recovery;await alive()
            print("PASS sustained cgroup CPU pressure and gradual recovery, existing sessions survive",flush=True)
        for rd,wr in clients:
            wr.close();await wr.wait_closed()
        clients=[]
        report["result"]="PASS"
        (root/"result.json").write_text(json.dumps(report,indent=2))
        print(json.dumps({"result":"PASS","artifacts":str(root),
            "initial_tcp":before["capacity"]["effective"]["tcp"],"initial_udp":before["capacity"]["effective"]["udp"],
            "memory_factor":low["capacity"]["capacity_percent"],
            "cpu_factor":busy["capacity"]["capacity_percent"],
            "recovery_factor":cpu_recovery["capacity"]["capacity_percent"]}),flush=True)
    finally:
        if hog and hog.poll() is None:hog.terminate();hog.wait(5)
        for rd,wr in clients:wr.close()
        subprocess.run(["systemctl","stop",unit],capture_output=True)
        subprocess.run(["systemctl","reset-failed",unit],capture_output=True)
        for server in servers:server.close()
        print("Artifacts:",root,flush=True)
if __name__=="__main__":asyncio.run(main())
