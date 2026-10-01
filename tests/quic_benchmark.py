#!/usr/bin/env python3
import asyncio,json,os,pathlib,subprocess,sys,tempfile,threading,time
from integration import cert_files,cli
binary,driver=sys.argv[1:3]
direction=sys.argv[3] if len(sys.argv)>3 else "download"
root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-quic-benchmark-"))
cert,key=cert_files(root)
subprocess.run(["openssl","x509","-in",str(cert),"-outform","DER","-out",str(root/"cert.der")],check=True)
subprocess.run(["openssl","pkcs8","-topk8","-nocrypt","-in",str(key),"-outform","DER","-out",str(root/"key.der")],check=True)
(root/"payload").write_bytes(os.urandom(1024*1024))
cfg=root/"config.json";cfg.write_text(json.dumps({"max_connections_per_ip":128,"udp_idle_seconds":2,
    "rules":[{"listen":"127.0.0.1:29560","domain":"a.test","target":"127.0.0.1:29660","protocol":"udp"}]}))
server=subprocess.Popen([driver,"server","127.0.0.1:29660",str(root/"cert.der"),str(root/"key.der"),str(root/"payload")],stdout=subprocess.PIPE,text=True)
assert server.stdout.readline().strip()=="READY"
log=(root/"router.log").open("w");p=subprocess.Popen([binary,"-c",str(cfg),"serve"],stdout=log,stderr=log)
def cpu():
    fields=pathlib.Path(f"/proc/{p.pid}/stat").read_text().rsplit(")",1)[1].split()
    return (int(fields[11])+int(fields[12]))/os.sysconf("SC_CLK_TCK")
try:
 for _ in range(100):
    if cfg.with_suffix(".sock").exists():break
    time.sleep(.02)
 result=[]
 for name,port in [("direct",29660),("routed",29560)]:
    start=time.monotonic();before=cpu()
    run=subprocess.run([driver,"client",f"127.0.0.1:{port}",str(root/"cert.der"),"8","10",direction,str(root/"payload")],capture_output=True,text=True,timeout=40)
    assert run.returncode==0,run.stderr
    data=json.loads(run.stdout);data.update(mode=name,direction=direction,router_cpu_percent=100*(cpu()-before)/(time.monotonic()-start))
    assert data["errors"]==0,run.stderr
    if name=="routed":
        data["router_stats"]=json.loads(cli(cfg,"status").stdout)
        status=pathlib.Path(f"/proc/{p.pid}/status").read_text().splitlines()
        data["router_rss_kib"]=int(next(x for x in status if x.startswith("VmRSS:")).split()[1])
        data["router_peak_rss_kib"]=int(next(x for x in status if x.startswith("VmHWM:")).split()[1])
    result.append(data);print(json.dumps(data),flush=True)
 (root/"result.json").write_text(json.dumps(result,indent=2));print("Artifacts:",root,flush=True)
finally:
 p.terminate();p.wait(5);server.terminate();server.wait(5);log.close()
