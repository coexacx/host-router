#!/usr/bin/env python3
"""Interleaved previous versus candidate release, identical rules and configured ceilings."""
import json,os,pathlib,resource,statistics,subprocess,sys,tempfile,threading,time
# SSH shells often inherit a 1024-descriptor soft limit, causing the automatic
# capacity guard to reject a 128-client churn test. Set the same process-local
# budget for both versions; never change host-wide limits or service units.
soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
benchmark_fd_limit=max(soft,min(hard,65536))
assert benchmark_fd_limit>=8192,"benchmark requires at least 8192 descriptors"
resource.setrlimit(resource.RLIMIT_NOFILE,(benchmark_fd_limit,hard))
root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-capacity-benchmark-"))
rust,old,driver=map(str,map(pathlib.Path,sys.argv[1:4]))
cfg={"default_port":"443","access_log":False,"dial_timeout_ms":5000,
     "rules":[{"listen":"127.0.0.1:29700","domain":"bench.test","target":"127.0.0.1:29701"}]}

rc=dict(cfg,max_tcp_connections=4096,max_connections_per_ip=4096,max_pending_handshakes=1024)
(root/"rust.json").write_text(json.dumps(rc))
(root/"old.json").write_text(json.dumps(rc))
payload=root/"payload.bin"
# Real, non-sparse data avoids measuring Linux shared zero-page behavior.
with payload.open("wb") as f:
 for _ in range(64): f.write(os.urandom(1024*1024))
env=dict(os.environ,GOMAXPROCS="2")
backend=subprocess.Popen([driver,"backend","127.0.0.1:29701",str(payload)],stdout=subprocess.PIPE,text=True,env=env)
assert backend.stdout.readline().strip()=="ready"
result=[]
def metric(pid):
    try:
        stat=pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
        d={}
        for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(("VmRSS:","VmHWM:","Threads:")):k,v=line.split(":",1);d[k]=int(v.split()[0])
        d["cpu_seconds"]=(int(stat[11])+int(stat[12]))/os.sysconf("SC_CLK_TCK")
        d["fds"]=len(os.listdir(f"/proc/{pid}/fd"))
        return d
    except FileNotFoundError:return {}
try:
 for trial in range(3):
  for mode,concurrency,size in [("bulk",16,32*1024*1024),("churn",128,1024)]:
   order=["old","rust"] if trial%2==0 else ["rust","old"]
   for kind in order:
    cmd=[old,"-c",str(root/"old.json")] if kind=="old" else [rust,"-c",str(root/"rust.json"),"serve"]
    log=(root/f"{kind}-{mode}-{trial}.log").open("w")
    p=subprocess.Popen(cmd,stdout=log,stderr=log,env=env)
    samples=[];stop=threading.Event()
    def observe():
     while not stop.wait(.05):samples.append(metric(p.pid))
    try:
     time.sleep(.25);assert p.poll() is None,"proxy failed to start"
     # Warm up each new process using the same traffic pattern.
     subprocess.run([driver,"load","127.0.0.1:29700",str(concurrency),"1",str(size)],env=env,check=True,capture_output=True)
     before=metric(p.pid);observer=threading.Thread(target=observe);observer.start()
     started=time.monotonic()
     traffic=json.loads(subprocess.check_output([driver,"load","127.0.0.1:29700",str(concurrency),"5",str(size)],env=env))
     elapsed=time.monotonic()-started;after=metric(p.pid)
     stop.set();observer.join();time.sleep(.2)
     item=dict(kernel=kind,mode=mode,trial=trial+1,concurrency=concurrency,body_bytes=size,
         cpu_percent=round(100*(after["cpu_seconds"]-before["cpu_seconds"])/elapsed,2),
         peak_rss_kib=max([x.get("VmRSS",0) for x in samples]+[after.get("VmRSS",0)]),
         post_rss_kib=metric(p.pid).get("VmRSS",0),
         peak_fds=max([x.get("fds",0) for x in samples]+[0]),**traffic)
     assert item["errors"]==0,item
     result.append(item);print(json.dumps(item),flush=True)
    finally:
     stop.set();p.terminate()
     try:p.wait(5)
     except subprocess.TimeoutExpired:p.kill();p.wait()
     log.close()
 summaries=[]
 for mode in ["bulk","churn"]:
  for kind in ["old","rust"]:
   rows=[x for x in result if x["kernel"]==kind and x["mode"]==mode]
   summaries.append(dict(kernel=kind,mode=mode,**{k:statistics.median(x[k] for x in rows) for k in ["gbps","requests_per_second","cpu_percent","peak_rss_kib","p95_ms"]}))
 report={"versions":{"old":subprocess.check_output([old,"--version"],text=True).strip(),"new":subprocess.check_output([rust,"--version"],text=True).strip()},"raw":result,"medians":summaries,"environment":{"cpus":os.cpu_count(),"GOMAXPROCS":2,"rust_workers":2,"fd_soft_limit":benchmark_fd_limit},"root":str(root)}
 (root/"results.json").write_text(json.dumps(report,indent=2))
 print(json.dumps(report,indent=2),flush=True)
finally:
 backend.terminate();backend.wait(5)
 payload.unlink(missing_ok=True)
 print("Artifacts:",root,flush=True)
