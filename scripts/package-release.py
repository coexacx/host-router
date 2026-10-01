#!/usr/bin/env python3
"""Package reviewed, tracked source and prebuilt binaries; keep signing keys outside the repository."""
import argparse,hashlib,json,os,pathlib,re,shutil,subprocess,tarfile
p=argparse.ArgumentParser()
p.add_argument("--key",required=True)
p.add_argument("--amd64",required=True)
p.add_argument("--arm64",required=True)
p.add_argument("--out",default="dist/v0.1.0")
args=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];os.chdir(root)
key=pathlib.Path(args.key).resolve()
assert not key.is_relative_to(root),"Signing key must be outside the source tree"
version=re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$',(root/"Cargo.toml").read_text(),re.M).group(1)
out=pathlib.Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
assets={}
for arch,source in [("amd64",args.amd64),("arm64",args.arm64)]:
    destination=out/f"host-router-linux-{arch}";shutil.copyfile(source,destination);destination.chmod(0o755)
    assets[destination.name]=hashlib.sha256(destination.read_bytes()).hexdigest()
script=(root/"hostip.sh").read_text()
script=re.sub(r"^VERSION=.*$",f"VERSION={version}",script,flags=re.M)
for arch in ["amd64","arm64"]:
    script=re.sub(r"^"+arch.upper()+r"_SHA=.*$",arch.upper()+"_SHA="+assets[f"host-router-linux-{arch}"],script,flags=re.M)
(root/"hostip.sh").write_text(script);(out/"hostip.sh").write_text(script);(out/"hostip.sh").chmod(0o755)
assets["hostip.sh"]=hashlib.sha256((out/"hostip.sh").read_bytes()).hexdigest()
files=subprocess.check_output(["git","ls-files","-z"]).decode().split("\0")
with tarfile.open(out/"host-router-source.tar.gz","w:gz") as archive:
    for name in files:
        if not name:continue
        f=root/name
        assert f.is_file() and not f.is_symlink(),f"Unsafe tracked path: {name}"
        assert f.suffix not in [".pem",".key",".pyc"],f"Private/generated file: {name}"
        info=archive.gettarinfo(str(f),arcname=f"host-router-{version}/{name}")
        info.uid=info.gid=0;info.uname=info.gname="";info.mtime=0
        with f.open("rb") as data:archive.addfile(info,data)
assets["host-router-source.tar.gz"]=hashlib.sha256((out/"host-router-source.tar.gz").read_bytes()).hexdigest()
manifest={"version":version,"assets":{name:{"sha256":digest,"url":f"https://github.com/coexacx/host-router/releases/download/v{version}/{name}"} for name,digest in assets.items()}}
(out/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
subprocess.run(["openssl","pkeyutl","-sign","-rawin","-inkey",str(key),"-in",str(out/"manifest.json"),"-out",str(out/"manifest.sig")],check=True)
for asset in assets:
    subprocess.run([str(out/"host-router-linux-amd64"),"verify-release","--manifest",str(out/"manifest.json"),"--signature",str(out/"manifest.sig"),"--asset",asset],check=True)
allfiles=sorted(assets)+["manifest.json","manifest.sig"]
(out/"SHA256SUMS").write_text("".join(hashlib.sha256((out/name).read_bytes()).hexdigest()+"  "+name+"\n" for name in allfiles))
print("Release prepared:",out)
