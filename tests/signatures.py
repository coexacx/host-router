#!/usr/bin/env python3
import hashlib,json,pathlib,subprocess,sys,tempfile
binary,key=sys.argv[1:3]
root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-signatures-"))
manifest=root/"manifest.json";signature=root/"manifest.sig"
def sign(d):
    manifest.write_text(json.dumps(d))
    subprocess.run(["openssl","pkeyutl","-sign","-rawin","-inkey",key,"-in",str(manifest),"-out",str(signature)],check=True)
def check(success=True):
    p=subprocess.run([binary,"verify-release","--manifest",str(manifest),"--signature",str(signature),"--asset","hostip.sh"],capture_output=True,text=True)
    assert (p.returncode==0)==success,(p.stdout,p.stderr)
    return p.stdout
d={"version":"0.1.0","assets":{"hostip.sh":{"sha256":"a"*64,"url":"https://github.com/coexacx/host-router/releases/download/v0.1.0/hostip.sh"}}}
sign(d);assert check().startswith("current")
manifest.write_bytes(manifest.read_bytes()+b" ");check(False)
sign(d);signature.write_bytes(bytes(64));check(False)
d["assets"]["hostip.sh"]["url"]="https://example.com/evil.sh";sign(d);check(False)
d["version"]="0.0.1";d["assets"]["hostip.sh"]["url"]="https://github.com/coexacx/host-router/releases/download/v0.0.1/hostip.sh"
sign(d);assert check().startswith("older")
print("PASS valid signature, manifest tampering, forged signature, foreign URL, downgrade classification")
print("Artifacts:",root)
