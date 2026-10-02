#!/usr/bin/env python3
"""Exercise real menu navigation and rule mutations using an isolated running router."""
import fcntl,json,os,pathlib,pty,re,select,socket,struct,subprocess,sys,tempfile,termios,time
binary=str(pathlib.Path(sys.argv[1]).resolve())
project=pathlib.Path(__file__).resolve().parents[1]
root=pathlib.Path(tempfile.mkdtemp(prefix="host-router-menu-"));cfg=root/"config.json"
cfg.write_text('{"rules":[]}')
env=dict(os.environ,HOST_ROUTER_BIN=binary,HOST_ROUTER_CONFIG=str(cfg),TERM="dumb",NO_COLOR="1")
ports=[]
for _ in range(3):
    with socket.socket() as sock:sock.bind(("127.0.0.1",0));ports.append(sock.getsockname()[1])
ports=[f"127.0.0.1:{p}" for p in ports]
log=(root/"router.log").open("w")
router=subprocess.Popen([binary,"-c",str(cfg),"serve"],stdout=log,stderr=log)
def rules():return json.loads(cfg.read_text())["rules"]
def menu(lines):
    p=subprocess.run(["bash",str(project/"hostip.sh")],input="\n".join(lines)+"\n",capture_output=True,text=True,env=env,timeout=20)
    assert p.returncode==0,(p.stdout,p.stderr)
    assert "\x1b" not in p.stdout,"redirected/plain output must not contain ANSI"
    return p.stdout+p.stderr
try:
    for _ in range(100):
        if cfg.with_suffix(".sock").exists():break
        assert router.poll() is None
        time.sleep(.02)
    output=menu(["2","1","70000",ports[0],"a.test","127.0.0.1","29678","n","","0"])
    assert "格式不正确" in output and "确认添加" in output
    assert not rules(),"cancelled preview changed rules"
    marker=root/"injected"
    output=menu(["2","1",ports[0],"a.test",f"$(touch {marker})","127.0.0.1","29678","y","","0"])
    assert "格式不正确" in output and not marker.exists()
    assert len(rules())==1 and rules()[0]["protocol"]=="both"
    batch=["b.test 127.0.0.1 29678","c.test 127.0.0.1 29678"]
    menu(["2","2",ports[0],*batch,"","n","","0"]);assert len(rules())==1
    menu(["2","2",ports[0],*batch,"","y","","0"]);assert len(rules())==3
    menu(["2","3",f"{ports[1]} d.test 127.0.0.1 29678",f"{ports[2]} e.test 127.0.0.1 29678","","y","","0"])
    assert len(rules())==5
    menu(["3","1",ports[0],"renamed.test","127.0.0.1:29679","n","","0"]);assert rules()[0]["domain"]=="a.test"
    menu(["3","1",ports[0],"renamed.test","127.0.0.1:29679","y","","0"]);assert rules()[0]["domain"]=="renamed.test"
    menu(["3","1","","","","y","","0"]);assert rules()[0]["domain"]=="renamed.test"
    menu(["4","2 4","n","","0"]);assert len(rules())==5
    menu(["4","2 4","y","","0"]);assert len(rules())==3
    output=menu(["4","1 999","y","","0"]);assert len(rules())==3 and "删除失败" in output
    menu(["5","1","60","","0"]);assert json.loads(cfg.read_text())["dns_refresh_seconds"]==60
    output=menu(["7","1","","0"]);assert "保护状态" in output and "当前使用 / 有效上限" in output
    for submenu in ["2","5","6","7","8"]:
        menu([submenu,"0","0"])
    before=cfg.read_bytes();batch_file=root/"preview.txt";batch_file.write_text("preview.test 127.0.0.1 29678\n")
    preview=subprocess.run([binary,"-c",str(cfg),"add-batch","--listen",ports[0],"--file",str(batch_file),"--check-only"],capture_output=True,text=True)
    assert preview.returncode==0 and cfg.read_bytes()==before
    assert json.loads(subprocess.check_output([binary,"-c",str(cfg),"status"]))["rules"]==3
    plain=menu(["0"]);(root/"menu.txt").write_text(plain)
    assert "转发规则" in plain and "运行维护" in plain and "自动调整" in plain
    # Real PTY path verifies colored display, keyboard input, and a clean exit.
    master,slave=pty.openpty();fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack("HHHH",24,80,0,0))
    tty_env=dict(env,TERM="xterm-256color");tty_env.pop("NO_COLOR",None)
    p=subprocess.Popen(["bash",str(project/"hostip.sh")],stdin=slave,stdout=slave,stderr=slave,env=tty_env)
    os.close(slave);os.write(master,b"0\n");capture=b"";deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        if select.select([master],[],[],.2)[0]:
            try:data=os.read(master,65536)
            except OSError:break
            if not data:break
            capture+=data
        if p.poll() is not None:break
    if p.poll() is None:p.kill()
    assert p.wait(5)==0 and b"\x1b[1;36m" in capture,capture
    os.close(master);(root/"menu-tty.txt").write_bytes(capture)
    print("PASS real menus: invalid field retry, no command interpolation, preview/cancel, single and both batch modes, edit/delete, settings, status, submenu return, PTY colors")
    print("Artifacts:",root)
finally:
    router.terminate();router.wait(5);log.close()
