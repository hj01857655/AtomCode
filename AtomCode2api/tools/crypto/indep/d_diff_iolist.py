# 签名轮 vs 非签名轮 IO 差分：循环 spawn 直到 keyder(97B) 命中；期间全量录 CreateFileW；与 d_api_trace.log 的基线清单 diff
import frida, time, json, pathlib, subprocess

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
BASE = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep")
OUT = BASE / "d_iolist_sign.log"

JS = r"""
'use strict';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
var files = [], signing = false;
setTimeout(function(){
  var BASE = mod().base;
  var adv = Process.findModuleByName('advapi32.dll'), k32 = Process.findModuleByName('kernel32.dll');
  function hookOpen(){
    var f = k32.findExportByName('CreateFileW');
    Interceptor.attach(f, { onEnter: function(a){ try { var p = a[0].readUtf16String(); if (p && files.indexOf(p) < 0) files.push(p); } catch(e){} } });
  }
  hookOpen();
  Interceptor.attach(BASE.add(0x566b4b), { onEnter: function(a){
    if (!signing && a[2].toInt32() === 97) {
      var h = hexAt(a[1], 97);
      if (h.indexOf('01ac078b42a8a21e') === 66) { signing = true; send({evt:'signing'}); }
    }
  }});
  // 结束信号：进程要退出了（finalize 之后 2s）→ dump
  Interceptor.attach(BASE.add(0x450ae9), { onEnter: function(){ send({evt:'sigend_dump', files: files.slice(0, 600)}); } });
  send({evt:'ready'});
}, 1200);
"""

logs = []
done = {"f": False}
def on_msg(msg, data):
    if msg.get('type') == 'send':
        p = msg['payload']
        logs.append(json.dumps(p, ensure_ascii=False))
        print(p.get('evt'), (str(p)[:120] if p.get('evt') != 'sigend_dump' else f"files={len(p.get('files',[]))}"))
    else:
        print("ERR", str(msg.get('description'))[:150])

for r in range(6):
    subprocess.run(["taskkill", "/F", "/IM", "atomcode.exe"], capture_output=True)
    time.sleep(1)
    logs.clear()
    pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)
    t0 = time.time()
    while time.time() - t0 < 25:
        if any('"sigend_dump"' in x for x in logs): break
        time.sleep(1)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass
    if any('"sigend_dump"' in x for x in logs):
        break

OUT.write_text('\n'.join(logs), encoding='utf-8')
# diff 基线
try:
    base_files = {json.loads(x).get('path') for x in (BASE/'d_api_trace.log').read_text(encoding='utf-8').splitlines() if '"file"' in x}
except Exception:
    base_files = set()
sign_files = set()
for x in logs:
    try:
        p = json.loads(x)
        if p.get('evt') == 'sigend_dump': sign_files = set(p.get('files', []))
    except Exception: pass
new = sorted(sign_files - base_files)
print("sign-round files NOT in baseline:", len(new))
for f in new[:60]: print("  +", f)
