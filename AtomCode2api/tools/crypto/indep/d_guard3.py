# D1 写痕追踪 v3：keyder(M,97B) 命中后把 D1 所在页设为 NO_ACCESS + 异常处理器抓写入者 PC/栈
import frida, time, json, pathlib, subprocess

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_guard3.log")

JS = r"""
'use strict';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
var armed = false, BASE = null;
setTimeout(function(){
  BASE = mod().base;
  Process.setExceptionHandler(function(details){
    send({evt:'exception', type:details.type,
          mem: details.memory ? details.memory.address.toString() : null,
          pc_rva: '0x'+details.context.pc.sub(BASE).toString(16),
          bt: (details.backtrace||[]).map(function(x){ return '0x'+ptr(x).sub(BASE).toString(16); }).slice(0,10)});
    return false;
  });
  Interceptor.attach(BASE.add(0x566b4b), { onEnter: function(a){
    if (armed) return;
    if (a[2].toInt32() !== 97) return;
    var h = hexAt(a[1], 97);
    if (h.indexOf('01ac078b42a8a21e') !== 66) return;
    armed = true;
    var d1 = a[1].add(33);
    var page = d1.and(ptr('0xfffffffffffff000'));
    var ok = Process.setProtection(page, 0x1000, true, false, false);
    send({evt:'armed', M:a[1].toString(), d1:d1.toString(), page:page.toString(), ok:ok});
  }});
  send({evt:'ready'});
}, 1200);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        p = msg['payload']; logs.append(json.dumps(p, ensure_ascii=False))
        print(p.get('evt'), str(p)[:300])
    else:
        logs.append(json.dumps(msg, ensure_ascii=False)); print("ERR", str(msg.get('description'))[:150])

def run(args):
    subprocess.run(["taskkill", "/F", "/IM", "atomcode.exe"], capture_output=True)
    time.sleep(1)
    pid = frida.spawn([EXE] + args)
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)
    t0 = time.time()
    while time.time() - t0 < 30:
        if any('"armed"' in x for x in logs) or any('"exception"' in x for x in logs):
            break
        time.sleep(1)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass
    return any('"armed"' in x for x in logs)

for args in (["-p", "ping", "--no-tools"], ["-p", "ping"], ["status"]):
    print("--- try", args)
    if run(args):
        break
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== ->', OUT)
