# D1 回溯 v2：attach 到现役 daemon（真实签名为它代跑），钩 extend_from_slice 抓 32B 段 src+backtrace
# 若 daemon 不在则先 spawn 一次 -p ping 拉起，再 attach。
import frida, sys, time, json, subprocess, pathlib

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d1_trace.log")

JS = r"""
'use strict';
function hex(p, n) { try { var b = new Uint8Array(p.readByteArray(n)); var s=''; for (var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; } catch(e){ return 'ERR'; } }
var M = null; for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) { M = m; break; }
if (!M) M = Process.enumerateModules()[0];
var BASE = M.base;
send({evt:'base', value: BASE.toString(), pid: Process.id});
var cnt = 0;
Interceptor.attach(BASE.add(0x566b4b), { onEnter: function(a){
  var len = a[2].toInt32();
  if (len >= 1 && len <= 256) send({evt:'keyder', len:len, data:hex(a[1], len)});
}});
Interceptor.attach(BASE.add(0x566ed2), { onEnter: function(a){
  if (cnt++ > 400) return;
  var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
    .map(function(x){ return x.sub(BASE); })
    .filter(function(x){ return x.compare(ptr(0x1000))>0 && x.compare(ptr(0x1000000))<0; })
    .slice(0,6).map(function(x){ return '0x'+x.toString(16); });
  send({evt:'ext_raw', rcx:a[0].toString(), rdx:a[1].toString(), r8:a[2].toInt32()&0x1ff, w:hex(a[1],32), bt:bt, ret:'0x'+this.returnAddress.sub(BASE).toString(16)});
}});
"""

def find_daemon():
    procs = frida.get_local_device().enumerate_processes()
    return sorted([p for p in procs if (p.name or "").lower() == "atomcode.exe"], key=lambda p: p.pid)

procs = find_daemon()
if procs:
    print("killing stray atomcode procs:", [p.pid for p in procs])
    for p in procs:
        try: frida.kill(p.pid)
        except Exception: pass
    time.sleep(2)
spawned = frida.spawn([EXE, "-p", "ping", "--no-tools"])
print("spawned", spawned)

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        p = msg['payload']
        print(p.get('evt'), str(p)[:200])
    else:
        print("ERR", str(msg)[:200])

session = frida.attach(spawned)
script = session.create_script(JS)
script.on('message', on_msg)
script.load()
print(f"attached spawn pid={spawned}; resuming…")
frida.resume(spawned)
time.sleep(40)
try: session.detach()
except Exception: pass
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== events:', len(logs), '->', OUT)
