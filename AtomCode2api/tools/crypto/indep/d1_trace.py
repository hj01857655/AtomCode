# D1 来源取证：钩 Vec::extend_from_slice(0x566ed2)，抓 len==32 拼装段的 src + 返回地址 + backtrace
# M 构造四段：token(24)/01+LE64(9)/D1(32)/D2(32)——D2=SHA256("5.2.3") 可自识别，另一段 32B 即 D1
# 产出 d1_trace.log（含 RVA 化的 return address 与线程 backtrace 前 6 帧）
import frida, sys, time, json

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d1_trace.log"

JS = r"""
'use strict';
function hex(p, n) {
  try {
    var b = new Uint8Array(p.readByteArray(n));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch(e){ return 'ERR'; }
}
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
var BASE = null;
setTimeout(function(){
  BASE = mod().base;
  send({evt:'base', value: BASE.toString()});
  Interceptor.attach(BASE.add(0x566ed2), { onEnter: function(a){
    var len = a[2].toInt32();
    if (len === 32 || len === 24 || len === 1) {
      var ra = this.returnAddress;
      var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                 .map(function(x){ return x.sub(BASE); }).filter(function(x){ return x.compare(ptr(0))>0 && x.compare(ptr(0x1000000))<0; })
                 .slice(0,6).map(function(x){ return '0x'+x.toString(16); });
      send({evt:'extend', len:len, src:hex(a[1], len), dst:a[0].toString(),
            ret_rva:'0x'+ra.sub(BASE).toString(16), bt:bt});
    }
  }});
}, 1500);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        print(msg['payload'].get('evt'), str(msg['payload'])[:170])

pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', on_msg)
script.load()
frida.resume(pid)
time.sleep(45)
try: session.detach()
except Exception: pass
try: frida.kill(pid)
except Exception: pass
open(OUT, 'w', encoding='utf-8').write('\n'.join(logs))
print('=== events:', len(logs), '->', OUT)
