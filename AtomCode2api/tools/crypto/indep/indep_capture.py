# 独立动态取证（我自有链）：frida spawn atomcode 5.2.3，钩自家 .pdata 定界得到的 RVA
# 产出 indep_capture.log —— 供 atomcode-07 独立版对拍，不引用他人 capture
import frida, sys, time, json, io

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\indep_capture.log"

JS = r"""
'use strict';
function hex(p, n) { try { return hexdump(p, {length: n, header: false, ansi: false}).replace(/\s+/g,'').slice(0, n*2); } catch(e){ return 'ERR'; } }
var BASE = null;
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hook(rva, name, dumpArgs){
  Interceptor.attach(Module.findExportByName(null, 'null') || ptr(0), {}); // noop placeholder
}
setTimeout(function(){
  var M = mod(); BASE = M.base;
  send({evt:'base', value: BASE.toString()});
  var R = {upd:0x566cd5, newsl:0x566c89, keyder:0x566b4b, fin:0x566f1b, f2:0x566576, hex64:0x566950, hex16:0x5668bf, mready:0x45058a, compress:0x27a02b};
  Interceptor.attach(BASE.add(R.upd), { onEnter: function(a){
    var len = a[2].toInt32();
    if (len>0 && len<=160) send({evt:'update', len:len, data:hex(a[1], Math.min(len,96))});
    else send({evt:'update', len:len, data:hex(a[1],48)});
  }});
  Interceptor.attach(BASE.add(R.newsl), { onEnter: function(a){
    send({evt:'new_from_slice', keylen:a[2].toInt32(), key:hex(a[1], Math.min(a[2].toInt32(),64))});
  }});
  Interceptor.attach(BASE.add(R.keyder), { onEnter: function(a){
    send({evt:'keyder', datalen:a[2].toInt32(), data:hex(a[1], Math.min(a[2].toInt32(),112))});
  }});
  Interceptor.attach(BASE.add(R.f2), { onEnter: function(a){
    send({evt:'F2', src:hex(a[1], Math.min(a[2].toInt32(),64)), len:a[2].toInt32()});
  }});
  Interceptor.attach(BASE.add(R.fin), { onEnter: function(a){ this.out = a[0]; },
    onLeave: function(){ send({evt:'finalize_out', out:hex(this.out,32)}); }});
  Interceptor.attach(BASE.add(R.hex16), { onEnter: function(a){
    send({evt:'hexin16', data:hex(a[1], Math.min(a[2].toInt32(),32))});
  }});
}, 1500);
"""

logs = []
def on_msg(msg, data):
    logs.append(json.dumps(msg, ensure_ascii=False))
    print(msg.get('type'), str(msg.get('payload', msg))[:160])

pid = frida.spawn([EXE, '-p', 'hi', '--no-tools'])
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', lambda m, d: (logs.append(json.dumps(m, ensure_ascii=False)), print(json.dumps(m)[:180])))
script.load()
frida.resume(pid)
time.sleep(50)
try: session.detach()
except Exception: pass
try: frida.kill(pid)
except Exception: pass
open(OUT, 'w', encoding='utf-8').write('\n'.join(logs))
print('=== events:', len(logs), '->', OUT)
