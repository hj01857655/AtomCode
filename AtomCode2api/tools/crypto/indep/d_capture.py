# D 原像实验第一步：frida spawn atomcode 抓本次会话的 D（=keyder/finalize 产物，免费档启动期即触发）
# 产出 d_capture.log：全部 finalize_out/new_from_slice/update/keyder/F2 事件。跑完用 match_d_preimage.py 对拍。
import frida, sys, time, json

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_capture.log"
CMD = sys.argv[1:] or ["-p", "ping", "--no-tools"]

JS = r"""
'use strict';
function hex(p, n) {
  try {
    var b = new Uint8Array(p.readByteArray(n));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch(e){ return 'ERR:' + e.message; }
}
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
setTimeout(function(){
  var BASE = mod().base;
  send({evt:'base', value: BASE.toString()});
  var R = {upd:0x566cd5, newsl:0x566c89, keyder:0x566b4b, fin:0x566f1b, f2:0x566576, compress:0x27a02b};
  var updSeq = [];
  Interceptor.attach(BASE.add(R.upd), { onEnter: function(a){
    var len = a[2].toInt32();
    if (len > 0 && len <= 256) send({evt:'update', self: a[0].toString(), len:len, data:hex(a[1], len)});
  }});
  Interceptor.attach(BASE.add(R.newsl), { onEnter: function(a){
    var kl = a[2].toInt32();
    if (kl > 0 && kl <= 64) send({evt:'new_from_slice', self: a[0].toString(), keylen:kl, key:hex(a[1], kl)});
  }});
  Interceptor.attach(BASE.add(R.keyder), { onEnter: function(a){
    var dl = a[2].toInt32();
    if (dl > 0 && dl <= 256) send({evt:'keyder', len:dl, data:hex(a[1], dl)});
  }});
  Interceptor.attach(BASE.add(R.f2), { onEnter: function(a){
    var dl = a[2].toInt32();
    if (dl > 0 && dl <= 128) send({evt:'F2', len:dl, src:hex(a[1], dl)});
  }});
  Interceptor.attach(BASE.add(R.fin), { onEnter: function(a){ this.out = a[0]; this.self = a[0].toString(); },
    onLeave: function(){ send({evt:'finalize_out', self:this.self, out:hex(this.out,32)}); }});
}, 1500);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        p = msg['payload']
        print(p.get('evt'), str(p)[:150])

pid = frida.spawn([EXE] + CMD)
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
