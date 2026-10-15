# D1 堆副本上下文 dump：spawn → scan 定位 → 前后各读 0x200B，看嵌在什么结构里
import frida, time, json, pathlib

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_ctx.log")

JS = r"""
'use strict';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
var BASE = null;
setTimeout(function(){
  BASE = mod().base;
  function strdump(p, n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++){ var c=b[i]; s += (c>=32&&c<127)?String.fromCharCode(c):'.'; } return s; }
  function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
  // 钩 sign_v1 内 D1 拷贝点：rsi = provider 状态对象，+0x28 = D1
  Interceptor.attach(BASE.add(0x450529), { onEnter: function(a){
    var obj = this.context.rsi;
    var q = [];
    for (var i=0;i<20;i++) { try { q.push(obj.sub(0x40).add(i*8).readPointer().toString()); } catch(e){ q.push('?'); } }
    send({evt:'obj', addr:obj.toString(),
          d1: hexAt(obj.add(0x28), 32),
          pre: strdump(obj.sub(0x40), 64),
          f00: strdump(obj, 40),
          f40: strdump(obj.add(0x40), 64),
          f80: strdump(obj.add(0x80), 64),
          q: q});
  }});
  send({evt:'ready'});
}, 1200);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        p = msg['payload']
        if (p.get('evt') == 'obj'):
            print("OBJ", p['addr'], "D1=", p['d1'][:16])
            print("  pre:", p['pre']); print("  f00:", p['f00']); print("  f40:", p['f40']); print("  f80:", p['f80'])
            print("  q:", p['q'][:12])
        else:
            print(p.get('evt'), str(p)[:250])
    else:
        print("ERR", str(msg)[:200])

pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
session = frida.attach(pid)
script = session.create_script(JS)
script.on('message', on_msg)
script.load()
frida.resume(pid)
time.sleep(35)
try: session.detach()
except Exception: pass
try: frida.kill(pid)
except Exception: pass
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== ->', OUT)
