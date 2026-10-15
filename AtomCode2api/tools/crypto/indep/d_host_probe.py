# D1 宿主结构终探：循环 spawn（先清 atomcode 进程）直到 sign_v1 钩命中；
# 命中后展开 obj[0x28..0x88] 的 fat-ptr 表（{ptr,len}×），解引用每个 len<=64 的项，找 D1 并回报其真身指针。
import frida, time, json, pathlib, subprocess, sys

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_host.log")
D1HEX = "01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2"

JS = r"""
'use strict';
var D1P = '01ac078b42a8a21e';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
setTimeout(function(){
  var BASE = mod().base;
  Interceptor.attach(BASE.add(0x450529), { onEnter: function(a){
    var obj = this.context.rsi;
    var tbl = [];
    for (var i = 0; i < 8; i++) {
      try {
        var slot = obj.add(0x28 + i*16);
        var p1 = slot.readPointer(), p2 = slot.add(8).readPointer();
        // 两种排布都试：{ptr,len} 或 {len,ptr}
        var ptrA = p1, lenA = p2.toUInt32 ? p2.toUInt32() : 0xffffffff;
        var e = {i:i, a:ptrA.toString(), b:p2.toString()};
        if (lenA > 0 && lenA <= 64 && !ptrA.isNull()) {
          try { var h = hexAt(ptrA, lenA); if (h.indexOf(D1P)===0) e.d1 = h; } catch(err){}
        }
        var lenB = p1.toUInt32 ? p1.toUInt32() : 0xffffffff;
        if (lenB > 0 && lenB <= 64 && !p2.isNull() && !(ptrA===p1)) {
          try { var h2 = hexAt(p2, lenB); if (h2.indexOf(D1P)===0) e.d1b = h2; } catch(err){}
        }
        tbl.push(e);
      } catch(e2){ tbl.push({i:i, err:''+e2}); }
    }
    send({evt:'host', obj:obj.toString(), tbl:tbl});
  }});
  send({evt:'ready'});
}, 1200);
"""

state = {"hit": False, "logs": []}
def on_msg(msg, data):
    if msg.get('type') == 'send':
        p = msg['payload']
        state['logs'].append(json.dumps(p, ensure_ascii=False))
        print(p.get('evt'), str(p)[:400])
        if p.get('evt') == 'host':
            for e in p['tbl']:
                if 'd1' in e or 'd1b' in e:
                    state['hit'] = True
    else:
        print("ERR", str(msg)[:180])

for rnd in range(6):
    subprocess.run(["taskkill", "/F", "/IM", "atomcode.exe"], capture_output=True)
    time.sleep(1)
    pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)
    t0 = time.time()
    while time.time() - t0 < 30 and not state['hit']:
        time.sleep(1)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass
    if state['hit']:
        print(f"=== HIT on round {rnd+1}")
        break
    print(f"round {rnd+1}: no D1 in table (daemon 抢单或表偏移不对), retry…")
OUT.write_text('\n'.join(state['logs']), encoding='utf-8')
print('->', OUT)
