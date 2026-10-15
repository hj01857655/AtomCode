# D1 生成者终局动态取证：sign_v1 入口 → 解 obj 切片表找 D1 宿主堆对象 → 全内存扫指向它的指针 → 报宿主表位置
import frida, time, json, pathlib, subprocess

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_owner.log")
D1HEX = "01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2"
D1PAT = " ".join(D1HEX[i:i+2] for i in range(0, 16, 2))
OWNERPAT = " ".join(D1HEX[i:i+2] for i in range(0, 16, 2))  # 同 D1 前 8B

JS = r"""
'use strict';
var D1P = '01ac078b42a8a21e';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
var done = false;
setTimeout(function(){
  var BASE = mod().base;
  Interceptor.attach(BASE.add(0x450400), { onEnter: function(a){
    if (done) return;
    var ctx = this.context;
    var candidates = [ctx.rsi, ctx.rdi, ctx.rbx, ctx.r14, ctx.r15].filter(function(p){ try { p.readPointer(); return true; } catch(e){ return false; } });
    for (var c = 0; c < candidates.length; c++) {
      var obj = candidates[c];
      // 扫 obj 及其前 0x100：找 {ptr,len} 其中 len==48(64dec?) 或 ==32 且内容==D1
      for (var off = -0x40; off <= 0x140; off += 8) {
        try {
          var slot = obj.add(off);
          var p = slot.readPointer();
          var meta = slot.add(8).readPointer();
          var ln1 = slot.add(8).readU32 ? slot.add(8).readU32() : 0;
          for (var cand of [p, meta]) {
            if (!cand || cand.compare(ptr(0x1000)) < 0) continue;
            var h; try { h = hexAt(cand, 8); } catch(e){ continue; }
            if (h === D1P) {
              done = true;
              send({evt:'owner_found', obj:obj.toString(), cand_off:off, holder:cand.toString(), via: (cand===p?'first':'second')});
              // 扫谁持有指向 holder 的 qword
              var ptrBytes = cand.and(ptr('0xffffffffffffffff'));
              var pat = [];
              var v = ptrBytes;
              for (var i=0;i<8;i++){ pat.push(('0'+(v.shr(i*8).and(0xff).toInt? v.shr(i*8).and(0xff).toNumber():0).toString(16)).slice(-2)); }
              var hexpat = pat.reverse().join(' ');
              var tables = [];
              var ranges = Process.enumerateRanges('rw-');
              var scanned = 0;
              for (var r = 0; r < ranges.length && tables.length < 6; r++) {
                var rng = ranges[r];
                if (rng.size > 0x2000000) continue;
                scanned += rng.size;
                try {
                  Memory.scanSync(rng.base, rng.size, hexpat).slice(0,3).forEach(function(m){ tables.push(m.address.toString()); });
                } catch(e){}
                if (tables.length >= 6) break;
              }
              send({evt:'tables', holder: holder_str, tables: tables, scanned_mb: (scanned/1048576)|0, d1_is_ascii68: undefined});
              return;
            }
          }
        } catch(e){}
      }
    }
    function holder_str(){}
  }});
  send({evt:'ready'});
}, 1200);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        print(msg['payload'].get('evt'), str(msg['payload'])[:300])
    else:
        print("ERR", str(msg.get('description'))[:120])

def run():
    subprocess.run(["taskkill", "/F", "/IM", "atomcode.exe"], capture_output=True)
    time.sleep(1)
    pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)
    time.sleep(30)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass
    return any('"owner_found"' in x for x in logs)

for r in range(5):
    if run(): break
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== ->', OUT)
