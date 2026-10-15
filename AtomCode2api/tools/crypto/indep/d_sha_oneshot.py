# 一次性 SHA256(0x140566516) 出生钩：spawn 签名轮，录每次调用的输入缓冲与输出 32B，找 == D1 的出生事件
import frida, time, json, pathlib, subprocess

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_sha1shot.log")
D1H = "01ac078b42a8a21e"

JS = r"""
'use strict';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
function strAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++){var c=b[i]; s+=(c>=32&&c<127)?String.fromCharCode(c):'.';} return s; }
setTimeout(function(){
  var BASE = mod().base;
  var seq = 0;
  Interceptor.attach(BASE.add(0x566516), {
    onEnter: function(a){
      this.n = ++seq;
      this.self = a[0];
      this.args = [a[0].toString(), a[1].toString(), a[2].toString(), a[3].toString()];
      // 尝试常见 Rust digest API：self=输入结构 {ptr@0, len@8/ptr@8}
      this.snap = [];
      try {
        var p0 = a[0].readPointer(), p1 = a[0].add(8).readPointer();
        var cand = [{x:p0,y:p1},{x:p1,y:p0}];
        for (var k=0;k<2;k++){
          var ptr=cand[k].x, ln=cand[k].y.toNumber();
          if (ptr.compare(ptr('0x1000'))>0 && ln>0 && ln<=2048) {
            this.snap.push({ptr:ptr.toString(), len:ln, head:hexAt(ptr, Math.min(ln,64)), ascii:strAt(ptr, Math.min(ln,80))});
          }
        }
      } catch(e){ this.snapErr = ''+e; }
    },
    onLeave: function(){
      try {
        var out = hexAt(this.self.add(0x20), 32);
        send({evt:'sha', n:this.n, args:this.args, snap:this.snap, snapErr:this.snapErr, out:out, hit:(out.indexOf('01ac078b42a8a21e')===0)});
      } catch(e){ send({evt:'sha', n:this.n, err:''+e}); }
    }
  });
  send({evt:'ready'});
}, 1200);
"""

logs = []
hit = False
def on_msg(msg, data):
    global hit
    if msg.get('type') == 'send':
        p = msg['payload']
        logs.append(json.dumps(p, ensure_ascii=False))
        if p.get('evt') == 'sha':
            mark = "  *** D1 BIRTH ***" if p.get('hit') else ""
            print(f"sha#{p['n']} out={p.get('out','')[:20]}{mark}")
            if p.get('snap'):
                for s in p['snap']: print("     in:", s['len'], "B |", s['ascii'][:78])
            if p.get('hit'): hit = True
        else:
            print(p.get('evt'), str(p)[:150])
    else:
        print("ERR", str(msg.get('description'))[:150])

for r in range(4):
    subprocess.run(["taskkill", "/F", "/IM", "atomcode.exe"], capture_output=True)
    time.sleep(1)
    pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)
    time.sleep(22)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass
    if hit: break
OUT.write_text('\n'.join(logs), encoding='utf-8')
print("=== hit:", hit, "->", OUT)
