# D1 宿主 String 解剖：定位含 D1 raw 的 48B 缓冲，dump 其前后共 160B —— 找出嵌在 D1 旁边的 16B 邻居
import frida, time, json, pathlib, subprocess

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_string.log")

JS = r"""
'use strict';
setTimeout(function(){
  var found = [];
  var ranges = Process.enumerateRanges('rw-');
  for (var r = 0; r < ranges.length && found.length < 2; r++) {
    var rng = ranges[r];
    if (rng.size > 0x2000000) continue;
    try {
      Memory.scanSync(rng.base, rng.size, '01 ac 07 8b 42 a8 a2 1e').slice(0,2).forEach(function(m){ found.push(m.address); });
    } catch(e){}
  }
  if (!found.length) { send({evt:'no_hit'}); return; }
  found.forEach(function(h){
    try {
      var start = h.sub(64);
      var b = new Uint8Array(start.readByteArray(160));
      var full = '';
      for (var i = 0; i < b.length; i++) full += ('0'+b[i].toString(16)).slice(-2);
      var off = full.indexOf('01ac078b42a8a21e') / 2;
      // 窗口 = [D1-64 .. D1+96]：前48B/后32B 邻居切片
      var pre = full.slice(0, off*2);            // 128 hex chars 前区
      var post = full.slice((off+32)*2);         // 64 hex chars 后区
      send({evt:'win', holder:h.toString(), off:off, pre:pre, d1:full.substr(off*2, 64), post:post});
    } catch(e){ send({evt:'err', msg:''+e}); }
  });
  send({evt:'done'});
}, 4000);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        p = msg['payload']
        logs.append(json.dumps(p, ensure_ascii=False))
        if p.get('evt') == 'win':
            print("HOLDER", p['holder'])
            print("  pre128:", p['pre'])
            print("  d1    :", p['d1'])
            print("  post64:", p['post'])
        else:
            print(p.get('evt'), str(p)[:200])
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
    time.sleep(24)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass
    if any('"win"' in x for x in logs): break
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== ->', OUT)
