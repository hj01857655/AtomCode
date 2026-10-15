# D1 宿主终局取证 v2：进程内扫 D1 原始字节 → 得 holder 堆地址 → 扫"指向 holder 的 qword" → 报宿主表位置
# 对照：--version（不签名）应零 holder；-p ping（签名）应现 holder+表。
import frida, time, json, pathlib, subprocess

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_owner.log")

JS = r"""
'use strict';
setTimeout(function(){
  var holders = [];
  var ranges = Process.enumerateRanges('rw-');
  for (var r = 0; r < ranges.length && holders.length < 3; r++) {
    var rng = ranges[r];
    if (rng.size > 0x2000000) continue;
    try {
      Memory.scanSync(rng.base, rng.size, '01 ac 07 8b 42 a8 a2 1e').slice(0,2).forEach(function(m){
        holders.push(m.address);
      });
    } catch(e){}
  }
  if (!holders.length) { send({evt:'no_holder'}); return; }
  var all = Process.enumerateRanges('r--');
  function scan(pat, cap) {
    var res = [];
    for (var q = 0; q < all.length && res.length < cap; q++) {
      var rg = all[q];
      if (rg.size > 0x2000000) continue;
      try { Memory.scanSync(rg.base, rg.size, pat).slice(0,3).forEach(function(m){ res.push(m.address.toString()); }); } catch(e){}
    }
    return res;
  }
  // 1) D1 hex 文本形态（若从配置文本读入）
  send({evt:'hexform', hits: scan('30 31 61 63 30 37 38 62', 6)});
  // 2) 每个 holder 的全量小端指针引用（含栈段）
  holders.forEach(function(h){
    var hs = h.toString(16);
    while (hs.length < 16) hs = '0' + hs;
    var pat = [];
    for (var i = 7; i >= 0; i--) pat.push(hs.substr(i*2, 2));
    send({evt:'owner', holder:h.toString(), tables: scan(pat.join(' '), 8)});
  });
  send({evt:'done'});
}, 3500);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        print(msg['payload'].get('evt'), str(msg['payload'])[:300])
    else:
        print("ERR", str(msg.get('description'))[:150])

def run(args, wait):
    subprocess.run(["taskkill", "/F", "/IM", "atomcode.exe"], capture_output=True)
    time.sleep(1)
    pid = frida.spawn([EXE] + args)
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)
    time.sleep(wait)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass
    return any('"owner"' in x for x in logs)

print("--- control: --version (no signing) ---")
run(["--version"], 9)
print("--- signing round(s) ---")
for r in range(4):
    n0 = len([x for x in logs if '"owner"' in x])
    run(["-p", "ping", "--no-tools"], 26)
    if len([x for x in logs if '"owner"' in x]) > n0:
        break
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== ->', OUT)
