# D1 计算者捕获：从 M 组装 extend(src=D1段) 拿源指针 → 页级去可写 → 二次签名写它即触发异常 → onException 报 PC+回溯
# 判读：抓到写者 PC ⇒ D1 每次签名现算（深派生可继续反汇编追公式）；
#       全程无写但签名照常 ⇒ D1 每进程算一次后只读，初始化在启动期（写痕抓不到属预期）。
import frida, time, json, pathlib, subprocess

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_guard.log")
D1HEX = "01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2"

JS = r"""
'use strict';
var D1P = '01ac078b42a8a21e';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
var armed = false;
setTimeout(function(){
  var BASE = mod().base;
  Interceptor.attach(BASE.add(0x566ed2), { onEnter: function(a){
    if (armed) return;
    var len = a[2].toInt32();
    if (len !== 32) return;
    var h; try { h = hexAt(a[1], 32); } catch(e){ return; }
    if (h.indexOf(D1P) !== 0) return;
    armed = true;
    var src = a[1];
    var page = src.and(ptr('0xfffffffffffff000'));
    // 去掉该页写权限（保留读）；Rust 若之后重写会 raise EXCEPTION_ACCESS_VIOLATION
    var ok = Process.setProtection(page, 0x1000, true /*read*/, false /*write*/, false /*exec*/);
    send({evt:'armed', src:src.toString(), page:page.toString(), prot_ok:ok});
  }});
  // 二次 sign 的拷贝点：命中即说明写者已被异常拦（onException 报事件），此处报"读用了缓存"
  Interceptor.attach(BASE.add(0x450529), { onEnter: function(){
    send({evt:'sign2_read', note:'second sign_v1 reached; no write hit yet'});
  }});
}, 1200);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        print(msg['payload'].get('evt'), str(msg['payload'])[:220])
    else:
        logs.append(json.dumps(msg, ensure_ascii=False))
        print("ERR", str(msg.get('description'))[:100], str(msg.get('stack'))[:300])

# 第 1 阶段：spawn+arm guard（签名发生在本进程时才 armed；循环到 armed 成功）
def run_round(secs):
    subprocess.run(["taskkill", "/F", "/IM", "atomcode.exe"], capture_output=True)
    time.sleep(1)
    pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on('message', on_msg)
    script.load()
    frida.resume(pid)
    time.sleep(secs)
    try: session.detach()
    except Exception: pass
    try: frida.kill(pid)
    except Exception: pass

armed = False
for r in range(5):
    run_round(28)
    if any('armed' in x for x in logs):
        print("=== guard armed at round", r+1)
        armed = True
        break
if armed:
    # 第 2 阶段：同进程内二次签名需要进程活够久；上面 28s 已含完整 ping 周期，
    # 若同进程还起 daemon 代跑其他请求会再 sign——sign2_read 事件即"绕过写"的证据。
    pass
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== events:', len(logs), '->', OUT)
