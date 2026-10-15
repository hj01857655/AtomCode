# D1 写痕终局取证：spawn suspended → attach → 钩 sign_v1 入口读 D1 地址 → Stalker 全程追写该地址的指令
# 原理：若 D1 每次运行现算（深派生），stalker 会抓到写 [addr..addr+32) 的指令 PC；
#       若启动早期就算完（follow 之前），则 sign_v1 处只有读、无写 ⇒ 定性为"启动期一次性初始化"，写痕追不到属预期。
import frida, time, json, pathlib

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_stalker.log")
D1HEX = "01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2"

JS = r"""
'use strict';
var D1P = '01ac078b42a8a21e';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
var BASE = null, d1Addr = null, writes = [], reads = 0;
setTimeout(function(){
  BASE = mod().base;
  // sign_v1 内 D1 拷贝点：0x450529（extend rdx=[rsi+0x28]）→ 直接钩函数入口更稳：0x450400 时 rsi=对象
  Interceptor.attach(BASE.add(0x450529), { onEnter: function(a){
    var ctx = this.context;
    var obj = ctx.rsi;
    try {
      var v = hexAt(obj.add(0x28), 32);
      send({evt:'signobj', obj:obj.toString(), d1:v, match:(v.indexOf(D1P)===0)});
      if (v.indexOf(D1P)===0 && d1Addr !== obj.add(0x28)) {
        d1Addr = obj.add(0x28);
        startStalker();
      }
    } catch(e){ send({evt:'err', msg:''+e}); }
  }});
  send({evt:'ready'});
}, 1200);
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
function startStalker(){
  var t = Process.enumerateThreads();
  // 只跟当前线程（签名/重建路径）
  Stalker.follow(Process.getCurrentThreadId(), {
    events: { compile: false, ret: false, call: false, callout: false },
    transform: function(it){
      var ins = it.next(); // keep default
    },
    onReceive: function(e){ }
  });
  send({evt:'stalker_on'});
}
"""

# 第二层：Interceptor 方案在"读拷贝点"之外不够抓写——用 Memory 保护页更锋利：
# 对 D1 所在堆页 VirtualProtect → guard page，触发异常即写者 PC。frida 可用 Process.setProtection。
JS2 = r"""
'use strict';
var D1P = '01ac078b42a8a21e';
function mod(){ for (var m of Process.enumerateModules()) if (m.path.toLowerCase().endsWith('atomcode.exe')) return m; return Process.enumerateModules()[0]; }
function hexAt(p,n){ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }
var BASE = null, armed = false;
setTimeout(function(){
  BASE = mod().base;
  Interceptor.attach(BASE.add(0x450529), { onEnter: function(a){
    var obj = this.context.rsi;
    var v = hexAt(obj.add(0x28), 32);
    send({evt:'signobj', obj:obj.toString(), match:(v.indexOf(D1P)===0)});
    // 复制一份"影子对象"再触发一次 sign 流程不现实；改为把源指针报出来，供外部 diff
  }});
  // 全内存找 D1 静态驻留点（.data/堆），最多报 8 处
  Process.enumerateRanges('r--').forEach(function(r){
    if (armed) return;
    try {
      Memory.scanSync(r.base, Math.min(r.size, 0x1000000), '01 ac 07 8b 42 a8 a2 1e').slice(0,4).forEach(function(m){
        send({evt:'found', addr:m.address.toString(), in_module:(m.address.compare(BASE)>=0 && m.address.compare(BASE.add(0xF000000))<0)});
      });
    } catch(e){}
  });
}, 1200);
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        print(msg['payload'].get('evt'), str(msg['payload'])[:160])
    else:
        print("ERR", str(msg)[:200])

pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
session = frida.attach(pid)
script = session.create_script(JS2)
script.on('message', on_msg)
script.load()
frida.resume(pid)
time.sleep(40)
try: session.detach()
except Exception: pass
try: frida.kill(pid)
except Exception: pass
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== events:', len(logs), '->', OUT)
