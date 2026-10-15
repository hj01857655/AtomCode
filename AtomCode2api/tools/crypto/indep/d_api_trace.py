# D1 存储来源取证：spawn 同进程钩"取秘密"的系统调用，抓初始化数据流
#   crypt32!CryptUnprotectData(pDataIn, ..., pDataOut)：7 参，a[0] 输入 blob / a[6] 输出 blob
#   kernel32!CreateFileW：敏感路径收集；advapi32!RegGetValueW/RegQueryValueExW：注册表
# 判据：任一 in/out buffer 含 D1 前缀 01ac078b42a8a21e；即便不命中也能看出客户端是否用 DPAPI。
import frida, time, json, pathlib

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_api_trace.log")

JS = r"""
'use strict';
var D1P = '01ac078b42a8a21e';
function hex(p,n){ try{ var b=new Uint8Array(p.readByteArray(n)); var s=''; for(var i=0;i<b.length;i++) s+=('0'+b[i].toString(16)).slice(-2); return s; }catch(e){return 'ERR';} }
function blob(tag, p){ // DATA_BLOB {u32 cb; ptr pb} (x64: pb at +8)
  try {
    var cb = p.readU32(), pb = p.add(8).readPointer();
    if (cb>0 && cb<=4096) {
      var h = hex(pb, cb);
      send({evt:'blob', tag:tag, cb:cb, head:h.slice(0,128), hit:(h.indexOf(D1P)>=0)});
    }
  } catch(e){ send({evt:'blob_err', tag:tag, msg:''+e}); }
}
function expOf(modName, fnName){ try { var m = Process.findModuleByName(modName); if (!m) return null; return m.findExportByName(fnName); } catch(e){ return null; } }
var dp = expOf('crypt32.dll','CryptUnprotectData');
if (dp) Interceptor.attach(dp, {
  onEnter: function(a){ blob('dpapi-in', a[0]); this.out = a[6]; },
  onLeave: function(r){ if (r.toInt32()!==0) blob('dpapi-out', this.out); }
}); else send({evt:'no_dpapi_export'});
var seen = {};
// 硬件指纹/系统材料 API：MAC、卷序列号、注册表全开放记录
['iphlpapi.dll!GetAdaptersInfo','iphlpapi.dll!GetAdaptersAddresses'].forEach(function(spec){
  var ps = spec.split('!'); var f = expOf(ps[0], ps[1]);
  if (f) Interceptor.attach(f, { onEnter: function(){ send({evt:'hwapi', api:ps[1]}); } });
});
var gvi = expOf('kernel32.dll','GetVolumeInformationW');
if (gvi) Interceptor.attach(gvi, { onEnter: function(a){ try { send({evt:'hwapi', api:'GetVolumeInformationW', root:a[0].readUtf16String()}); } catch(e){ send({evt:'hwapi', api:'GetVolumeInformationW'}); } } });
var rok = expOf('advapi32.dll','RegOpenKeyExW');
if (rok) Interceptor.attach(rok, { onEnter: function(a){ try { var s=a[1].readUtf16String(); if (s && !seen['r'+s]) { seen['r'+s]=1; send({evt:'regopen', key:s}); } } catch(e){} } });
['bcrypt.dll!BCryptDeriveKeyPBKDF2','bcrypt.dll!BCryptDeriveKey','crypt32.dll!CryptDeriveKey'].forEach(function(spec){
  var ps = spec.split('!'); var f = expOf(ps[0], ps[1]);
  if (f) Interceptor.attach(f, { onEnter: function(){ send({evt:'kdfapi', api:ps[1]}); } });
});
var cf = expOf('kernel32.dll','CreateFileW');
if (cf) Interceptor.attach(cf, { onEnter: function(a){
  try { var p = a[0].readUtf16String();
    if (p && !seen[p] && /key|cred|secret|auth|atomcode|dpapi|master|protect|token/i.test(p)) { seen[p]=1; send({evt:'file', path:p}); }
  } catch(e){}
}});
['advapi32.dll!RegGetValueW','advapi32.dll!RegQueryValueExW'].forEach(function(spec){
  var parts = spec.split('!');
  var f = expOf(parts[0], parts[1]);
  if (!f) return;
  Interceptor.attach(f, { onEnter: function(a){
    try { var s = a[1].readUtf16String(); if (s && /atomcode/i.test(s) && !seen[s]) { seen[s]=1; send({evt:'reg', key:s}); } } catch(e){}
  }});
});
send({evt:'ready', pid: Process.id});
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        print(msg['payload'].get('evt'), str(msg['payload'])[:170])
    else:
        print("ERR", str(msg)[:200])

pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
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
OUT.write_text('\n'.join(logs), encoding='utf-8')
print('=== events:', len(logs), '->', OUT)
