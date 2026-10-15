# 启动期 DNS/外连取证：spawn 登录态进程，钩 ws2_32!getaddrinfo 域名 + connectex IP:port
# 判据：启动到出词之间出现过 api.gitcode.com / acs.atomgit.com / llm-api / relay 等 ⇒ 有会话/种子拉取动作
import frida, time, json, pathlib

EXE = r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe"
OUT = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\d_dns_trace.log")

JS = r"""
'use strict';
function expOf(mod, fn){ try { var m = Process.findModuleByName(mod); return m ? m.findExportByName(fn) : null; } catch(e){ return null; } }
var gai = expOf('ws2_32.dll','getaddrinfo');
if (gai) Interceptor.attach(gai, { onEnter: function(a){ try { send({evt:'dns', host:a[0].readUtf8String()}); } catch(e){} } });
var conn = expOf('ws2_32.dll','connect');
if (conn) Interceptor.attach(conn, { onEnter: function(a){
  try {
    var sa = a[1], fam = sa.readU16(), port = 0, ip = '';
    if (fam == 2) { port = (sa.add(2).readU8()<<8) | sa.add(3).readU8();
      var q = sa.add(4); ip = q.readU8()+'.'+q.add(1).readU8()+'.'+q.add(2).readU8()+'.'+q.add(3).readU8(); }
    send({evt:'conn', ip:ip, port:port});
  } catch(e){}
}});
send({evt:'ready', pid: Process.id});
"""

logs = []
def on_msg(msg, data):
    if msg.get('type') == 'send':
        logs.append(json.dumps(msg['payload'], ensure_ascii=False))
        p = msg['payload']
        if p.get('evt') == 'conn': return   # IP 噪音大，只落盘不打
        print(p.get('evt'), str(p)[:120])
    else:
        print("ERR", str(msg)[:180])

pid = frida.spawn([EXE, "-p", "ping", "--no-tools"])
session = frida.attach(pid)
script = session.create_script(JS)
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
