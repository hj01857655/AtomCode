#!/usr/bin/env python3
"""capture_hmac1.py — 精准钩取 HMAC1 的真实输入（key / data 指针 + 静态密钥字节）。

关键修正：此前从未 dump 过静态密钥传入 HMAC1 哪个参数。
disasm 显示（RVA，image_base=0x140000000）：
  0x14045058a  M 就绪： [rsp+0x70]=M.ptr, [rsp+0x100]=97(len)
  0x14045059a  HMAC1    : 静态密钥加载点（lea rdx,[rip+0x24defdf] → 0x14292f570）
  0x1404505ed  ipad ^0x36 / 0x140450637 opad ^0x6a —— 手写 HMAC key schedule

HMAC1 语义未知两种可能：
  A) key=静态密钥(rdx), data=M([rsp+0x70]) —— HMAC(K, M)
  B) key=M, data=静态密钥 —— HMAC(M, K)
钩 0x1404505ed（ipad 入口，此时 key 已在寄存器/栈上）：
  onEnter 记录 rcx/rdx/r8/r9 + [rsp+0x70]/[rsp+0x100] + 静态密钥字节 + ipad 后的 64B。
"""
import os
import time

import frida

EXE = (r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode"
       r"\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe")
ARGS = ["-p", "say OK", "--no-tools", "--provider", "AtomGit-qwen3.8-27b"]
CWD = r"C:\Users\12925"
WAIT = 90

JS = r"""
const RVA_HMAC1_IPAD = 0x4505ed;   // ipad ^0x36 入口
const RVA_HMAC1_OPAD = 0x450637;   // opad ^0x6a 入口

let nIpad = 0, nOpad = 0;
function hexs(ab) { let s=''; for (let i=0;i<ab.length;i++) s+=ab[i].toString(16).padStart(2,'0'); return s; }
function dump(ptr, len, tag) {
    try {
        len = Math.min(len, 256);
        const ab = new Uint8Array(ptr.readByteArray(len));
        send({type:'mem', tag:tag, ptr:ptr.toString(), len:len, hex:hexs(ab)});
    } catch(e) { send({type:'mem_err', tag:tag, msg:e.toString()}); }
}

const mod = Process.enumerateModules().find(m => m.name.toLowerCase().includes('atomcode'));
if (!mod) send({type:'fatal', msg:'atomcode not found'});
else {
    send({type:'info', msg:'base=0x' + mod.base.toString(16)});

    Interceptor.attach(mod.base.add(RVA_HMAC1_IPAD), {
        onEnter() {
            const n = ++nIpad;
            const c = this.context;
            const rsp = c.rsp;
            let info = {
                type: 'ipad', n: n,
                rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                r8: c.r8.toString(), r9: c.r9.toString()
            };
            try { info.rsp70 = rsp.add(0x70).readPointer().toString(); } catch(e){}
            try { info.rsp100 = rsp.add(0x100).readPointer().toInt32(); } catch(e){}
            try { info.rsp108 = rsp.add(0x108).readPointer().toString(); } catch(e){}
            try { info.rsp110 = rsp.add(0x110).readPointer().toInt32(); } catch(e){}
            send(info);
            // dump M（97B @ [rsp+0x70]）
            try { dump(rsp.add(0x70).readPointer(), 97, 'M'); } catch(e){}
            // dump 静态密钥（0x14292f570 绝对地址）
            dump(ptr(0x14292f570), 32, 'static_key');
            // dump 寄存器可能指向的 key（各 32B）
            for (const [name, reg] of [['rcx',c.rcx],['rdx',c.rdx]]) {
                try { dump(reg, 32, 'reg_' + name); } catch(e){}
            }
            // dump 栈窗口 0x00-0x180（含可能的 key 指针/密钥副本）
            try {
                const win = new Uint8Array(rsp.readByteArray(0x180));
                let lines = [];
                for (let i = 0; i < win.length; i += 8) {
                    let row = '';
                    for (let j = 0; j < 8 && i+j < win.length; j++) row += win[i+j].toString(16).padStart(2,'0');
                    lines.push('+' + i.toString(16).padStart(3,'0') + ': ' + row);
                }
                send({type:'stack', tag:'ipad_stack', lines:lines});
            } catch(e) {}
        }
    });

    Interceptor.attach(mod.base.add(RVA_HMAC1_OPAD), {
        onEnter() {
            const n = ++nOpad;
            const c = this.context;
            send({type:'opad', n:n, rcx:c.rcx.toString(), rdx:c.rdx.toString(),
                  r8:c.r8.toString(), r9:c.r9.toString()});
            // opad 入口时 key schedule 的 ipad 结果通常已在栈/寄存器
            for (const [name, reg] of [['rcx',c.rcx],['rdx',c.rdx]]) {
                try { dump(reg, 64, 'opad_reg_' + name); } catch(e){}
            }
        }
    });

    send({type:'ready', msg:'hmac1 hooks installed'});
}
"""


def on_message(message, data):
    if message["type"] == "send":
        p = message["payload"]
        if p.get("type") == "mem":
            print(f"\n### MEM [{p['tag']}] ptr={p['ptr']} len={p['len']}")
            print(f"  {p['hex']}")
        elif p.get("type") == "stack":
            print(f"### STACK [{p['tag']}]")
            for ln in p["lines"]:
                print("  " + ln)
        else:
            print(str(p))
        import sys
        sys.stdout.flush()
    elif message["type"] == "error":
        print(f"[JS-ERROR] {message.get('description', message)}")
        import sys
        sys.stdout.flush()


def main():
    print(f"[*] spawn: {EXE} {ARGS}")
    env = dict(os.environ)
    pid = frida.spawn([EXE] + ARGS, env=env, cwd=CWD, stdio="pipe")
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    print("[*] loaded, resuming")
    frida.resume(pid)
    deadline = time.time() + WAIT
    try:
        while time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    try:
        session.detach()
        frida.kill(pid)
    except Exception:
        pass
    print("[*] done")


if __name__ == "__main__":
    main()
