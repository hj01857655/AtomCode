#!/usr/bin/env python3
"""capture_full.py v2 — 一次运行抓全 sign_v1 全部中间量，供离线逐层复算对拍。

静态骨架（disasm_sign.log 已钉死，全部 RVA，image_base=0x140000000）：
  0x14045058a  M 就绪      : [rsp+0x70]=M.ptr, [rsp+0x100]=97(len), [rsp+0x108]=ptr, [rsp+0x110]=cap
  0x14045059a  HMAC1.update : rdx=cell(0x14292f570, 32B 静态密钥 e97250f0...637123)
  0x1404505ed  ipad ^0x36   / 0x140450637 opad ^0x6a —— 手写 HMAC key schedule
  0x1404506e0  HKDF info    : "atomcode-signing-v1" (19B)
  0x1404508a8  HKDF 完成    : rsp+0x440 = OKM(32B)
  0x1404508ff  HMAC2        : new_from_slice(OKM) —— key = OKM
  0x140450904.. canonical    : "v1\\n" + "POST" + "\\n" + path + "\\n" + <body相关> + "\\n"
                               + hex(nonce16) + "\\n" + ts + ...
  0x140450ab0  输出          : "v1:" 前缀 + hex64(HMAC2.finalize) → X-AtomCode-Sig

v1 教训（本版已修）：
  - JS 常量必须写死在 JS 里 —— 上一版靠 Python % 格式化注入 MAX_UPDATE，漏了
    `% {}` 替换，JS 里 MAX_UPDATE 未定义 → 所有 update/hex 钩子 ReferenceError 报废。
  - 0x140566c89 (new_from_slice) 的 rdx 是指向 (ptr,len) 结构的栈指针，直接读
    [rdx]/[rdx+8] 拿到的是未填充值；改为原始 dump 32B 离线核对。
"""
import json
import os
import sys
import time

import frida

EXE = (r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode"
       r"\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe")
ARGS = ["-p", "say OK", "--no-tools", "--provider", "AtomGit-qwen3.8-27b"]
CWD = r"C:\Users\12925"
WAIT_SECONDS = 120

JS = r"""
const RVA_M_READY   = 0x45058a;   // M 就绪：rsp+0x70=M.ptr(heap)
const RVA_OKM_DONE  = 0x4508a8;   // HKDF 完成：rsp+0x440 = OKM 32B
const RVA_NEW_KEY   = 0x566c89;   // HmacSha256::new_from_slice(rcx=self, rdx=&struct)
const RVA_UPDATE    = 0x566cd5;   // hmac.update(rcx=self, rdx=data, r8=len)
const RVA_HEX64     = 0x566950;   // hex-encode(rcx=out, rdx=data, r8=len) —— body hash / 最终签名
const RVA_HEX16     = 0x5668bf;   // hex-encode —— nonce(16B)

const MAX_UPDATE = 40;
const MAX_HEXENC = 12;

let phase = 0;        // 0=未进签名 1=M就绪(HMAC1/HKDF) 3=OKM后(HMAC2 canonical)
let nUpdate = 0, nHex64 = 0, nHex16 = 0, nNewKey = 0;

function hexs(ab) {
    let s = '';
    for (let i = 0; i < ab.length; i++) s += ab[i].toString(16).padStart(2, '0');
    return s;
}
function asc(ab) {
    let s = '';
    for (let i = 0; i < ab.length; i++) {
        const b = ab[i];
        if (b === 10) s += '\n';
        else if (b >= 32 && b < 127) s += String.fromCharCode(b);
        else s += '.';
    }
    return s;
}
function dumpPtr(ptr, len, tag) {
    try {
        len = Math.min(len, 512);
        const ab = new Uint8Array(ptr.readByteArray(len));
        send({type: 'mem', tag: tag, ptr: ptr.toString(), len: len,
              hex: hexs(ab), ascii: asc(ab)});
    } catch (e) {
        send({type: 'mem_err', tag: tag, ptr: ptr.toString(), msg: e.toString()});
    }
}
function dumpStackWin(rsp, from, to, tag) {
    try {
        const n = to - from;
        const ab = new Uint8Array(rsp.add(from).readByteArray(n));
        let lines = [];
        for (let i = 0; i < n; i += 8) {
            let row = '';
            for (let j = 0; j < 8 && i + j < n; j++) row += ab[i + j].toString(16).padStart(2, '0');
            lines.push('  +' + (from + i).toString(16).padStart(3, '0') + ': ' + row);
        }
        send({type: 'stack', tag: tag, lines: lines});
    } catch (e) {
        send({type: 'mem_err', tag: tag, msg: e.toString()});
    }
}

const mod = Process.enumerateModules().find(m => m.name.toLowerCase().includes('atomcode'));
if (!mod) { send({type: 'fatal', msg: 'atomcode module not found'}); }
else {
    send({type: 'info', msg: 'module ' + mod.name + ' base=0x' + mod.base.toString(16)});

    // ① M 就绪 —— 阶段 1
    // 实证：0x450554 `mov [rsp+0x70], rdx`（rdx=[rsp+0x108]=M 堆指针），
    //       [rsp+0x100]=97(len), [rsp+0x108]=ptr, [rsp+0x110]=cap
    Interceptor.attach(mod.base.add(RVA_M_READY), {
        onEnter() {
            const rsp = this.context.rsp;
            send({type: 'phase', phase: 'M_ready', rsp: rsp.toString()});
            try {
                const p = rsp.add(0x70).readPointer();
                const n = rsp.add(0x100).readPointer().toInt32();
                send({type: 'M_meta', ptr: p.toString(), len: n});
                dumpPtr(p, n, 'M_bytes');
            } catch (e) { send({type: 'mem_err', tag: 'M_bytes', msg: e.toString()}); }
            dumpStackWin(rsp, 0x60, 0x130, 'stack_M_ready');
            phase = 1;
        }
    });

    // ② new_from_slice —— HMAC1 key=M / HMAC2 key=OKM；rdx 指向栈上 (ptr,len) 结构
    Interceptor.attach(mod.base.add(RVA_NEW_KEY), {
        onEnter() {
            const n = ++nNewKey;
            const ctx = this.context;
            send({type: 'new_from_slice', n: n, out: ctx.rcx.toString(),
                  rdx: ctx.rdx.toString()});
            dumpPtr(ctx.rdx, 32, 'nk_struct#' + n);   // 原始结构体，离线解析
        }
    });

    // ③ OKM 完成 —— 阶段 3
    Interceptor.attach(mod.base.add(RVA_OKM_DONE), {
        onEnter() {
            const rsp = this.context.rsp;
            send({type: 'phase', phase: 'OKM_done'});
            dumpPtr(rsp.add(0x440), 32, 'OKM');
            phase = 3;
        }
    });

    // ④ update —— 仅 phase 3（HMAC2 canonical 分片，按序拼接即规范串）
    Interceptor.attach(mod.base.add(RVA_UPDATE), {
        onEnter() {
            if (phase !== 3) return;
            const n = ++nUpdate;
            if (n > MAX_UPDATE) return;
            const ctx = this.context;
            const len = ctx.r8.toInt32();
            send({type: 'update', n: n, self: ctx.rcx.toString(),
                  ptr: ctx.rdx.toString(), len: len});
            dumpPtr(ctx.rdx, Math.min(len, 512), 'upd#' + n);
        }
    });

    // ⑤ hex-encode A —— phase3 内：hex64#1=body 相关 hex，hex64#2=最终签名
    Interceptor.attach(mod.base.add(RVA_HEX64), {
        onEnter(args) {
            if (phase !== 3) return;
            this.out = args[0];
            this.data = args[1];
            this.len = args[2].toInt32();
        },
        onLeave() {
            if (!this.out) return;
            const n = ++nHex64;
            if (n > MAX_HEXENC) return;
            send({type: 'hex64', n: n, out: this.out.toString(),
                  data: this.data.toString(), len: this.len});
            try { dumpPtr(this.data, Math.min(this.len, 512), 'hex64#' + n + '.in'); } catch (e) {}
            for (const off of [0, 8, 16, 24]) {
                try {
                    const v = this.out.add(off).readPointer();
                    if (!v.isNull()) dumpPtr(v, 96, 'hex64#' + n + '.out+' + off);
                } catch (e) {}
            }
        }
    });

    // ⑥ hex-encode B —— nonce(16B)
    Interceptor.attach(mod.base.add(RVA_HEX16), {
        onEnter(args) {
            if (phase !== 3) return;
            this.out = args[0];
            this.data = args[1];
            this.len = args[2].toInt32();
        },
        onLeave() {
            if (!this.out) return;
            const n = ++nHex16;
            if (n > MAX_HEXENC) return;
            send({type: 'hex16', n: n, out: this.out.toString(),
                  data: this.data.toString(), len: this.len});
            try { dumpPtr(this.data, Math.min(this.len, 512), 'hex16#' + n + '.in'); } catch (e) {}
            for (const off of [0, 8, 16, 24]) {
                try {
                    const v = this.out.add(off).readPointer();
                    if (!v.isNull()) dumpPtr(v, 64, 'hex16#' + n + '.out+' + off);
                } catch (e) {}
            }
        }
    });

    send({type: 'ready', msg: 'hooks installed'});
}
"""


def on_message(message, data):
    if message["type"] == "send":
        p = message["payload"]
        t = p.get("type")
        if t == "mem":
            print(f"\n### MEM [{p['tag']}] ptr={p['ptr']} len={p['len']}")
            print(f"  hex  : {p['hex']}")
            print(f"  ascii: {p['ascii']}")
        elif t == "mem_err":
            print(f"### MEM_ERR [{p['tag']}] {p.get('ptr', '')} {p['msg']}")
        elif t == "stack":
            print(f"### STACK [{p['tag']}]")
            for ln in p["lines"]:
                print(ln)
        else:
            print(json.dumps(p, ensure_ascii=False))
        sys.stdout.flush()
    elif message["type"] == "error":
        print(f"[JS-ERROR] {message.get('description', message)}")
        sys.stdout.flush()


def main():
    print(f"[*] spawning: {EXE}")
    print(f"[*] args: {ARGS}")
    env = dict(os.environ)
    pid = frida.spawn([EXE] + ARGS, env=env, cwd=CWD, stdio="pipe")
    print(f"[*] spawned pid={pid}")
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    print("[*] hooks loaded, resuming ...")
    frida.resume(pid)

    deadline = time.time() + WAIT_SECONDS
    try:
        while time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    print("[*] wait over, detaching ...")
    try:
        session.detach()
    except Exception:
        pass
    try:
        frida.kill(pid)
    except Exception:
        pass
    print("[*] done")


if __name__ == "__main__":
    main()
