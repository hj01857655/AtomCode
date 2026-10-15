#!/usr/bin/env python3
"""hook_sign2.py — frida spawn 模式抓取 atomcode.exe 签名密钥与消息构造。

崩溃史教训：JS 里 mod.base.add() 必须传 RVA（VA - 0x140000000），传完整 VA 会
落到未映射地址直接 AV。所有 hook 地址统一用 RVA。

静态反汇编已还原的算法骨架（v5.2.3 sign_v1）：
  1. 构造消息 Vec M
  2. HmacSha256::new_from_slice(M) @0x140566c89 —— HMAC1 以 M 为 key
  3. hmac.update(静态cell@0x14292f570, 32B) @0x140566cd5 —— data = 静态 32B
  4. 手写 ipad(0x36)/opad(0x6a) key schedule + 两次 sha256 @0x14027a02b
  5. HKDF-Expand(info="atomcode-signing-v1", 19B) → OKM 32B @rsp+0x440
  6. HmacSha256::new_from_slice(OKM) —— HMAC2 以派生密钥为 key
  7. hmac.update("v1" + method + ...) —— data = 规范请求串
  8. 输出 hex(hmac2) = 64 字符签名

本脚本 hook 六个点，全部用 RVA：
  A 0x566c89  new_from_slice —— dump key ptr/len/内容（两段 HMAC 的 key）
  B 0x566cd5  update         —— dump data ptr/len/内容（全部消息块，含顺序）
  C 0x450602  ipad loop 后   —— dump rsp+0x2c0 64B（ipad 块，^0x36 还原 key）
  D 0x450679  opad call      —— dump rdx 64B（opad 块）
  E 0x4508a8  HKDF 完成后    —— dump rsp+0x440 32B（派生签名密钥 OKM）
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
WAIT_SECONDS = 150

MAX_EVENTS_PER_HOOK = 60

JS = r"""
const RVA_CELL_LOADED   = 0x450591;   // lea rdx,[rip+..]->0x14292f570 之后：rdx=静态cell指针
const RVA_NEW_FROM_SLICE = 0x45059a;   // call new_from_slice 前：rcx=out, rdx=key, r8=32
const RVA_AFTER_IPAD     = 0x450607;   // ipad 循环结束后：rsp+0x2c0 = ipad 块(64B)
const RVA_OPAD_CALL      = 0x450686;   // opad 的 call：rdx = opad 块(64B)
const RVA_AFTER_HKDF     = 0x4508a8;   // HKDF-Expand 完成：rsp+0x440 = OKM(32B)

const CAP = %(cap)d;
const counts = {};
function allow(name) {
    counts[name] = (counts[name] || 0) + 1;
    return counts[name] <= CAP;
}

const dumpMem = function(ptr, len, tag) {
    try {
        len = Math.min(len, 512);
        const ab = ptr.readByteArray(len);
        const arr = new Uint8Array(ab);
        let hex = '';
        let ascii = '';
        for (let i = 0; i < arr.length; i++) {
            hex += arr[i].toString(16).padStart(2, '0') + (i %% 16 === 15 ? '\n' : ' ');
            ascii += (arr[i] >= 32 && arr[i] < 127) ? String.fromCharCode(arr[i]) : '.';
            if (i %% 16 === 15) { ascii += '\n'; }
        }
        send({type: 'dump', tag: tag, len: len, ptr: ptr.toString(), hex: hex, ascii: ascii});
    } catch (e) {
        send({type: 'dump_error', tag: tag, ptr: ptr.toString(), msg: e.toString()});
    }
}

const mod = Process.enumerateModules().find(m => m.name.toLowerCase().includes('atomcode'));
if (!mod) { send({type: 'fatal', msg: 'atomcode module not found'}); }
else {
    send({type: 'info', msg: 'module ' + mod.name + ' base=0x' + mod.base.toString(16) +
          ' size=0x' + mod.size.toString(16)});

    // A: 静态 cell 已加载 —— 该 cell 运行时填充，dump 出真正密钥
    const aAddr = mod.base.add(RVA_CELL_LOADED);
    Interceptor.attach(aAddr, {
        onEnter(args) {
            if (!allow('cell_loaded')) return;
            const ctx = this.context;
            send({type: 'cell_loaded', rdx: ctx.rdx.toString()});
            dumpMem(ctx.rdx, 32, 'static_cell.runtime_value');
        }
    });

    // B: new_from_slice 前 —— 实际传入的 HMAC key
    const bAddr = mod.base.add(RVA_NEW_FROM_SLICE);
    Interceptor.attach(bAddr, {
        onEnter(args) {
            if (!allow('new_from_slice')) return;
            const ctx = this.context;
            const len = ctx.r8.toInt32();
            send({type: 'new_from_slice', out: ctx.rcx.toString(),
                  key_ptr: ctx.rdx.toString(), key_len: len});
            dumpMem(ctx.rdx, Math.min(len, 64), 'new_from_slice.key');
        }
    });

    // C: ipad 循环后 —— rsp+0x2c0
    const cAddr = mod.base.add(RVA_AFTER_IPAD);
    Interceptor.attach(cAddr, {
        onEnter(args) {
            if (!allow('ipad')) return;
            const rsp = this.context.rsp;
            send({type: 'ipad_block', rsp: rsp.toString()});
            dumpMem(rsp.add(0x2c0), 64, 'ipad_block(key^0x36)');
        }
    });

    // D: opad call —— rdx 指向 opad 块
    const dAddr = mod.base.add(RVA_OPAD_CALL);
    Interceptor.attach(dAddr, {
        onEnter(args) {
            if (!allow('opad')) return;
            send({type: 'opad_call', rdx: this.context.rdx.toString()});
            dumpMem(this.context.rdx, 64, 'opad_block(key^0x6a)');
        }
    });

    // E: HKDF 完成后 —— rsp+0x440 = OKM
    const eAddr = mod.base.add(RVA_AFTER_HKDF);
    Interceptor.attach(eAddr, {
        onEnter(args) {
            if (!allow('okm')) return;
            const rsp = this.context.rsp;
            send({type: 'okm', rsp: rsp.toString()});
            dumpMem(rsp.add(0x440), 32, 'okm(derived_key)');
        }
    });

    send({type: 'ready', msg: 'hooks installed: ' + JSON.stringify(counts)});
}
""" % {"cap": MAX_EVENTS_PER_HOOK}


def on_message(message, data):
    if message["type"] == "send":
        p = message["payload"]
        if p.get("type") == "dump":
            print(f"\n### DUMP [{p['tag']}] ptr={p['ptr']} len={p['len']}")
            print(p["hex"])
            print("ascii:")
            print(p["ascii"])
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
    print("[*] wait window over, detaching ...")
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
