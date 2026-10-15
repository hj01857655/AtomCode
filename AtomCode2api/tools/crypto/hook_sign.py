#!/usr/bin/env python3
"""hook_sign.py — frida 动态抓取 atomcode.exe 签名密钥与消息输入。

策略：
1. attach 到运行中的 atomcode.exe
2. 读 LazyLock 密钥 @ module_base + 0x292f570（32B）
3. hook 签名函数入口 0x140450400，dump 所有寄存器参数
4. hook 密钥加载点 0x14045059a，确认运行时密钥值
5. hook 签名函数返回处，dump 输出（64hex 签名）
"""
import json
import sys

import frida

KEY_RVA = 0x292f570          # LazyLock 密钥指针 (RVA)
KEY_LOAD_RVA = 0x450591      # mov r8d,0x20 — call前安全点，rdx=密钥ptr (RVA, VA=0x140450591)

JS = r"""
'use strict';

const KEY_RVA = %(key_rva)d;
const KEY_LOAD_RVA = %(key_load_rva)d;

const mod = Process.enumerateModules().find(m => m.name.toLowerCase().includes('atomcode'));
if (!mod) { send({type: 'error', msg: 'atomcode module not found'}); }
else {
    send({type: 'info', msg: 'module: ' + mod.name + ' base=0x' + mod.base.toString(16)});

    const keyAddr = mod.base.add(KEY_RVA);
    send({type: 'info', msg: 'LazyLock addr: 0x' + keyAddr.toString(16)});

    // 1. 读 LazyLock 头：前8字节是指针，指向真正的密钥
    try {
        const ptr = keyAddr.readPointer();
        send({type: 'lazylock_ptr', ptr: ptr.toString()});
        if (!ptr.isNull()) {
            try {
                const kb = ptr.readByteArray(64);
                const arr = new Uint8Array(kb);
                const hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
                send({type: 'key_at_ptr', hex: hex, addr: ptr.toString()});
            } catch(e) {
                send({type: 'key_at_ptr_error', msg: e.toString()});
            }
        }
    } catch(e) {
        send({type: 'lazylock_error', msg: e.toString()});
    }

    // 2. Hook 密钥加载点 0x14045059a：call 0x140566cd5(rcx, rdx=密钥ptr, r8=32)
    //    在 call 之前 rdx 已经是指向 32 字节密钥的指针（HmacSha256::new_from_slice 之前）
    const keyLoad = mod.base.add(0x14045059a);
    Interceptor.attach(keyLoad, {
        onEnter(args) {
            const ctx = this.context;
            const keyPtr = ctx.rdx;
            const keyLen = ctx.r8.toInt32();
            send({type: 'key_load_hit', ptr: keyPtr.toString(), len: keyLen,
                  rcx: ctx.rcx.toString()});
            try {
                const kb = keyPtr.readByteArray(Math.min(keyLen, 64));
                const arr = new Uint8Array(kb);
                const hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
                send({type: 'key_actual', hex: hex, len: keyLen});
            } catch(e) {
                send({type: 'key_actual_error', msg: e.toString()});
            }
        }
    });
    send({type: 'info', msg: 'hooked key_load @ 0x' + keyLoad.toString(16)});
}
""" % {"key_rva": KEY_RVA, "key_load_rva": KEY_LOAD_RVA}


def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        sys.stdout.flush()
    elif message["type"] == "error":
        print(f"[ERROR] {message.get('stack', message)}")
        sys.stdout.flush()


def main():
    print("[*] attaching to atomcode.exe ...")
    session = frida.attach("atomcode.exe")
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    print("[*] hooks installed. waiting for events (Ctrl+C to stop) ...")
    print("[*] now trigger a signed request in atomcode (send a message) ...")
    try:
        import time
        for _ in range(120):  # wait up to 120s
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] detaching ...")
        session.detach()


if __name__ == "__main__":
    main()
