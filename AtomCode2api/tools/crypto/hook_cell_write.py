#!/usr/bin/env python3
"""hook_cell_write.py — 用 MemoryAccessMonitor 抓静态密钥 cell 的首次写入。

静态分析结论：
  - cell VA 0x14292f570（RVA 0x292f570）无任何直接 store 指令
  - 0x140450d99 是它的 LazyLock init：把 cell 指针打包，
    mov qword [rsp+0x20], 0x14135ae90（闭包对象）后
    call 0x140e82c60 = OnceCell::get_or_init
  - 因此密钥由闭包在运行时计算，需动态抓写入者

本脚本 attach 到一个已跑起来的 atomcode 进程，对该 cell 下读/写监控，
首次写入时 dump 写入值 + Thread.backtrace，反推填充函数。
"""
import json
import sys
import time

import frida

CELL_RVA = 0x292f570
CELL_LEN = 32
WAIT_SECONDS = 90

JS = r"""
const CELL_RVA = 0x%(cell_rva)x;
const CELL_LEN = %(cell_len)d;

const mod = Process.enumerateModules().find(m => m.name.toLowerCase().includes('atomcode'));
if (!mod) { send({type: 'fatal', msg: 'atomcode module not found'}); }
else {
    const cell = mod.base.add(CELL_RVA);
    send({type: 'info', msg: 'cell @ 0x' + cell.toString(16)});

    MemoryAccessMonitor.enable([{base: cell, size: CELL_LEN}], {
        onAccess(details) {
            const op = details.operation;
            send({type: 'access', op: op, from: details.from.toString(),
                  address: details.address.toString(),
                  parts: details.parts ? details.parts.join(',') : ''});
            if (op === 'write') {
                send({type: 'WRITE_VALUE',
                      hex: cell.readByteArray(CELL_LEN) ?
                           Array.from(new Uint8Array(cell.readByteArray(CELL_LEN)))
                               .map(b => b.toString(16).padStart(2, '0')).join('') : '?'});
                send({type: 'BACKTRACE', trace: Thread.backtrace(details.contextBacktrace)
                    .map(a => a.sub(mod.base).toString(16)).join(' <- ')});
            }
        }
    });
    send({type: 'ready', msg: 'memory monitor armed on cell'});
}
"""


def on_message(message, data):
    if message["type"] == "send":
        print(json.dumps(message["payload"], ensure_ascii=False))
        sys.stdout.flush()
    elif message["type"] == "error":
        print(f"[JS-ERROR] {message.get('description', message)}")
        sys.stdout.flush()


def main():
    print("[*] enumerating atomcode processes ...")
    try:
        procs = [p for p in frida.enumerate_processes() if "atomcode" in p.name.lower()]
    except Exception as e:
        print(f"[!] enumerate failed: {e}")
        return 1
    if not procs:
        print("[!] no atomcode.exe running — start one first (e.g. `atomcode -p hi`)")
        return 1
    target = procs[0]
    print(f"[*] attaching to pid={target.pid} name={target.name}")
    session = frida.attach(target.pid)
    script = session.create_script(JS % {"cell_rva": CELL_RVA, "cell_len": CELL_LEN})
    script.on("message", on_message)
    script.load()
    print(f"[*] armed, watching {WAIT_SECONDS}s ...")
    deadline = time.time() + WAIT_SECONDS
    try:
        while time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    print("[*] done, detaching")
    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
