#!/usr/bin/env python3
"""capture_compress.py — 钩 SHA-256 compress(0x27a02b) + update(0x566cd5)，回放 sign_v1 哈希输入序列。

不再猜 ABI：compress 每次调用 dump (state_in 32B @rcx, block 64B @rdx, state_out @rcx onLeave)；
update dump (self @rcx, data @rdx, len @r8)。配合 M_ready/OKM_done 标记，离线即可重建：
  hasher1 被喂了什么 → D 的原像；HMAC1 消息块；expand 块（info||0x01）→ OKM 公式。
"""
import os
import sys
import time

import frida

EXE = (r"C:\Users\12925\AppData\Roaming\npm\node_modules\@atomgit.com\atomcode"
       r"\node_modules\@atomgit.com\atomcode-win32-x64\bin\atomcode.exe")
ARGS = ["-p", "say OK", "--no-tools", "--provider", "AtomGit-qwen3.8-27b"]
CWD = r"C:\Users\12925"
WAIT = 90

JS = r"""
const RVA_COMPRESS = 0x27a02b;  // sha256 compress(rcx=state, rdx=block, r8=nblocks)
const RVA_UPDATE   = 0x566cd5;  // update(rcx=self, rdx=data, r8=len)
const RVA_F1       = 0x566b4b;  // call@0x140450559: rcx=buf, rdx=M.ptr, r8=M.len
const RVA_F2       = 0x566576;  // call@0x1404505e8: rcx=buf, rdx=fin, r8=0x20
const RVA_F3       = 0x566e17;  // call@0x1404505bf/0x140450842
const RVA_F4       = 0x566f1b;  // finalize?(rcx=out, rdx=self)
const RVA_M_READY  = 0x45058a;
const RVA_OKM_DONE = 0x4508a8;

const MAX_COMPRESS = 4000, MAX_UPDATE = 800, MAX_F = 100;
let nComp = 0, nUpd = 0, nF1 = 0, nF2 = 0, nF3 = 0, nF4 = 0;

function hexs(p, len) {
    try {
        const ab = new Uint8Array(p.readByteArray(len));
        let s = '';
        for (let i = 0; i < ab.length; i++) s += ab[i].toString(16).padStart(2, '0');
        return s;
    } catch (e) { return 'ERR:' + e.toString(); }
}

const mod = Process.enumerateModules().find(m => m.name.toLowerCase().includes('atomcode'));
if (!mod) send({type: 'fatal', msg: 'module not found'});
else {
    const B = mod.base;
    send({type: 'info', msg: 'base=0x' + B.toString(16)});

    Interceptor.attach(B.add(RVA_M_READY), {onEnter() {
        send({type: 'mark', mark: 'M_READY'});
    }});
    Interceptor.attach(B.add(RVA_OKM_DONE), {onEnter() {
        send({type: 'mark', mark: 'OKM_DONE'});
    }});

    Interceptor.attach(B.add(RVA_COMPRESS), {
        onEnter() {
            if (nComp >= MAX_COMPRESS) return;
            const n = ++nComp;
            send({type: 'comp_in', n: n,
                  state: hexs(this.context.rcx, 32),
                  block: hexs(this.context.rdx, 64)});
        },
        onLeave() {
            if (nComp === 0 || nComp > MAX_COMPRESS) return;
            send({type: 'comp_out', n: nComp});
        }
    });

    Interceptor.attach(B.add(RVA_UPDATE), {
        onEnter() {
            if (nUpd >= MAX_UPDATE) return;
            const n = ++nUpd;
            const c = this.context;
            const len = c.r8.toInt32();
            send({type: 'upd', n: n, self: c.rcx.toString(), len: len,
                  data: hexs(c.rdx, Math.min(len, 160))});
        }
    });

    Interceptor.attach(B.add(RVA_F1), {
        onEnter() {
            if (nF1 >= MAX_F) return;
            const n = ++nF1;
            const c = this.context;
            send({type: 'F1', n: n, rcx: c.rcx.toString(),
                  rdx: c.rdx.toString(), r8: c.r8.toInt32(),
                  in_buf: hexs(c.rcx, 64)});
            this.rcx = c.rcx;
        },
        onLeave() {
            if (this.rcx) send({type: 'F1_out', n: nF1, buf: hexs(this.rcx, 64)});
        }
    });

    Interceptor.attach(B.add(RVA_F2), {
        onEnter() {
            if (nF2 >= MAX_F) return;
            const n = ++nF2;
            const c = this.context;
            send({type: 'F2', n: n, rcx: c.rcx.toString(), r8: c.r8.toInt32(),
                  src: hexs(c.rdx, 32)});
            this.rcx = c.rcx;
        },
        onLeave() {
            if (this.rcx) send({type: 'F2_out', n: nF2, buf: hexs(this.rcx, 64)});
        }
    });

    Interceptor.attach(B.add(RVA_F3), {
        onEnter() {
            if (nF3 >= MAX_F) return;
            const n = ++nF3;
            const c = this.context;
            send({type: 'F3', n: n, rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                  at_rcx: hexs(c.rcx, 40)});
        }
    });

    Interceptor.attach(B.add(RVA_F4), {
        onEnter() {
            if (nF4 >= MAX_F) return;
            const n = ++nF4;
            const c = this.context;
            send({type: 'F4', n: n, rcx: c.rcx.toString(), rdx: c.rdx.toString(),
                  self: hexs(c.rdx, 104)});
            this.rcx = c.rcx;
        },
        onLeave() {
            if (this.rcx) send({type: 'F4_out', n: nF4, out: hexs(this.rcx, 32)});
        }
    });

    send({type: 'ready'});
}
"""


def on_message(message, data):
    if message["type"] == "send":
        import json
        print(json.dumps(message["payload"], ensure_ascii=False))
        sys.stdout.flush()
    elif message["type"] == "error":
        print(f"[JS-ERROR] {message.get('description', message)}")
        sys.stdout.flush()


def main():
    print(f"[*] spawn {EXE} {ARGS}")
    pid = frida.spawn([EXE] + ARGS, env=dict(os.environ), cwd=CWD, stdio="pipe")
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
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
