import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from dump_key_region import BIN, parse_pe
data = open(BIN,'rb').read()
image_base, secs = parse_pe(data)
tname, tvsize, tvaddr, toff, tsize = next(s for s in secs if s[0]=='.text')
TL, TH = image_base+tvaddr, image_base+tvaddr+tsize
def off_of(rva):
    for name, vsize, vaddr, rawptr, rawsize in secs:
        if vaddr <= rva < vaddr+vsize: return rawptr + (rva-vaddr)
    return None
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True; md.skipdata=True

print('=== hexdump 0x140f08c80..0x140f08cf0 ===')
o = off_of(0x140f08c80-image_base)
for i in range(0, 0x70, 16):
    row = data[o+i:o+i+16]
    print(f'  {0x140f08c80+i:#x}: {row.hex(" ")}  {"".join(chr(b) if 32<=b<127 else "." for b in row)}')

def dis(lo, hi, title):
    print(f'\n=== {title} ===')
    a = toff + (lo-image_base-tvaddr); b = toff + (hi-image_base-tvaddr)
    for ins in md.disasm(data[a:b], lo):
        note=''
        m = re.search(r'\[rip\s*([+-])\s*0x([0-9a-f]+)\]', ins.op_str)
        if m:
            d = int(m.group(2),16); d = -d if m.group(1)=='-' else d
            t = ins.address+ins.size+d; trva = t-image_base
            nm, oo = None, None
            for n2,v2,va2,rp2,rs2 in secs:
                if va2 <= trva < va2+v2: nm, oo = n2, rp2+(trva-va2); break
            if oo is not None:
                txt = ''.join(chr(b) if 32<=b<127 else '.' for b in data[oo:oo+56])
                if txt.strip('.'): note = f"  ; {nm} '{txt[:48]}' @ {t:#x}"
        print(f'  {ins.address:#x}: {ins.mnemonic:<9}{ins.op_str}{note}')
dis(0x140e82c60, 0x140e82d20, 'force/get_or_init @0x140e82c60 (contains call [rsi+0x20])')
dis(0x140566fc0, 0x140566ff0, 'descriptor slot +0x18 = 0x140566fd2')

print('\n=== xrefs to header strings ===')
for s in [b'X-AtomCode-Sig\x00', b'X-AtomCode-Ts\x00', b'X-AtomCode-Nonce\x00',
          b'X-AtomCode-Alg\x00', b'X-AtomCode-Ver\x00', b'atomcode-signing-v1\x00']:
    idx = data.find(s)
    if idx < 0: print(f'  {s!r}: NOT FOUND'); continue
    # file offset -> rva
    rva = None
    for name, vsize, vaddr, rawptr, rawsize in secs:
        if rawptr <= idx < rawptr+rawsize: rva = vaddr + (idx-rawptr); break
    va = image_base + rva
    print(f'  {s[:-1].decode()!r:22s} @ {va:#x} rva={rva:#x}')
    hits = 0
    a = toff; b = toff+tsize
    for ins in md.disasm(data[a:b], TL):
        if ins.mnemonic != 'lea': continue
        m = re.search(r'\[rip\s*([+-])\s*0x([0-9a-f]+)\]', ins.op_str)
        if not m: continue
        d = int(m.group(2),16); d = -d if m.group(1)=='-' else d
        if ins.address+ins.size+d == va:
            print(f'      lea @ {ins.address:#x}  {ins.op_str}')
            hits += 1
            if hits > 6: break
