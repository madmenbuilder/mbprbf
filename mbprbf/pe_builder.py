
"""
pe_builder.py - низкоуровневая PE-генерация для Windows x64.

Поддерживает GUI (IMAGE_SUBSYSTEM_WINDOWS_GUI) и CUI (IMAGE_SUBSYSTEM_WINDOWS_CUI).
Поддерживает .rsrc секцию с манифестом (RT_MANIFEST).

Экспортирует:
  build_pe(out_path, text_bytes, rdata_bytes, data_bytes, entry_rva,
           import_dir_rva, import_dir_size, iat_rva, iat_size,
           rsrc_bytes=None, rsrc_rva=None, subsystem=...)
  RdataBuilder(rdata_rva, imports)
  RsrcBuilder(rsrc_rva)
  align_up, u8, u16, u32, u64
"""

import struct
import time
from .version import LINKER_MAJOR, LINKER_MINOR

IMAGE_BASE     = 0x140000000
SECTION_ALIGN  = 0x1000
FILE_ALIGN     = 0x200
STACK_RESERVE  = 0x100000
STACK_COMMIT   = 0x1000
HEAP_RESERVE   = 0x100000
HEAP_COMMIT    = 0x1000

IMAGE_FILE_MACHINE_AMD64       = 0x8664
IMAGE_FILE_RELOCS_STRIPPED     = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE    = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040

IMAGE_SCN_CNT_CODE             = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE          = 0x20000000
IMAGE_SCN_MEM_READ             = 0x40000000
IMAGE_SCN_MEM_WRITE            = 0x80000000

IMAGE_DIRECTORY_ENTRY_RESOURCE = 2

def align_up(v, a):
    return (v + a - 1) & ~(a - 1)

def u8(x):  return struct.pack("<B", x)
def u16(x): return struct.pack("<H", x)
def u32(x): return struct.pack("<I", x)
def u64(x): return struct.pack("<Q", x)

def build_dos_header(pe_offset):
    h  = b"MZ"
    h += u16(0x90) + u16(0x03) + u16(0x00) + u16(0x04)
    h += u16(0x00) + u16(0xFFFF) + u16(0x00) + u16(0xB8)
    h += u16(0x00) + u16(0x00) + u16(0x00) + u16(0x40)
    h += u16(0x00)
    h += b"\x00" * 8
    h += u16(0x00) + u16(0x00)
    h += b"\x00" * 20
    h += u32(pe_offset)
    assert len(h) == 64
    return h

DOS_STUB = bytes([
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
    0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
]) + b"This program cannot be run in DOS mode.\r\r\n$"

def build_coff_header(num_sections, timestamp=None):
    if timestamp is None:
        timestamp = int(time.time())
    h  = b"PE\x00\x00"
    h += u16(IMAGE_FILE_MACHINE_AMD64)
    h += u16(num_sections)
    h += u32(timestamp & 0xFFFFFFFF)
    h += u32(0)
    h += u32(0)
    h += u16(0x00F0)
    h += u16(IMAGE_FILE_EXECUTABLE_IMAGE |
             IMAGE_FILE_LARGE_ADDRESS_AWARE)
    return h

def build_optional_header(entry_rva, text_rva, text_size,
                          rdata_rva, rdata_size,
                          data_rva, data_size,
                          size_of_image, size_of_headers,
                          import_dir_rva, import_dir_size,
                          iat_rva, iat_size,
                          rsrc_rva=0, rsrc_size=0,
                          reloc_rva=0, reloc_size=0,
                          pdata_rva=0, pdata_size=0,
                          subsystem=IMAGE_SUBSYSTEM_WINDOWS_GUI):
    h  = u16(0x020B)
    h += u8(LINKER_MAJOR)     
    h += u8(LINKER_MINOR)
    h += u32(text_size)
    h += u32(rdata_size + data_size)
    h += u32(0)
    h += u32(entry_rva)
    h += u32(text_rva)
    h += u64(IMAGE_BASE)
    h += u32(SECTION_ALIGN)
    h += u32(FILE_ALIGN)
    h += u16(6) + u16(0)
    h += u16(0) + u16(0)
    h += u16(6) + u16(1)
    h += u32(0)
    h += u32(size_of_image)
    h += u32(size_of_headers)
    h += u32(0)
    h += u16(subsystem)
    h += u16(IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
             IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    h += u64(STACK_RESERVE)
    h += u64(STACK_COMMIT)
    h += u64(HEAP_RESERVE)
    h += u64(HEAP_COMMIT)
    h += u32(0)
    h += u32(16)
    h += u32(0) + u32(0)
    h += u32(import_dir_rva) + u32(import_dir_size)
    h += u32(rsrc_rva) + u32(rsrc_size)
    h += u32(pdata_rva) + u32(pdata_size)
    h += u32(0) + u32(0)
    h += u32(reloc_rva) + u32(reloc_size)
    for _ in range(6):
        h += u32(0) + u32(0)
    h += u32(iat_rva) + u32(iat_size)
    for _ in range(3):
        h += u32(0) + u32(0)
    assert len(h) == 240
    return h

def build_section(name, virt_size, virt_addr, raw_size, raw_ptr, characteristics):
    h  = name.encode("ascii") + b"\x00" * (8 - len(name))
    h += u32(virt_size)
    h += u32(virt_addr)
    h += u32(raw_size)
    h += u32(raw_ptr)
    h += u32(0) + u32(0)
    h += u16(0) + u16(0)
    h += u32(characteristics)
    assert len(h) == 40
    return h

def build_reloc_section(relocs):
    """relocs: [(rva, type), ...] где type = IMAGE_REL_BASED_DIR64 = 10.
       Возвращает bytes секции .reloc."""
    if not relocs:
        return b""

    pages = {}
    for rva, typ in relocs:
        page = rva & ~0xFFF
        offset = rva & 0xFFF
        pages.setdefault(page, []).append((offset, typ))

    blob = bytearray()
    for page in sorted(pages):
        entries = pages[page]
        size = 8 + len(entries) * 2
        size_aligned = (size + 3) & ~3  
        blob += u32(page)
        blob += u32(size_aligned)
        for offset, typ in entries:
            blob += u16((typ << 12) | (offset & 0xFFF))
        blob += b"\x00" * (size_aligned - size)
    return bytes(blob)

class RdataBuilder:
    def __init__(self, rdata_rva, imports):
        self.rdata_rva = rdata_rva
        self.imports = imports
        self.string_blobs = []
        self.strings_start = 0
        self._rvas = {}
        self._compute_iat()

    def _compute_iat(self):
        num_dlls = len(self.imports)
        total_funcs = sum(len(f) for _, f in self.imports)

        self.idt_rva  = self.rdata_rva
        self.idt_size = (num_dlls + 1) * 20
        self.ilt_rva  = self.idt_rva + self.idt_size
        self.ilt_size = (total_funcs + num_dlls) * 8
        self.iat_rva  = self.ilt_rva + self.ilt_size
        self.iat_size = self.ilt_size
        self.hint_base = self.iat_rva + self.iat_size

        self.iat = {}
        off = 0
        for _dll_name, funcs in self.imports:
            for f in funcs:
                self.iat[f] = self.iat_rva + off
                off += 8
            off += 8

        hint_size = 0
        for _dll_name, funcs in self.imports:
            for f in funcs:
                hint_size += 2 + len(f) + 1
        dll_size = sum(len(d) + 1 for d, _ in self.imports)
        self.strings_start = self.hint_base + hint_size + dll_size

    def add_string(self, name, s):
        if name in self._rvas:
            return self._rvas[name]
        rva = self.strings_start
        blob = s.encode("ascii") + b"\x00"
        self.strings_start += len(blob)
        self.string_blobs.append((rva, blob))
        self._rvas[name] = rva
        return rva

    def add_wstring(self, name, s):
        """Добавить wide-строку (UTF-16LE) в .rdata."""
        if name in self._rvas:
            return self._rvas[name]
        rva = self.strings_start
        blob = s.encode("utf-16-le") + b"\x00\x00"
        self.strings_start += len(blob)
        self.string_blobs.append((rva, blob))
        self._rvas[name] = rva
        return rva

    def get_rva(self, name):
        return self._rvas.get(name)

    def build(self):
        hint_blob = bytearray()
        hint_rva = {}
        for _dll_name, funcs in self.imports:
            for f in funcs:
                hint_rva[f] = self.hint_base + len(hint_blob)
                hint_blob += u16(0)
                hint_blob += f.encode("ascii") + b"\x00"

        dll_rvas = []
        dll_blob = bytearray()
        for dll_name, _funcs in self.imports:
            dll_rvas.append(self.hint_base + len(hint_blob) + len(dll_blob))
            dll_blob += dll_name.encode("ascii") + b"\x00"

        ilt = bytearray()
        iat = bytearray()
        for _dll_name, funcs in self.imports:
            for f in funcs:
                ilt += u64(hint_rva[f])
                iat += u64(hint_rva[f])
            ilt += u64(0)
            iat += u64(0)

        idt = bytearray()
        ilt_off = 0
        for dll_idx, (_dll_name, funcs) in enumerate(self.imports):
            idt += u32(self.ilt_rva + ilt_off)
            idt += u32(0)
            idt += u32(0)
            idt += u32(dll_rvas[dll_idx])
            idt += u32(self.iat_rva + ilt_off)
            ilt_off += (len(funcs) + 1) * 8
        idt += b"\x00" * 20

        data = bytearray()
        data += idt
        data += ilt
        data += iat
        data += hint_blob
        data += dll_blob
        for _rva, blob in self.string_blobs:
            data += blob

        return bytes(data), self.idt_rva, self.idt_size, self.iat_rva, self.iat_size

class RsrcBuilder:
    """Сборка .rsrc секции. Универсальный builder дерева ресурсов.

    Ресурсы: список (type_id, name_id, lang_id, data_bytes).
      type_id  — 3 (RT_ICON), 14 (RT_GROUP_ICON), 16 (RT_VERSION), 24 (RT_MANIFEST)
      name_id  — ID ресурса внутри типа (1, 2, ...)
      lang_id  — 0x0409 (en-US) обычно
      data_bytes — байты ресурса
    """

    def __init__(self, rsrc_rva):
        self.rsrc_rva = rsrc_rva

    def build(self, resources):
        """resources: list of (type_id, name_id, lang_id, data_bytes).
           Возвращает bytes секции .rsrc."""

        tree = {}
        for typ, name, lang, data in resources:
            tree.setdefault(typ, {}).setdefault(name, {})[lang] = data

        type_dirs = sorted(tree.keys())

        dir_root_size = 16 + 8 * len(type_dirs)
        off_type_dir = {}
        cur = dir_root_size
        for typ in type_dirs:
            off_type_dir[typ] = cur
            cur += 16 + 8 * len(tree[typ])

        off_name_dir = {}
        for typ in type_dirs:
            for name in sorted(tree[typ].keys()):
                off_name_dir[(typ, name)] = cur
                cur += 16 + 8 * len(tree[typ][name])

        off_data_entry = {}
        for typ in type_dirs:
            for name in sorted(tree[typ].keys()):
                for lang in sorted(tree[typ][name].keys()):
                    off_data_entry[(typ, name, lang)] = cur
                    cur += 16

        off_data = {}
        for typ in type_dirs:
            for name in sorted(tree[typ].keys()):
                for lang in sorted(tree[typ][name].keys()):
                    off_data[(typ, name, lang)] = cur
                    cur += len(tree[typ][name][lang])
                    pad = (4 - cur % 4) % 4
                    cur += pad

        blob = bytearray()

        blob += u32(0) + u32(0)
        blob += u16(0) + u16(0)
        blob += u16(0) + u16(len(type_dirs))
        for typ in type_dirs:
            blob += u32(typ)
            blob += u32(0x80000000 | off_type_dir[typ])

        for typ in type_dirs:
            names = sorted(tree[typ].keys())
            blob += u32(0) + u32(0)
            blob += u16(0) + u16(0)
            blob += u16(0) + u16(len(names))
            for name in names:
                blob += u32(name)
                blob += u32(0x80000000 | off_name_dir[(typ, name)])

        for typ in type_dirs:
            for name in sorted(tree[typ].keys()):
                langs = sorted(tree[typ][name].keys())
                blob += u32(0) + u32(0)
                blob += u16(0) + u16(0)
                blob += u16(0) + u16(len(langs))
                for lang in langs:
                    blob += u32(lang)
                    blob += u32(off_data_entry[(typ, name, lang)])

        for typ in type_dirs:
            for name in sorted(tree[typ].keys()):
                for lang in sorted(tree[typ][name].keys()):
                    data = tree[typ][name][lang]
                    data_rva = self.rsrc_rva + off_data[(typ, name, lang)]
                    blob += u32(data_rva)
                    blob += u32(len(data))
                    blob += u32(0)
                    blob += u32(0)

        for typ in type_dirs:
            for name in sorted(tree[typ].keys()):
                for lang in sorted(tree[typ][name].keys()):
                    data = tree[typ][name][lang]
                    blob += data
                    pad = (4 - len(blob) % 4) % 4
                    blob += b"\x00" * pad

        return bytes(blob)

def _align4(blob):
    return blob + b"\x00" * ((4 - len(blob) % 4) % 4)

def _wstr(s):
    return s.encode("utf-16-le") + b"\x00\x00"

def build_version_info(v):
    """v: dict с метаданными. Возвращает bytes для RT_VERSION."""

    def make_block(wValueLength, wType, szKey, value_bytes, children_bytes, abs_off):
        """abs_off — абсолютный offset блока в ресурсе (для выравнивания)."""
        key_bytes = _wstr(szKey)
        header_len = 6

        cur = abs_off + header_len + len(key_bytes)
        pad1 = (4 - cur % 4) % 4
        key_block = key_bytes + b"\x00" * pad1

        cur = abs_off + header_len + len(key_block) + len(value_bytes)
        pad2 = (4 - cur % 4) % 4
        value_block = value_bytes + b"\x00" * pad2

        body = key_block + value_block + children_bytes
        wLength = header_len + len(body)
        return u16(wLength) + u16(wValueLength) + u16(wType) + body

    def make_string(szKey, value, abs_off):
        val_bytes = _wstr(value)
        return make_block(len(val_bytes), 1, szKey, val_bytes, b"", abs_off)

    def make_string_table(lang_cp, strings, abs_off):

        header_len = 6
        key_bytes = _wstr(lang_cp)
        cur = abs_off + header_len + len(key_bytes)
        pad = (4 - cur % 4) % 4
        children_start = abs_off + header_len + len(key_bytes) + pad

        children = bytearray()
        child_off = children_start
        for k, val in strings:
            s = make_string(k, val, child_off)
            children += s
            child_off += len(s)

        body = key_bytes + b"\x00" * pad + bytes(children)
        wLength = header_len + len(body)
        return u16(wLength) + u16(0) + u16(1) + body

    def make_string_file_info(lang_cp, strings, abs_off):
        header_len = 6
        key_bytes = _wstr("StringFileInfo")
        cur = abs_off + header_len + len(key_bytes)
        pad = (4 - cur % 4) % 4
        children_start = abs_off + header_len + len(key_bytes) + pad

        child = make_string_table(lang_cp, strings, children_start)
        body = key_bytes + b"\x00" * pad + child
        wLength = header_len + len(body)
        return u16(wLength) + u16(0) + u16(1) + body

    def make_var_file_info(lang_cp, abs_off):
        header_len = 6
        key_bytes = _wstr("VarFileInfo")
        cur = abs_off + header_len + len(key_bytes)
        pad = (4 - cur % 4) % 4
        children_start = abs_off + header_len + len(key_bytes) + pad

        v_header = 6
        v_key = _wstr("Translation")
        v_cur = children_start + v_header + len(v_key)
        v_pad = (4 - v_cur % 4) % 4
        v_body = v_key + b"\x00" * v_pad + u32(lang_cp)
        v_block = u16(v_header + len(v_body)) + u16(4) + u16(0) + v_body

        body = key_bytes + b"\x00" * pad + v_block
        wLength = header_len + len(body)
        return u16(wLength) + u16(0) + u16(1) + body

    def pack_ms(t): return ((t[0] & 0xFFFF) << 16) | (t[1] & 0xFFFF)

    def pack_ls(t): return ((t[2] & 0xFFFF) << 16) | (t[3] & 0xFFFF)

    fv = v.get("file_version", (1, 0, 0, 0))
    pv = v.get("product_version", fv)
    fv_str = v.get("file_version_str", ".".join(str(x) for x in fv))
    pv_str = v.get("product_version_str", ".".join(str(x) for x in pv))

    ffi = u32(0xFEEF04BD)
    ffi += u32(0x00010000)
    ffi += u32(pack_ms(fv))
    ffi += u32(pack_ls(fv))
    ffi += u32(pack_ms(pv))
    ffi += u32(pack_ls(pv))
    ffi += u32(0)
    ffi += u32(0)
    ffi += u32(0x00040004)
    ffi += u32(0x00000001)
    ffi += u32(0)
    ffi += u32(0)
    ffi += u32(0)
    assert len(ffi) == 52

    strings = [
        ("CompanyName", v.get("company_name", "")),
        ("FileDescription", v.get("file_description", "")),
        ("FileVersion", fv_str),
        ("InternalName", v.get("internal_name", "")),
        ("LegalCopyright", v.get("legal_copyright", "")),
        ("LegalTrademarks", v.get("legal_trademarks", "")),
        ("OriginalFilename", v.get("original_filename", "")),
        ("PrivateBuild", v.get("private_build", "")),
        ("ProductName", v.get("product_name", "")),
        ("ProductVersion", pv_str),
        ("SpecialBuild", v.get("special_build", "")),
        ("Comments", v.get("comments", "")),
    ]

    abs_off = 0
    header_len = 6
    root_key = _wstr("VS_VERSION_INFO")
    cur = abs_off + header_len + len(root_key)
    pad1 = (4 - cur % 4) % 4
    cur += pad1 + len(ffi)
    pad2 = (4 - cur % 4) % 4
    children_start = abs_off + header_len + len(root_key) + pad1 + len(ffi) + pad2

    sfi = make_string_file_info("040904B0", strings, children_start)
    sfi_size = len(sfi)

    vfi = make_var_file_info(0x040904B0, children_start + sfi_size)

    root_body = root_key + b"\x00" * pad1 + ffi + b"\x00" * pad2 + sfi + vfi
    root_wlen = header_len + len(root_body)
    root = u16(root_wlen) + u16(52) + u16(0) + root_body

    return root

def make_default_version(internal_name="app",
                         original_filename="app.exe",
                         file_description="Built with MBPRBF",
                         product_name="MBPRBF Application"):
    """Дефолтные метаданные RT_VERSION для MBPRBF-приложений.

    Возвращает dict, совместимый с build_version_info.
    """
    return {
        "file_version": (1, 0, 0, 0),
        "product_version": (1, 0, 0, 0),
        "file_version_str": "1.0.0.0",
        "product_version_str": "1.0.0.0",
        "company_name": "MBPRBF",
        "file_description": file_description,
        "internal_name": internal_name,
        "legal_copyright": "Copyright (C) 2026 MBPRBF",
        "legal_trademarks": "MBPRBF",
        "original_filename": original_filename,
        "product_name": product_name,
        "private_build": "MBPRBF default",
        "special_build": "Built with MBPRBF",
        "comments": "Generated by MBPRBF",
    }

def build_seh_sections(methods, pdata_rva, xdata_rva,
                       c_specific_handler_rva):
    """Собрать .pdata и .xdata из списка методов.

    methods — список Method (с rva, end_rva, prologue_codes,
              prologue_size, unwind_info, has_seh).
    pdata_rva — RVA, где будет размещена .pdata.
    xdata_rva — RVA, где будет размещена .xdata.
    c_specific_handler_rva — RVA __C_specific_handler.

    Возвращает (pdata_bytes, xdata_bytes).
    """
    import struct as _struct
    from .seh import UnwindInfo

    pdata_blob = bytearray()
    xdata_blob = bytearray()

    print(f"[SEH] pdata_rva={pdata_rva:#x} xdata_rva={xdata_rva:#x} "
          f"csh={c_specific_handler_rva:#x}")

    all_methods = sorted(
        [m for m in methods if m.rva is not None and m.end_rva is not None],
        key=lambda m: m.rva,
    )
    print(f"[SEH] methods_with_rva = {len(all_methods)}")

    for m in all_methods:
        begin = m.rva
        end = m.end_rva

        print(f"[SEH]   {m.name}: rva={m.rva:#x} end={m.end_rva:#x} "
              f"ui={m.unwind_info is not None} has_seh={m.has_seh}")

        while len(xdata_blob) % 4 != 0:
            xdata_blob.append(0)
        ui_rva = xdata_rva + len(xdata_blob)

        if m.unwind_info is None:
            raise RuntimeError(
                f"build_seh_sections: метод {m.name} не имеет unwind_info. "
                f"Проверь end_method в methods.py."
            )
        ui = m.unwind_info
        print(f"[SEH]     flags={ui.flags:#x} "
              f"codes={len(ui.codes)} scopes={len(ui.scope_table)}")
        if m.has_seh:
            ui.handler_rva = c_specific_handler_rva
            print(f"[XData] {m.name}: handler_rva={c_specific_handler_rva:#x} "
                  f"(method rva={m.rva:#x})")
        ui_bytes = ui.pack()

        xdata_blob.extend(ui_bytes)

        pdata_blob += _struct.pack("<III", begin, end, ui_rva)

    while len(pdata_blob) % 4 != 0:
        pdata_blob.append(0)
    while len(xdata_blob) % 4 != 0:
        xdata_blob.append(0)

    print(f"[SEH] pdata_bytes={len(pdata_blob)} xdata_bytes={len(xdata_blob)}")
    return bytes(pdata_blob), bytes(xdata_blob)

def parse_ico(source):
    """Читает .ico/.png (путь или байты).
       Возвращает (list_of_icon_data, group_dir_bytes).

       list_of_icon_data — список байтов PNG для каждого RT_ICON.
       group_dir_bytes   — байты для RT_GROUP_ICON (GRPICONDIR).

       ВАЖНО: nID в GRPICONDIR — временные (1, 2, 3...).
       Их нужно перезаписать реальными ID перед добавлением в .rsrc.
    """
    from PIL import Image
    import io

    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        with open(source, "rb") as f:
            data = f.read()

    is_ico = (len(data) >= 4) and (data[:4] == b"\x00\x00\x01\x00")

    if is_ico:
        img = Image.open(io.BytesIO(data))
    else:

        img = Image.open(io.BytesIO(data))
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        buf = io.BytesIO()
        img.save(buf, format="ICO",
                 sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (256, 256)])
        buf.seek(0)
        img = Image.open(buf)

    if not hasattr(img, "ico"):
        raise ValueError(f"Не удалось получить ICO из источника")

    sizes = list(img.ico.sizes())
    icons = []
    entries = []
    for w, h in sizes:
        frame = img.ico.getimage((w, h))
        buf = io.BytesIO()
        frame.save(buf, format="PNG")
        png_data = buf.getvalue()
        icons.append(png_data)
        bw = w if w < 256 else 0
        bh = h if h < 256 else 0
        entries.append((bw, bh, 0, 0, 1, 32, len(png_data)))

    grp = bytearray()
    grp += u16(0) + u16(1) + u16(len(icons))
    for idx, (w, h, c, r, p, bpp, size) in enumerate(entries):
        grp += u8(w) + u8(h) + u8(c) + u8(r)
        grp += u16(p) + u16(bpp)
        grp += u32(size)
        grp += u16(idx + 1)   
    return icons, bytes(grp)

def rewrite_grp_nids(grp_bytes, first_icon_id):
    """Перезаписывает nID в GRPICONDIR реальными ID RT_ICON.

       grp_bytes: bytes GRPICONDIR
       first_icon_id: ID первого RT_ICON этой группы
    """
    grp = bytearray(grp_bytes)
    count = struct.unpack_from("<H", grp, 4)[0]
    for i in range(count):
        off = 6 + i * 14 + 12
        struct.pack_into("<H", grp, off, first_icon_id + i)
    return bytes(grp)

def make_default_icon():
    from PIL import Image, ImageDraw, ImageFont
    import io

    S = 256
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    RED = (200, 30, 30, 255)
    draw.rounded_rectangle([8, 8, S - 8, S - 8], radius=24, fill=RED)

    text = "MBPRBF"

    font = None
    for name in ("arialbd.ttf", "Arial Bold.ttf", "DejaVuSans-Bold.ttf",
                 "LiberationSans-Bold.ttf", "arial.ttf", "DejaVuSans.ttf"):
        try:
            font = ImageFont.truetype(name, 56)
            break
        except Exception:
            continue
    if font is None:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    x = (S - tw) // 2 - bbox[0]
    y = (S - th) // 2 - bbox[1]

    draw.text((x, y), text, fill=(255, 255, 255, 255), font=font)

    buf = io.BytesIO()
    img.save(buf, format="ICO",
             sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (256, 256)])
    return buf.getvalue()

def build_pe(out_path,
             text_bytes,
             rdata_bytes,
             data_bytes,
             entry_rva,
             import_dir_rva, import_dir_size,
             iat_rva, iat_size,
             rsrc_bytes=None, rsrc_rva=None,
             pdata_bytes=None, pdata_rva=None,
             xdata_bytes=None, xdata_rva=None,
             relocs=None, reloc_rva=None, timestamp=None,
             text_rva=0x1000, rdata_rva=0x2000, data_rva=0x3000,
             subsystem=IMAGE_SUBSYSTEM_WINDOWS_GUI):
    dos_size = 64
    stub_size = len(DOS_STUB)
    pe_offset = align_up(dos_size + stub_size, 8)

    reloc_bytes = build_reloc_section(relocs) if relocs else b""

    pe_sig_size = 4
    coff_size = 20
    opt_size = 240
    num_sections = 3
    if rsrc_bytes: num_sections += 1
    if pdata_bytes: num_sections += 1
    if xdata_bytes: num_sections += 1
    if reloc_bytes: num_sections += 1
    sect_table = 40 * num_sections
    headers_size = pe_offset + pe_sig_size + coff_size + opt_size + sect_table
    headers_padded = align_up(headers_size, FILE_ALIGN)

    text_raw = headers_padded

    text_padded = align_up(len(text_bytes), FILE_ALIGN)
    text_bytes = text_bytes + b"\x00" * (text_padded - len(text_bytes))

    rdata_padded = align_up(len(rdata_bytes), FILE_ALIGN)
    rdata_bytes = rdata_bytes + b"\x00" * (rdata_padded - len(rdata_bytes))

    data_padded = align_up(len(data_bytes), FILE_ALIGN)
    data_bytes = data_bytes + b"\x00" * (data_padded - len(data_bytes))

    rdata_raw = text_raw + text_padded
    data_raw = rdata_raw + rdata_padded

    next_rva_after = data_rva + align_up(data_padded, SECTION_ALIGN)
    next_raw_after = data_raw + data_padded

    if rsrc_bytes:
        if rsrc_rva is None:
            rsrc_rva = next_rva_after
        rsrc_padded = align_up(len(rsrc_bytes), FILE_ALIGN)
        rsrc_bytes_padded = rsrc_bytes + b"\x00" * (rsrc_padded - len(rsrc_bytes))
        rsrc_raw = next_raw_after

        next_rva_after = rsrc_rva + align_up(rsrc_padded, SECTION_ALIGN)
        next_raw_after = rsrc_raw + rsrc_padded
    else:
        rsrc_rva = 0
        rsrc_padded = 0
        rsrc_bytes_padded = b""
        rsrc_raw = 0

    if pdata_bytes:
        if pdata_rva is None:
            pdata_rva = next_rva_after
        pdata_padded = align_up(len(pdata_bytes), FILE_ALIGN)
        pdata_bytes_padded = pdata_bytes + b"\x00" * (pdata_padded - len(pdata_bytes))
        pdata_raw = next_raw_after
        next_rva_after = pdata_rva + align_up(pdata_padded, SECTION_ALIGN)
        next_raw_after = pdata_raw + pdata_padded
    else:
        pdata_rva = 0
        pdata_padded = 0
        pdata_bytes_padded = b""
        pdata_raw = 0

    if xdata_bytes:
        if xdata_rva is None:
            xdata_rva = next_rva_after
        xdata_padded = align_up(len(xdata_bytes), FILE_ALIGN)
        xdata_bytes_padded = xdata_bytes + b"\x00" * (xdata_padded - len(xdata_bytes))
        xdata_raw = next_raw_after
        next_rva_after = xdata_rva + align_up(xdata_padded, SECTION_ALIGN)
        next_raw_after = xdata_raw + xdata_padded
    else:
        xdata_rva = 0
        xdata_padded = 0
        xdata_bytes_padded = b""
        xdata_raw = 0

    if reloc_bytes:
        if reloc_rva is None:
            reloc_rva = next_rva_after
        reloc_padded = align_up(len(reloc_bytes), FILE_ALIGN)
        reloc_bytes_padded = reloc_bytes + b"\x00" * (reloc_padded - len(reloc_bytes))
        reloc_raw = next_raw_after
        size_of_image = reloc_rva + align_up(reloc_padded, SECTION_ALIGN)
    else:
        reloc_rva = 0
        reloc_padded = 0
        reloc_bytes_padded = b""
        reloc_raw = 0
        size_of_image = next_rva_after

    dos = build_dos_header(pe_offset)
    coff = build_coff_header(num_sections, timestamp=timestamp)
    opt = build_optional_header(entry_rva, text_rva, text_padded,
                                rdata_rva, rdata_padded,
                                data_rva, data_padded,
                                size_of_image, headers_padded,
                                import_dir_rva, import_dir_size,
                                iat_rva, iat_size,
                                rsrc_rva=(rsrc_rva or 0),
                                rsrc_size=rsrc_padded,
                                reloc_rva=(reloc_rva or 0),
                                reloc_size=reloc_padded,
                                pdata_rva=(pdata_rva or 0),
                                pdata_size=len(pdata_bytes) if pdata_bytes else 0,
                                subsystem=subsystem)

    text_flags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    rdata_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    data_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    rsrc_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ

    sect = build_section(".text", text_padded, text_rva, text_padded, text_raw, text_flags)
    sect += build_section(".rdata", rdata_padded, rdata_rva, rdata_padded, rdata_raw, rdata_flags)
    sect += build_section(".data", data_padded, data_rva, data_padded, data_raw, data_flags)
    if rsrc_bytes:
        sect += build_section(".rsrc", rsrc_padded, rsrc_rva, rsrc_padded, rsrc_raw, rsrc_flags)
    if pdata_bytes:
        pdata_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        sect += build_section(".pdata", pdata_padded, pdata_rva, pdata_padded, pdata_raw, pdata_flags)
    if xdata_bytes:
        xdata_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        sect += build_section(".xdata", xdata_padded, xdata_rva, xdata_padded, xdata_raw, xdata_flags)
    if reloc_bytes:
        reloc_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        sect += build_section(".reloc", reloc_padded, reloc_rva, reloc_padded, reloc_raw, reloc_flags)

    out = bytearray()
    out += dos
    out += DOS_STUB
    while len(out) < pe_offset:
        out += b"\x00"
    out += coff
    out += opt
    out += sect
    out += b"\x00" * (headers_padded - len(out))
    out += text_bytes
    out += rdata_bytes
    out += data_bytes
    if rsrc_bytes:
        out += rsrc_bytes_padded
    if pdata_bytes:
        out += pdata_bytes_padded
    if xdata_bytes:
        out += xdata_bytes_padded
    if reloc_bytes:
        out += reloc_bytes_padded

    with open(out_path, "wb") as f:
        f.write(bytes(out))
    return len(out)
