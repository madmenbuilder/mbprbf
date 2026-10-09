# MBPRBF — Madmen Builder for Programs on Raw Bytes Framework
# Copyright (C) 2026 Madmen3733
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


"""console.py - сборка консольных приложений для MBRBF.

Публичный API:
    build_console(out_path, main, data_alloc=None, data_order=None,
                  strings=None, imports=None, extra_strings=None,
                  version=None, text_rva=0x1000)

    main(ctx)  - функция, эмитящая код entry point через ConsoleContext.

Также реэкспортирует всё нужное для консольного генератора:
    ConsoleContext, data_alloc, data_alloc_struct, add_string, reset_data,
    IMPORT_DLL, CONSOLE_CORE_IMPORTS.
"""

import struct

from . import pe_builder as pe
from .pe_builder import align_up, build_seh_sections

from .consts import (
    STD_OUTPUT_HANDLE, STD_INPUT_HANDLE,
)
from .imports import IMPORT_DLL, CONSOLE_CORE_IMPORTS
from .data import (
    DATA_ALLOC, DATA_ORDER, STRINGS, build_data
)
from .methods import MethodRegistry
from .structs import WINAPI_STRUCTS
from .contexts import ConsoleContext
import ctypes

def _ensure_service_slots(data_alloc, data_order):
    """Добавить слоты, нужные консольному приложению."""
    for name, size in (
        ("_hinst",   8),
        ("_stdout",  8),
        ("_stdin",   8),
        ("_written", 4),
        ("_read",    4),
        ("_scratch", 4),
        ("_text_rva", 4),
        ("_text_size", 8),
        ("_loop_i", 4),
        ("_pdata_rva", 4),
        ("_pdata_count", 4),
    ):
        if name not in data_alloc:
            data_alloc[name] = {"off": None, "size": size,
                                "init": 0, "type": "int"}
            data_order.append(name)

def _ensure_service_strings(strings):
    """Добавить базовые строки, нужные консольному приложению.

    Регистрирует ТОЛЬКО:
      - переводы строк / пробелы
      - форматы printf для wsprintfA
      - разделители

    Готовые фразы (_press_enter, _done, _ok, _error и т.д.)
    пользователь добавляет сам через add_string.

    Не перезаписывает уже добавленные пользователем строки.
    """
    base = {
        # --- Переводы строк / пробелы ---
        "_crlf":   "\r\n",
        "_lf":     "\n",
        "_cr":     "\r",
        "_tab":    "\t",
        "_space":  " ",
        "_empty":  "",
        "_nul":    "\x00",

        # --- Форматы printf (для wsprintfA) ---
        "_fmt_d":   "%d",
        "_fmt_u":   "%u",
        "_fmt_x":   "%x",
        "_fmt_X":   "%X",
        "_fmt_s":   "%s",
        "_fmt_c":   "%c",
        "_fmt_p":   "%p",
        "_fmt_ld":  "%ld",
        "_fmt_lu":  "%lu",
        "_fmt_lld": "%lld",
        "_fmt_llu": "%llu",
        "_fmt_zu":  "%zu",
        "_fmt_f":   "%f",
        "_fmt_lf":  "%lf",
        "_fmt_g":   "%g",
        "_fmt_e":   "%e",

        # --- Разделители ---
        "_eq":    "=",
        "_colon": ": ",
        "_comma": ", ",
        "_dash":  " - ",
    }
    for name, value in base.items():
        if name not in strings:
            strings[name] = value

def _layout_console_data(data_alloc, data_order):
    """Раскладка .data для консольного приложения.

    Использует ФИКСИРОВАННЫЕ offsets из data.py:
        DATA_OFF_MSG   = 0x50   (зарезервировано, не используется)
        DATA_OFF_HINST = 0x80
        DATA_OFF_HEAP  = 0x90
    """
    from .consts import TEXT_BUF_SIZE
    from .data import (DATA_OFF_HINST, DATA_OFF_HEAP,
                       DATA_OFF_FREE_START)

    data_alloc["_hinst"]["off"] = DATA_OFF_HINST

    data_alloc["_heap"]["off"] = DATA_OFF_HEAP

    cursor = DATA_OFF_FREE_START

    cursor = align_up(cursor, 8)
    data_alloc["_stdout"]["off"] = cursor
    cursor += 8

    cursor = align_up(cursor, 8)
    data_alloc["_stdin"]["off"] = cursor
    cursor += 8

    cursor = align_up(cursor, 8)
    data_alloc["_written"]["off"] = cursor
    cursor += 4

    cursor = align_up(cursor, 8)
    data_alloc["_read"]["off"] = cursor
    cursor += 4

    cursor = align_up(cursor, 8)
    data_alloc["_scratch"]["off"] = cursor
    cursor += 4

    for name in data_order:
        info = data_alloc[name]
        if info["off"] is not None:
            continue
        cursor = align_up(cursor, 8)
        info["off"] = cursor
        cursor += info["size"]

    cursor = align_up(cursor, 16)
    text_buf_off = cursor
    cursor += TEXT_BUF_SIZE
    cursor = align_up(cursor, 16)

    return cursor, text_buf_off

def _build_console_text(text_rva, iat, data_rva, text_buf_off,
                        main, data_alloc, used_imports,
                        string_rvas=None, strings=None, method_registry=None):
    """Сгенерировать .text консольного приложения."""
    code = bytearray()

    def call_iat(name):
        used_imports.add(name)
        iat_rva = iat[name]
        next_rva = text_rva + len(code) + 6
        disp = iat_rva - next_rva
        code.extend(bytes([0xFF, 0x15]) + struct.pack("<i", disp))

    def mov_mem_reg(mem_rva, reg):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = text_rva + len(code) + 7
        disp = mem_rva - next_rva
        code.extend(bytes([rex, 0x89, modrm]) + struct.pack("<i", disp))

    code.extend(bytes([0x48, 0x83, 0xEC, 0x48]))   

    code.extend(bytes([0x31, 0xC9]))
    call_iat("GetModuleHandleA")
    mov_mem_reg(data_rva + data_alloc["_hinst"]["off"], 0)

    call_iat("GetProcessHeap")
    mov_mem_reg(data_rva + data_alloc["_heap"]["off"], 0)

    code.extend(bytes([0xB9]) + struct.pack("<i", STD_OUTPUT_HANDLE))
    call_iat("GetStdHandle")
    mov_mem_reg(data_rva + data_alloc["_stdout"]["off"], 0)

    code.extend(bytes([0xB9]) + struct.pack("<i", STD_INPUT_HANDLE))
    call_iat("GetStdHandle")
    mov_mem_reg(data_rva + data_alloc["_stdin"]["off"], 0)

    ctx = ConsoleContext(
        code, text_rva, iat, data_rva, data_alloc,
        stdout_rva=data_rva + data_alloc["_stdout"]["off"],
        stdin_rva=data_rva + data_alloc["_stdin"]["off"],
        buf_rva=data_rva + text_buf_off,
        written_rva=data_rva + data_alloc["_written"]["off"],
        read_rva=data_rva + data_alloc["_read"]["off"],
        scratch_rva=data_rva + data_alloc["_scratch"]["off"],
        string_rvas=string_rvas,
        strings=strings,
        used_imports=used_imports,
        method_registry=method_registry
    )

    from .arrays import ARRAYS, emit_array_alloc

    for arr in ARRAYS:
        emit_array_alloc(ctx, arr)

    main(ctx)

    code.extend(bytes([0x31, 0xC9]))
    call_iat("ExitProcess")
    code.extend(bytes([0xCC]))

    from .runtime_guard import gen_runtime_guard
    csh_rva_wrapper = gen_runtime_guard(ctx)

    return bytes(code), csh_rva_wrapper

def build_console(out_path, main,
                  data_alloc=None, data_order=None, strings=None,
                  imports=None, extra_strings=None,
                  has_icon=True, has_manifest=True, has_version=True,
                  icon=None, version=None, is_default_version=True, timestamp=None,
                  text_rva=0x1000):
    """Собрать консольное приложение.

    out_path     - путь к .exe
    main         - callable(ctx) -> None, эмитит entry point
    data_alloc   - реестр .data (по умолчанию DATA_ALLOC)
    data_order   - порядок (по умолчанию DATA_ORDER)
    strings      - реестр строк (по умолчанию STRINGS)
    imports      - дополнительные импорты (кроме CONSOLE_CORE_IMPORTS)
    extra_strings - дополнительные строки (не добавляются в STRINGS)
    version      - dict для RT_VERSION
    text_rva     - RVA секции .text
    """
    if data_alloc is None: data_alloc = DATA_ALLOC
    if data_order is None: data_order = DATA_ORDER
    if strings is None: strings = STRINGS
    if extra_strings is None: extra_strings = {}

    _ensure_service_slots(data_alloc, data_order)
    _ensure_service_strings(strings)
    if "_heap" not in data_alloc:
        data_alloc["_heap"] = {"off": None, "size": 8,
                               "init": 0, "type": "int"}
        data_order.append("_heap")

    method_registry = MethodRegistry()

    data_size, text_buf_off = _layout_console_data(data_alloc, data_order)
    data_bytes = build_data(data_size, data_alloc, data_order)

    SECTION_ALIGN = 0x1000
    FILE_ALIGN    = 0x200

    used_imports = set(CONSOLE_CORE_IMPORTS)
    if imports:
        used_imports.update(imports)

    _TMP_TEXT  = text_rva
    _TMP_RDATA = 0x10000
    _TMP_DATA  = 0x20000

    rb_fake = pe.RdataBuilder(_TMP_RDATA, [])
    rb_fake.add_string("_empty", "")
    string_rvas_fake = {}
    for name, s in strings.items():
        string_rvas_fake[name] = rb_fake.add_string("str_" + name, s)
    for name, s in extra_strings.items():
        if name in string_rvas_fake:
            continue
        string_rvas_fake[name] = rb_fake.add_string("str_" + name, s)

    iat_fake = {name: 0 for name in IMPORT_DLL}

    from . import memory_tracker as _mt

    _mt.reset_tracking()

    _build_console_text(_TMP_TEXT, iat_fake, _TMP_DATA, text_buf_off,
                        main, data_alloc, used_imports,
                        string_rvas=string_rvas_fake, strings=strings, method_registry=method_registry)

    unknown = used_imports - set(IMPORT_DLL.keys())
    if unknown:
        raise KeyError(
            f"build_console: неизвестные импорты {sorted(unknown)}. "
            f"Добавьте их в IMPORT_DLL в imports.py."
        )

    dll_to_funcs = {}
    for name in sorted(used_imports):
        dll = IMPORT_DLL[name]
        dll_to_funcs.setdefault(dll, []).append(name)
    real_imports = [(dll, sorted(funcs)) for dll, funcs in sorted(dll_to_funcs.items())]

    rb_tmp = pe.RdataBuilder(_TMP_RDATA, real_imports)
    rb_tmp.add_string("_empty", "")
    empty_str_rva_tmp = rb_tmp.get_rva("_empty")
    string_rvas_tmp = {}
    for name, s in strings.items():
        string_rvas_tmp[name] = rb_tmp.add_string("str_" + name, s)
    for name, s in extra_strings.items():
        if name in string_rvas_tmp:
            continue
        string_rvas_tmp[name] = rb_tmp.add_string("str_" + name, s)
    rdata_bytes_tmp, _, _, _, _ = rb_tmp.build()

    _mt.reset_tracking()
    text_bytes_tmp, _csh_tmp = _build_console_text(
        _TMP_TEXT, rb_tmp.iat, _TMP_DATA,
        text_buf_off, main, data_alloc, set(used_imports),
        string_rvas=string_rvas_tmp,
        strings=strings, method_registry=method_registry)

    text_padded  = align_up(len(text_bytes_tmp),  FILE_ALIGN)
    rdata_padded = align_up(len(rdata_bytes_tmp), FILE_ALIGN)
    data_padded  = align_up(len(data_bytes),      FILE_ALIGN)

    text_rva_final  = text_rva
    rdata_rva_final = text_rva_final  + align_up(text_padded,  SECTION_ALIGN)
    data_rva_final  = rdata_rva_final + align_up(rdata_padded, SECTION_ALIGN)

    rb = pe.RdataBuilder(rdata_rva_final, real_imports)
    rb.add_string("_empty", "")
    string_rvas = {}
    for name, s in strings.items():
        string_rvas[name] = rb.add_string("str_" + name, s)
    for name, s in extra_strings.items():
        if name in string_rvas:
            continue
        string_rvas[name] = rb.add_string("str_" + name, s)
    rdata_bytes, idt_rva, idt_size, iat_rva, iat_size = rb.build()

    used_imports_final = set(used_imports)
    _mt.reset_tracking()
    text_bytes, csh_rva = _build_console_text(
        text_rva_final, rb.iat, data_rva_final,
        text_buf_off, main, data_alloc, used_imports_final,
        string_rvas=string_rvas,
        strings=strings, method_registry=method_registry)

    db = bytearray(data_bytes)
    struct.pack_into("<Q", db, data_alloc["_text_rva"]["off"], text_rva_final)
    struct.pack_into("<Q", db, data_alloc["_text_size"]["off"], len(text_bytes))
    data_bytes = bytes(db)

    from .memory_tracker import check_all_freed
    check_all_freed()

    assert len(text_bytes) == len(text_bytes_tmp), (
        f"build_console: text size mismatch {len(text_bytes):#x} vs "
        f"{len(text_bytes_tmp):#x}"
    )
    assert len(rdata_bytes) == len(rdata_bytes_tmp), (
        f"build_console: rdata size mismatch {len(rdata_bytes):#x} vs "
        f"{len(rdata_bytes_tmp):#x}"
    )

    rsrc_rva_final = data_rva_final + align_up(data_padded, SECTION_ALIGN)

    resources = []

    if has_manifest:
        manifest_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
            '  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">\n'
            '    <security>\n'
            '      <requestedPrivileges>\n'
            '        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>\n'
            '      </requestedPrivileges>\n'
            '    </security>\n'
            '  </trustInfo>\n'
            '  <application xmlns="urn:schemas-microsoft-com:asm.v3">\n'
            '    <windowsSettings>\n'
            '      <dpiAware xmlns="...">true/pm</dpiAware>\n'
            '      <dpiAwareness xmlns="...">PerMonitorV2,PerMonitor</dpiAwareness>\n'
            '    </windowsSettings>\n'
            '  </application>\n'
            '</assembly>'
        )
        resources.append((24, 1, 0x0409, manifest_xml.encode("utf-8")))

    if has_version:
        if version is None and is_default_version:
            import os
            exe_basename = os.path.splitext(os.path.basename(out_path))[0]
            version = pe.make_default_version(
                internal_name=exe_basename,
                original_filename=os.path.basename(out_path),
                file_description="Built with MBPRBF",
                product_name="MBPRBF Application",
            )
        if version:
            resources.append((16, 1, 0x0409, pe.build_version_info(version)))

    if has_icon:
        icon_sources = []
        if icon is not None:
            icon_sources.append(icon)
        else:
            icon_sources.append(pe.make_default_icon())

        def _icon_key(s):
            return bytes(s) if isinstance(s, (bytes, bytearray)) else str(s)

        seen = {}
        unique_icons = []
        for src in icon_sources:
            k = _icon_key(src)
            if k not in seen:
                unique_icons.append(src)
                seen[k] = True

        rt_icon_next_id = 1
        grp_id_next = 1
        for source in unique_icons:
            try:
                icons, grp = pe.parse_ico(source)
            except ImportError:
                break
            first_icon_id = rt_icon_next_id
        for icondata in icons:
            resources.append((3, rt_icon_next_id, 0x0409, icondata))
            rt_icon_next_id += 1
            grp_fixed = pe.rewrite_grp_nids(grp, first_icon_id)
            resources.append((14, grp_id_next, 0x0409, grp_fixed))
            grp_id_next += 1

    if resources:
        rsrc_builder = pe.RsrcBuilder(rsrc_rva_final)
        rsrc_bytes = rsrc_builder.build(resources)
    else:
        rsrc_bytes = b""

    all_methods = list(method_registry.methods.values())
    for m in all_methods:
        if m.rva is None or m.end_rva is None:
            continue
        if m.unwind_info is not None:
            ui = m.unwind_info
    pdata_rva_final = rsrc_rva_final + align_up(len(rsrc_bytes), SECTION_ALIGN)
    n_methods_with_rva = sum(1 for m in all_methods
                             if m.rva is not None and m.end_rva is not None)
    pdata_size_est = n_methods_with_rva * 12
    xdata_rva_final = pdata_rva_final + align_up(pdata_size_est, SECTION_ALIGN)

    pdata_bytes, xdata_bytes = build_seh_sections(
        all_methods,
        pdata_rva_final,
        xdata_rva_final,
        csh_rva,
    )

    n_rt = len(pdata_bytes) // 12
    db = bytearray(data_bytes)
    struct.pack_into("<I", db, data_alloc["_pdata_rva"]["off"], pdata_rva_final)
    struct.pack_into("<I", db, data_alloc["_pdata_count"]["off"], n_rt)
    data_bytes = bytes(db)

    IMAGE_REL_BASED_DIR64 = 10
    relocs = []
    for name in data_order:
        info = data_alloc.get(name)
        if not info or info.get("type") != "struct":
            continue
        struct_name = info.get("struct_name")
        if struct_name not in WINAPI_STRUCTS:
            continue
        spec = WINAPI_STRUCTS[struct_name]
        cls = spec["cls"]
        for field in spec["rva_fields"]:
            field_off = getattr(cls, field).offset
            reloc_rva = data_rva_final + info["off"] + field_off
            relocs.append((reloc_rva, IMAGE_REL_BASED_DIR64))

    from .pe_builder import IMAGE_SUBSYSTEM_WINDOWS_CUI
    total = pe.build_pe(out_path, text_bytes, rdata_bytes, data_bytes,
                        entry_rva=text_rva_final,
                        import_dir_rva=idt_rva, import_dir_size=idt_size,
                        iat_rva=iat_rva, iat_size=iat_size,
                        rsrc_bytes=rsrc_bytes if rsrc_bytes else None,
                        rsrc_rva=rsrc_rva_final if rsrc_bytes else None,
                        pdata_bytes=pdata_bytes,
                        pdata_rva=pdata_rva_final,
                        xdata_bytes=xdata_bytes,
                        xdata_rva=xdata_rva_final,
                        relocs=relocs,
                        text_rva=text_rva_final,
                        rdata_rva=rdata_rva_final,
                        data_rva=data_rva_final,
                        timestamp=timestamp,
                        subsystem=IMAGE_SUBSYSTEM_WINDOWS_CUI)
    print(f"Generated {out_path}: {total} bytes")
    print(f"  sections: .text={len(text_bytes)} .rdata={len(rdata_bytes)} "
          f".data={len(data_bytes)}")
    print(f"  imports ({len(used_imports_final)}): {sorted(used_imports_final)}")

    return total
