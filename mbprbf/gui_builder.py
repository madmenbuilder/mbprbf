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


"""gui_builder.py - сборка .text и финальная сборка PE для GUI-приложений.

Экспортирует build_gui(out_path, windows, widgets, timers, ...).
"""

import struct

from . import pe_builder as pe
from .pe_builder import align_up, IMAGE_SUBSYSTEM_WINDOWS_GUI, build_seh_sections

from .consts import (
    WM_COMMAND, WM_CREATE, WM_DESTROY, WM_TIMER, WM_SIZE,
    WM_CLOSE, WM_PAINT, WM_ERASEBKGND, WM_SETICON,
    ICON_BIG, ICON_SMALL,
    IMAGE_ICON, LR_DEFAULTSIZE,
    SW_SHOW, SW_HIDE,
    IDC_ARROW,
    ICC_STANDARD_CLASSES, ICC_PROGRESS_CLASS, ICC_BAR_CLASSES,
)
from .imports import IMPORT_DLL, CORE_IMPORTS
from .data import (
    DATA_ALLOC, DATA_ORDER, STRINGS,
    DATA_OFF_MSG, DATA_OFF_HINST, DATA_OFF_HEAP,
    layout_data, build_data, WSTRINGS
)
from .structs import WINAPI_STRUCTS, build_struct, resolve_struct_override
from .widgets import Button
from .contexts import GUIContext
from .methods import MethodRegistry
from .arrays import ARRAYS
import ctypes

def _emit_entry_point(ctx_make, windows, timers, code, text_rva, data_rva,
                      data_alloc, iat, used_imports,
                      arrays=None):
    """Entry point: hInstance, hHeap, ICC, регистрация классов, msg loop."""
    def call_iat(name):
        used_imports.add(name)
        iat_rva = iat[name]
        next_rva = text_rva + len(code) + 6
        disp = iat_rva - next_rva
        code.extend(bytes([0xFF, 0x15]) + struct.pack("<i", disp))

    def lea_rip(reg, target_rva):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = text_rva + len(code) + 7
        disp = target_rva - next_rva
        code.extend(bytes([rex, 0x8D, modrm]) + struct.pack("<i", disp))

    def mov_reg_mem(reg, mem_rva):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = text_rva + len(code) + 7
        disp = mem_rva - next_rva
        code.extend(bytes([rex, 0x8B, modrm]) + struct.pack("<i", disp))

    def mov_mem_reg(mem_rva, reg):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = text_rva + len(code) + 7
        disp = mem_rva - next_rva
        code.extend(bytes([rex, 0x89, modrm]) + struct.pack("<i", disp))

    code.extend(bytes([0x48, 0x83, 0xEC, 0x68]))
    code.extend(bytes([0xDB, 0xE3]))   

    code.extend(bytes([0x31, 0xC9]))
    call_iat("GetModuleHandleA")
    mov_mem_reg(data_rva + DATA_OFF_HINST, 0)

    call_iat("GetProcessHeap")
    mov_mem_reg(data_rva + DATA_OFF_HEAP, 0)

    if arrays:
        c_setup = ctx_make(None)
        from .arrays import emit_array_alloc
        for arr in arrays:
            emit_array_alloc(c_setup, arr)

    lea_rip(1, data_rva + data_alloc["_icc"]["off"])
    call_iat("InitCommonControlsEx")

    reg_jz = []
    for win in windows:
        wc_rva = data_rva + win.wc_off

        mov_reg_mem(0, data_rva + DATA_OFF_HINST)
        mov_mem_reg(wc_rva + 0x18, 0)

        code.extend(bytes([0x31, 0xC9]))
        code.extend(bytes([0xBA]) + struct.pack("<I", IDC_ARROW))
        call_iat("LoadCursorA")
        mov_mem_reg(wc_rva + 0x28, 0)

        lea_rip(1, wc_rva)
        call_iat("RegisterClassExA")
        code.extend(bytes([0x48, 0x85, 0xC0]))
        jz = len(code)
        code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))
        reg_jz.append(jz)

    pending_init_calls = []
    for win in windows:
        off = len(code)
        code.extend(bytes([0xE8, 0x00, 0x00, 0x00, 0x00]))
        pending_init_calls.append((off, win))

    main_win = next((w for w in windows if w.is_main), windows[0])
    mov_reg_mem(1, data_rva + main_win.hwnd_off)
    call_iat("UpdateWindow")

    for t in timers:
        if not getattr(t, "autostart", True):
            continue
        parent = t.parent if t.parent is not None else windows[0]
        mov_reg_mem(1, data_rva + parent.hwnd_off)
        code.extend(bytes([0xBA]) + struct.pack("<I", t.id_val))
        code.extend(bytes([0x41, 0xB8]) + struct.pack("<I", t.ms))
        code.extend(bytes([0x45, 0x31, 0xC9]))
        call_iat("SetTimer")

    msg_loop_off = len(code)
    lea_rip(1, data_rva + DATA_OFF_MSG)
    code.extend(bytes([0x31, 0xD2]))
    code.extend(bytes([0x45, 0x31, 0xC0]))
    code.extend(bytes([0x45, 0x31, 0xC9]))
    call_iat("GetMessageA")
    code.extend(bytes([0x85, 0xC0]))
    jz_done = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))
    lea_rip(1, data_rva + DATA_OFF_MSG)
    call_iat("TranslateMessage")
    lea_rip(1, data_rva + DATA_OFF_MSG)
    call_iat("DispatchMessageA")
    rel = msg_loop_off - (len(code) + 5)
    code.extend(bytes([0xE9]) + struct.pack("<i", rel))

    done_off = len(code)
    rel = done_off - (jz_done + 6)
    struct.pack_into("<i", code, jz_done + 2, rel)

    call_iat("ExitProcess")
    code.extend(bytes([0xCC]))

    code.extend(bytes([0x31, 0xC9]))
    call_iat("ExitProcess")
    code.extend(bytes([0xCC]))

    fail_off = len(code)
    for jz in reg_jz:
        rel = fail_off - (jz + 6)
        struct.pack_into("<i", code, jz + 2, rel)
    code.extend(bytes([0xB9]) + struct.pack("<I", 1))
    call_iat("ExitProcess")
    code.extend(bytes([0xCC]))

    return pending_init_calls

def _emit_wndproc(ctx_make, win, widgets, timers, windows_ref, shapes,
                  data_alloc, code, text_rva, data_rva, iat, used_imports,
                  string_rvas, wstring_rvas, method_registry):
    """WndProc одного окна с инлайнеными коллбэками."""
    def call_iat(name):
        used_imports.add(name)
        iat_rva = iat[name]
        next_rva = text_rva + len(code) + 6
        disp = iat_rva - next_rva
        code.extend(bytes([0xFF, 0x15]) + struct.pack("<i", disp))

    win.wndproc_rva = text_rva + len(code)
    code.extend(bytes([0x48, 0x83, 0xEC, 0x68]))

    win_widgets = [w for w in widgets if w.parent is win]
    win_timers = [t for t in timers if (t.parent is win) or
                  (t.parent is None and win is windows_ref[0])]

    code.extend(bytes([0x81, 0xFA]) + struct.pack("<I", WM_COMMAND))
    je_cmd = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    code.extend(bytes([0x81, 0xFA]) + struct.pack("<I", WM_SIZE))
    je_size = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    code.extend(bytes([0x81, 0xFA]) + struct.pack("<I", WM_TIMER))
    je_timer = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    code.extend(bytes([0x81, 0xFA]) + struct.pack("<I", WM_PAINT))
    je_paint = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    code.extend(bytes([0x81, 0xFA]) + struct.pack("<I", WM_ERASEBKGND))
    je_erase = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    je_close = None
    if not win.is_main:
        code.extend(bytes([0x83, 0xFA, WM_CLOSE]))
        je_close = len(code)
        code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    code.extend(bytes([0x83, 0xFA, WM_DESTROY]))
    je_destroy = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    call_iat("DefWindowProcA")
    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

    code.extend(bytes([0x81, 0xFA]) + struct.pack("<I", WM_CREATE))
    je_create = len(code)
    code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))

    off_here = len(code)
    rel = off_here - (je_cmd + 6)
    struct.pack_into("<i", code, je_cmd + 2, rel)

    code.extend(bytes([0x44, 0x89, 0xC0]))                  
    code.extend(bytes([0x25, 0xFF, 0xFF, 0x00, 0x00]))      

    buttons = [w for w in win_widgets
               if isinstance(w, Button) and w.on_click is not None]
    btn_patch = []
    for w in buttons:
        code.extend(bytes([0x3D]) + struct.pack("<I", w.id_val))
        p = len(code)
        code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))
        btn_patch.append((w, p))

    jmp_cmd_done = len(code)
    code.extend(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))

    btn_jmps = []
    for w, p in btn_patch:
        handler = len(code)
        rel = handler - (p + 6)
        struct.pack_into("<i", code, p + 2, rel)
        c = ctx_make(win)
        w.on_click(c)
        j = len(code)
        code.extend(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))
        btn_jmps.append(j)

    cmd_done = len(code)
    rel = cmd_done - (jmp_cmd_done + 5)
    struct.pack_into("<i", code, jmp_cmd_done + 1, rel)
    for j in btn_jmps:
        rel = cmd_done - (j + 5)
        struct.pack_into("<i", code, j + 1, rel)

    code.extend(bytes([0x31, 0xC0]))
    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

    off_here = len(code)
    rel = off_here - (je_size + 6)
    struct.pack_into("<i", code, je_size + 2, rel)

    if win.on_resize is not None:
        c = ctx_make(win)
        win.on_resize(c)

    code.extend(bytes([0x31, 0xC0]))
    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

    off_here = len(code)
    rel = off_here - (je_timer + 6)
    struct.pack_into("<i", code, je_timer + 2, rel)

    code.extend(bytes([0x44, 0x89, 0xC0]))
    code.extend(bytes([0x25, 0xFF, 0xFF, 0x00, 0x00]))

    timers_here = [t for t in win_timers if t.on_tick is not None]
    t_patch = []
    for t in timers_here:
        code.extend(bytes([0x3D]) + struct.pack("<I", t.id_val))
        p = len(code)
        code.extend(bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]))
        t_patch.append((t, p))

    jmp_timer_done = len(code)
    code.extend(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))

    t_jmps = []
    for t, p in t_patch:
        handler = len(code)
        rel = handler - (p + 6)
        struct.pack_into("<i", code, p + 2, rel)
        c = ctx_make(win)
        t.on_tick(c)
        j = len(code)
        code.extend(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))
        t_jmps.append(j)

    timer_done = len(code)
    rel = timer_done - (jmp_timer_done + 5)
    struct.pack_into("<i", code, jmp_timer_done + 1, rel)
    for j in t_jmps:
        rel = timer_done - (j + 5)
        struct.pack_into("<i", code, j + 1, rel)

    code.extend(bytes([0x31, 0xC0]))
    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

    off_here = len(code)
    rel = off_here - (je_erase + 6)
    struct.pack_into("<i", code, je_erase + 2, rel)

    if not getattr(win, "erase_bg", True):
        code.extend(bytes([0xB8, 0x01, 0x00, 0x00, 0x00]))
    else:
        call_iat("DefWindowProcA")
    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

    off_here = len(code)
    rel = off_here - (je_paint + 6)
    struct.pack_into("<i", code, je_paint + 2, rel)

    if shapes:
        from .contexts import GDIContext
        win_shapes = [s for s in shapes if getattr(s, "window", None) in (None, win)]

        c = GDIContext(
            code, text_rva, iat, data_rva, data_alloc,
            hdc_rva=data_rva + data_alloc["_hdc"]["off"],
            ps_rva=data_rva + data_alloc["_ps"]["off"],
            window=win,
            hbrush_rva=data_rva + data_alloc["_hbrush"]["off"],
            hbrush_old_rva=data_rva + data_alloc["_hbrush_old"]["off"],
            hpen_rva=data_rva + data_alloc["_hpen"]["off"],
            hpen_old_rva=data_rva + data_alloc["_hpen_old"]["off"],
            hfont_rva=data_rva + data_alloc["_hfont"]["off"],
            hfont_old_rva=data_rva + data_alloc["_hfont_old"]["off"],
            string_rvas=string_rvas,
            wstring_rvas=wstring_rvas,
            used_imports=used_imports,
            method_registry=method_registry
        )

        c.begin_paint()

        use_db = getattr(win, "double_buffer", False)
        if use_db:
            c.begin_buffer(
                hmemdc_rva=data_rva + data_alloc["_hmemdc"]["off"],
                hbmp_rva=data_rva + data_alloc["_hbmp"]["off"],
                hbmp_old_rva=data_rva + data_alloc["_hbmp_old"]["off"],
                rect_rva=data_rva + data_alloc["_paint_rect"]["off"],
            )

        c.enable_advanced_graphics()

        for shape in win_shapes:
            shape.emit(c)

        if use_db:
            c.present(
                hmemdc_rva=data_rva + data_alloc["_hmemdc"]["off"],
                hbmp_rva=data_rva + data_alloc["_hbmp"]["off"],
                hbmp_old_rva=data_rva + data_alloc["_hbmp_old"]["off"],
                rect_rva=data_rva + data_alloc["_paint_rect"]["off"],
            )

        c.end_paint()
        code.extend(bytes([0x31, 0xC0]))
    else:
        call_iat("DefWindowProcA")

    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

    if je_close is not None:
        off_here = len(code)
        rel = off_here - (je_close + 6)
        struct.pack_into("<i", code, je_close + 2, rel)
        call_iat("DestroyWindow")
        code.extend(bytes([0x31, 0xC0]))
        code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
        code.extend(bytes([0xC3]))

    off_here = len(code)
    rel = off_here - (je_destroy + 6)
    struct.pack_into("<i", code, je_destroy + 2, rel)

    if win.on_destroy is not None:
        c = ctx_make(win)
        win.on_destroy(c)

    if shapes:
        from .contexts import GDIContext

        c_gdi = GDIContext(
            code, text_rva, iat, data_rva, data_alloc,
            hdc_rva=data_rva + data_alloc["_hdc"]["off"],
            ps_rva=data_rva + data_alloc["_ps"]["off"],
            window=win,
            hbrush_rva=data_rva + data_alloc["_hbrush"]["off"],
            hbrush_old_rva=data_rva + data_alloc["_hbrush_old"]["off"],
            hpen_rva=data_rva + data_alloc["_hpen"]["off"],
            hpen_old_rva=data_rva + data_alloc["_hpen_old"]["off"],
            hfont_rva=data_rva + data_alloc["_hfont"]["off"],
            hfont_old_rva=data_rva + data_alloc["_hfont_old"]["off"],
            string_rvas=string_rvas,
            wstring_rvas=wstring_rvas,
            used_imports=used_imports,
            method_registry=method_registry
        )

        for shape in shapes:
            if not hasattr(shape, "himg_key"):
                continue
            if getattr(shape, "window", None) not in (None, win):
                continue

            uid = shape.uid
            c_gdi.image_free_sprite(
                shape.himg_key,
                f"_img_mask_dc_{uid}", f"_img_mask_bmp_{uid}", f"_img_mask_old_{uid}",
                f"_img_mask_inv_dc_{uid}", f"_img_mask_inv_bmp_{uid}", f"_img_mask_inv_old_{uid}",
                f"_img_spr_dc_{uid}", f"_img_spr_bmp_{uid}", f"_img_spr_old_{uid}",
            )
            c_gdi.store_dword_imm(shape.img_w_key, 0)
            c_gdi.store_dword_imm(shape.img_h_key, 0)

    if not win.is_main:
        rva_hwnd = data_rva + win.hwnd_off
        code.extend(bytes([0xC7, 0x05])
                    + struct.pack("<i", rva_hwnd - (text_rva + len(code) + 10))
                    + struct.pack("<I", 0))

    if win.is_main:
        code.extend(bytes([0x31, 0xC9]))
        call_iat("PostQuitMessage")

    code.extend(bytes([0x31, 0xC0]))
    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

    off_here = len(code)
    rel = off_here - (je_create + 6)
    struct.pack_into("<i", code, je_create + 2, rel)

    if win.on_create is not None:
        c = ctx_make(win)
        win.on_create(c)

    code.extend(bytes([0x31, 0xC0]))
    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

def _emit_create_window(ctx_make, win, widgets, code, text_rva, iat,
                        data_rva, data_alloc, used_imports, has_icon=True):
    """create_window_N: CreateWindowExA окна + всех его виджетов."""
    def call_iat(name):
        used_imports.add(name)
        iat_rva = iat[name]
        next_rva = text_rva + len(code) + 6
        disp = iat_rva - next_rva
        code.extend(bytes([0xFF, 0x15]) + struct.pack("<i", disp))

    def lea_rip(reg, target_rva):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = text_rva + len(code) + 7
        disp = target_rva - next_rva
        code.extend(bytes([rex, 0x8D, modrm]) + struct.pack("<i", disp))

    def mov_reg_mem(reg, mem_rva):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = text_rva + len(code) + 7
        disp = mem_rva - next_rva
        code.extend(bytes([rex, 0x8B, modrm]) + struct.pack("<i", disp))

    def mov_mem_reg(mem_rva, reg):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = text_rva + len(code) + 7
        disp = mem_rva - next_rva
        code.extend(bytes([rex, 0x89, modrm]) + struct.pack("<i", disp))

    win.create_rva = text_rva + len(code)
    code.extend(bytes([0x48, 0x83, 0xEC, 0x68]))

    ex_style = getattr(win, "ex_style", 0)
    code.extend(bytes([0xB9]) + struct.pack("<I", ex_style))
    lea_rip(2, win.cls_rva)
    lea_rip(8, win.title_rva)
    code.extend(bytes([0x41, 0xB9]) + struct.pack("<I", win.style))
    code.extend(bytes([0xC7, 0x44, 0x24, 0x20]) + struct.pack("<I", 0x80000000))
    code.extend(bytes([0xC7, 0x44, 0x24, 0x28]) + struct.pack("<I", 0x80000000))
    code.extend(bytes([0xC7, 0x44, 0x24, 0x30]) + struct.pack("<I", win.w))
    code.extend(bytes([0xC7, 0x44, 0x24, 0x38]) + struct.pack("<I", win.h))
    code.extend(bytes([0x48, 0xC7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00]))
    code.extend(bytes([0x48, 0xC7, 0x44, 0x24, 0x48, 0x00, 0x00, 0x00, 0x00]))
    mov_reg_mem(0, data_rva + DATA_OFF_HINST)
    code.extend(bytes([0x48, 0x89, 0x44, 0x24, 0x50]))
    code.extend(bytes([0x48, 0xC7, 0x44, 0x24, 0x58, 0x00, 0x00, 0x00, 0x00]))
    call_iat("CreateWindowExA")
    mov_mem_reg(data_rva + win.hwnd_off, 0)

    if has_icon:
        res_id = win.icon_res_id if win.icon_res_id else 1
        mov_reg_mem(0, data_rva + DATA_OFF_HINST)
        code.extend(bytes([0x48, 0x89, 0xC1]))
        code.extend(bytes([0xBA]) + struct.pack("<I", res_id))
        code.extend(bytes([0x41, 0xB8]) + struct.pack("<I", IMAGE_ICON))
        code.extend(bytes([0x45, 0x31, 0xC9]))
        code.extend(bytes([0xC7, 0x44, 0x24, 0x20]) + struct.pack("<I", 0))
        code.extend(bytes([0xC7, 0x44, 0x24, 0x28])
                + struct.pack("<I", LR_DEFAULTSIZE))
        call_iat("LoadImageA")
        mov_mem_reg(data_rva + data_alloc["_hicon"]["off"], 0)

        mov_reg_mem(1, data_rva + win.hwnd_off)
        code.extend(bytes([0xBA]) + struct.pack("<I", WM_SETICON))
        code.extend(bytes([0x41, 0xB8]) + struct.pack("<I", ICON_BIG))
        mov_reg_mem(9, data_rva + data_alloc["_hicon"]["off"])
        call_iat("SendMessageA")

        mov_reg_mem(1, data_rva + win.hwnd_off)
        code.extend(bytes([0xBA]) + struct.pack("<I", WM_SETICON))
        code.extend(bytes([0x41, 0xB8]) + struct.pack("<I", ICON_SMALL))
        mov_reg_mem(9, data_rva + data_alloc["_hicon"]["off"])
        call_iat("SendMessageA")

    mov_reg_mem(1, data_rva + win.hwnd_off)
    code.extend(bytes([0xBA]) + struct.pack("<I", SW_SHOW if win.visible else SW_HIDE))
    call_iat("ShowWindow")

    for w in widgets:
        if w.parent is not win:
            continue
        code.extend(bytes([0x31, 0xC9]))
        lea_rip(2, w.cls_rva)
        lea_rip(8, w.text_rva)
        code.extend(bytes([0x41, 0xB9]) + struct.pack("<I", w.style))
        code.extend(bytes([0xC7, 0x44, 0x24, 0x20]) + struct.pack("<I", w.x))
        code.extend(bytes([0xC7, 0x44, 0x24, 0x28]) + struct.pack("<I", w.y))
        code.extend(bytes([0xC7, 0x44, 0x24, 0x30]) + struct.pack("<I", w.w))
        code.extend(bytes([0xC7, 0x44, 0x24, 0x38]) + struct.pack("<I", w.h))
        mov_reg_mem(0, data_rva + win.hwnd_off)
        code.extend(bytes([0x48, 0x89, 0x44, 0x24, 0x40]))
        code.extend(bytes([0x48, 0xC7, 0x44, 0x24, 0x48])
                    + struct.pack("<I", w.id_val))
        mov_reg_mem(0, data_rva + DATA_OFF_HINST)
        code.extend(bytes([0x48, 0x89, 0x44, 0x24, 0x50]))
        code.extend(bytes([0x48, 0xC7, 0x44, 0x24, 0x58, 0x00, 0x00, 0x00, 0x00]))
        call_iat("CreateWindowExA")
        mov_mem_reg(data_rva + w.data_off, 0)

    if win.on_resize is not None:
        c = ctx_make(win)
        win.on_resize(c)

    code.extend(bytes([0x48, 0x83, 0xC4, 0x68]))
    code.extend(bytes([0xC3]))

def build_text(text_rva, iat, data_rva, text_buf_off,
               widgets, timers, windows, string_rvas,
               empty_str_rva, data_alloc, used_imports=None,
               wstring_rvas=None, method_registry=None,
               on_setup=None, arrays=None, has_icon=True):
    code = bytearray()
    if used_imports is None:
        used_imports = set()
    if wstring_rvas is None:
        wstring_rvas = {}
    if method_registry is None:
        method_registry = MethodRegistry()

    if on_setup is not None:
        c_setup = GUIContext(
            code, text_rva, iat, data_rva, text_buf_off,
            empty_str_rva, string_rvas, None, data_alloc,
            used_imports=used_imports,
            method_registry=method_registry,
        )
        on_setup(c_setup)

    pending_create_calls = []

    def ctx_make(win):
        c = GUIContext(code, text_rva, iat, data_rva, text_buf_off,
                       empty_str_rva, string_rvas, win, data_alloc,
                       used_imports=used_imports, method_registry=method_registry)
        c.windows_ref = windows

        def _create_window(w2, _c=c):
            off = len(code)
            code.extend(bytes([0xE8, 0x00, 0x00, 0x00, 0x00]))
            pending_create_calls.append((off, w2))

        c.create_window = _create_window
        return c

    pending_init = _emit_entry_point(ctx_make, windows, timers, code,
                                     text_rva, data_rva, data_alloc,
                                     iat, used_imports, arrays=arrays)

    for win in windows:
        _emit_wndproc(ctx_make, win, widgets, timers, windows,
                      getattr(win, "gdi_shapes", []), data_alloc,
                      code, text_rva, data_rva, iat, used_imports,
                      string_rvas, wstring_rvas, method_registry)

    for win in windows:
        _emit_create_window(ctx_make, win, widgets, code, text_rva, iat,
                            data_rva, data_alloc, used_imports, has_icon=has_icon)

    for off, win in pending_init:
        next_rva = text_rva + off + 5
        disp = win.create_rva - next_rva
        struct.pack_into("<i", code, off + 1, disp)

    for off, win in pending_create_calls:
        next_rva = text_rva + off + 5
        disp = win.create_rva - next_rva
        struct.pack_into("<i", code, off + 1, disp)

    from .runtime_guard import gen_runtime_guard
    csh_rva = gen_runtime_guard(GUIContext(
        code, text_rva, iat, data_rva, text_buf_off,
        empty_str_rva, string_rvas, None, data_alloc,
        used_imports=used_imports,
        method_registry=method_registry,
    ))

    return bytes(code), csh_rva, [w.wndproc_rva for w in windows]

def build_gui(out_path, windows, widgets, timers,
              data_alloc=None, data_order=None, strings=None,
              imports=None, extra_strings=None, timestamp=None,
              has_icon=True, has_manifest=True, has_version=True,
              icon=None, version=None, is_default_version=True,
              text_rva=0x1000, extra_resources=None, on_setup=None):
    if data_alloc is None: data_alloc = DATA_ALLOC
    if data_order is None: data_order = DATA_ORDER
    if strings is None: strings = STRINGS
    if extra_strings is None: extra_strings = {}
    if extra_resources is None:
        extra_resources = []

    for name, size in (
        ("_center_x", 4), ("_center_y", 4),
        ("_hicon", 8), ("_icc", 8), ("_ps", 72),
        ("_hdc", 8), ("_hmemdc", 8), ("_hbmp", 8), ("_hbmp_old", 8),
        ("_hbrush", 8), ("_hbrush_old", 8),
        ("_hpen", 8), ("_hpen_old", 8),
        ("_paint_rect", 16), ("_hfont", 8), ("_hfont_old", 8),
        ("_paint_rect", 16),
        ("_loop_i", 4),
        ("_text_rva", 8),
        ("_text_size", 8),
        ("_pdata_rva", 4),
        ("_pdata_count", 4),
    ):
        if name not in data_alloc:
            data_alloc[name] = {"off": None, "size": size, "init": 0, "type": "int"}
            data_order.append(name)

    method_registry = MethodRegistry()

    SECTION_ALIGN = 0x1000
    FILE_ALIGN    = 0x200

    data_offsets, text_buf_off, data_size = layout_data(
        widgets, windows, data_alloc, data_order
    )
    data_bytes = build_data(data_size, data_alloc, data_order)

    used_imports = set(CORE_IMPORTS)
    if imports:
        used_imports.update(imports)

    _TMP_TEXT  = text_rva
    _TMP_RDATA = 0x10000
    _TMP_DATA  = 0x20000

    rb_fake = pe.RdataBuilder(_TMP_RDATA, [])
    rb_fake.add_string("_empty", "")
    empty_str_rva_fake = rb_fake.get_rva("_empty")
    for win in windows:
        win.cls_rva = rb_fake.add_string("cls_" + win.cls_name, win.cls_name)
        win.title_rva = rb_fake.add_string("title_" + win.title, win.title)
        if win.icon:
            win.icon_rva = rb_fake.add_string("icon_" + win.cls_name, win.icon)
    for w in widgets:
        w.cls_rva = rb_fake.add_string("wcls_" + w.cls_name, w.cls_name)
        w.text_rva = rb_fake.add_string("wtext_" + w.name + "_" + w.text, w.text)
        w.data_off = data_offsets[w.name]
    string_rvas_fake = {}
    for name, s in strings.items():
        string_rvas_fake[name] = rb_fake.add_string("str_" + name, s)
    for name, s in extra_strings.items():
        if name in string_rvas_fake:
            continue
        string_rvas_fake[name] = rb_fake.add_string("str_" + name, s)
    wstring_rvas_fake = {}
    for name, s in WSTRINGS.items():
        wstring_rvas_fake[name] = rb_fake.add_wstring("wstr_" + name, s)

    from . import memory_tracker as _mt
    _mt.reset_tracking()
    iat_fake = {name: 0 for name in IMPORT_DLL}
    _tb, _csh, _wp = build_text(_TMP_TEXT, iat_fake, _TMP_DATA, text_buf_off,
                                widgets, timers, windows, string_rvas_fake,
                                empty_str_rva_fake, data_alloc, used_imports=used_imports,
                                wstring_rvas=wstring_rvas_fake, method_registry=method_registry, on_setup=on_setup, arrays=ARRAYS, has_icon=has_icon)

    unknown = used_imports - set(IMPORT_DLL.keys())
    if unknown:
        raise KeyError(
            f"build_gui: неизвестные импорты {sorted(unknown)}. "
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
    for win in windows:
        win.cls_rva = rb_tmp.add_string("cls_" + win.cls_name, win.cls_name)
        win.title_rva = rb_tmp.add_string("title_" + win.title, win.title)
        if win.icon:
            win.icon_rva = rb_tmp.add_string("icon_" + win.cls_name, win.icon)
    for w in widgets:
        w.cls_rva = rb_tmp.add_string("wcls_" + w.cls_name, w.cls_name)
        w.text_rva = rb_tmp.add_string("wtext_" + w.name + "_" + w.text, w.text)
    string_rvas_tmp = {}
    for name, s in strings.items():
        string_rvas_tmp[name] = rb_tmp.add_string("str_" + name, s)
    for name, s in extra_strings.items():
        if name in string_rvas_tmp:
            continue
        string_rvas_tmp[name] = rb_tmp.add_string("str_" + name, s)
    wstring_rvas_tmp = {}
    for name, s in WSTRINGS.items():
        wstring_rvas_tmp[name] = rb_tmp.add_wstring("wstr_" + name, s)
    rdata_bytes_tmp, _, _, _, _ = rb_tmp.build()

    unique_icons = _prepare_icons(windows, icon)

    _mt.reset_tracking()
    text_bytes_tmp, _csh_tmp, _wp_tmp = build_text(_TMP_TEXT, rb_tmp.iat, _TMP_DATA,
                                                    text_buf_off, widgets, timers, windows,
                                                    string_rvas_tmp, empty_str_rva_tmp,
                                                    data_alloc, wstring_rvas=wstring_rvas_tmp, method_registry=method_registry, on_setup=on_setup, arrays=ARRAYS, has_icon=has_icon)

    text_padded  = align_up(len(text_bytes_tmp),  FILE_ALIGN)
    rdata_padded = align_up(len(rdata_bytes_tmp), FILE_ALIGN)
    data_padded  = align_up(len(data_bytes),      FILE_ALIGN)

    text_rva_final  = text_rva
    rdata_rva_final = text_rva_final  + align_up(text_padded,  SECTION_ALIGN)
    data_rva_final  = rdata_rva_final + align_up(rdata_padded, SECTION_ALIGN)

    rb = pe.RdataBuilder(rdata_rva_final, real_imports)
    rb.add_string("_empty", "")
    empty_str_rva = rb.get_rva("_empty")
    for win in windows:
        win.cls_rva = rb.add_string("cls_" + win.cls_name, win.cls_name)
        win.title_rva = rb.add_string("title_" + win.title, win.title)
        if win.icon:
            win.icon_rva = rb.add_string("icon_" + win.cls_name, win.icon)
    for w in widgets:
        w.cls_rva = rb.add_string("wcls_" + w.cls_name, w.cls_name)
        w.text_rva = rb.add_string("wtext_" + w.name + "_" + w.text, w.text)
        w.data_off = data_offsets[w.name]
    string_rvas = {}
    for name, s in strings.items():
        string_rvas[name] = rb.add_string("str_" + name, s)
    for name, s in extra_strings.items():
        if name in string_rvas:
            continue
        string_rvas[name] = rb.add_string("str_" + name, s)
    wstring_rvas = {}
    for name, s in WSTRINGS.items():
        wstring_rvas[name] = rb.add_wstring("wstr_" + name, s)
    rdata_bytes, idt_rva, idt_size, iat_rva, iat_size = rb.build()

    _mt.reset_tracking()
    text_bytes, csh_rva_wrapper, _wp_final = build_text(text_rva_final, rb.iat, data_rva_final,
                                                       text_buf_off, widgets, timers, windows,
                                                       string_rvas, empty_str_rva, data_alloc, wstring_rvas=wstring_rvas, method_registry=method_registry, on_setup=on_setup, arrays=ARRAYS, has_icon=has_icon)

    db_tmp = bytearray(data_bytes)
    struct.pack_into("<Q", db_tmp, data_alloc["_text_rva"]["off"], text_rva_final)
    struct.pack_into("<Q", db_tmp, data_alloc["_text_size"]["off"], len(text_bytes))
    data_bytes = bytes(db_tmp)

    from .memory_tracker import check_all_freed
    check_all_freed()

    db = bytearray(data_bytes)

    icc_off = data_alloc["_icc"]["off"]
    icc_flags = (ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS | ICC_BAR_CLASSES)
    struct.pack_into("<I", db, icc_off + 0, 8)
    struct.pack_into("<I", db, icc_off + 4, icc_flags)

    spec_wc = WINAPI_STRUCTS["WNDCLASSEXA"]
    for win in windows:
        blob = build_struct(
            "WNDCLASSEXA", pe.IMAGE_BASE,
            lpfnWndProc=win.wndproc_rva,
            lpszClassName=win.cls_rva,
        )
        if win.wc_off + spec_wc["size"] > len(db):
            raise ValueError(f"WNDCLASSEXA {win.cls_name}: выход за .data")
        db[win.wc_off:win.wc_off + spec_wc["size"]] = blob

    for name in data_order:
        info = data_alloc.get(name)
        if not info or info.get("type") != "struct":
            continue
        struct_name = info.get("struct_name")
        if struct_name not in WINAPI_STRUCTS:
            raise KeyError(f"{name}: struct_name={struct_name!r} нет в WINAPI_STRUCTS")
        spec = WINAPI_STRUCTS[struct_name]

        overrides = dict(info.get("struct_overrides", {}))
        for key, val in list(overrides.items()):
            overrides[key] = resolve_struct_override(
                val, string_rvas, data_rva_final, data_alloc, windows
            )

        blob = build_struct(struct_name, pe.IMAGE_BASE, **overrides)
        off = info["off"]
        db[off:off + spec["size"]] = blob

    data_bytes = bytes(db)

    assert len(text_bytes) == len(text_bytes_tmp), (
        f"build_gui: text size mismatch {len(text_bytes):#x} vs "
        f"{len(text_bytes_tmp):#x} — RVA влияют на длину кода"
    )
    assert len(rdata_bytes) == len(rdata_bytes_tmp), (
        f"build_gui: rdata size mismatch {len(rdata_bytes):#x} vs "
        f"{len(rdata_bytes_tmp):#x}"
    )

    rsrc_rva_final = data_rva_final + align_up(data_padded, SECTION_ALIGN)

    resources = []

    if has_manifest:
        manifest_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
            '  <dependency>\n'
            '    <dependentAssembly>\n'
            '      <assemblyIdentity type="win32" '
            'name="Microsoft.Windows.Common-Controls" '
            'version="6.0.0.0" processorArchitecture="*" '
            'publicKeyToken="6595b64144ccf1df" language="*"/>\n'
            '    </dependentAssembly>\n'
            '  </dependency>\n'
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
                file_description="MBPRBF GUI Application",
                product_name="MBPRBF Application",
            )
        if version:
            resources.append((16, 1, 0x0409, pe.build_version_info(version)))

    if extra_resources:
        resources.extend(extra_resources)

    if has_icon:
        unique_icons = _prepare_icons(windows, icon)
        if unique_icons:
            try:
                rt_icon_next_id = 1
                for source, is_exe, win, gid in unique_icons:
                    icons, grp = pe.parse_ico(source)
                    first_icon_id = rt_icon_next_id
                    for icondata in icons:
                        resources.append((3, rt_icon_next_id, 0x0409, icondata))
                        rt_icon_next_id += 1
                    grp_fixed = pe.rewrite_grp_nids(grp, first_icon_id)
                    resources.append((14, gid, 0x0409, grp_fixed))
            except ImportError:
                pass
    else:
        for win in windows:
            win.icon_res_id = 0

    if resources:
        rsrc_builder = pe.RsrcBuilder(rsrc_rva_final)
        rsrc_bytes = rsrc_builder.build(resources)
    else:
        rsrc_bytes = b""

    all_methods = list(method_registry.methods.values())

    pdata_rva_final = rsrc_rva_final + align_up(len(rsrc_bytes), SECTION_ALIGN)
    n_methods_with_rva = sum(1 for m in all_methods
                             if m.rva is not None and m.end_rva is not None)
    pdata_size_est = n_methods_with_rva * 12
    xdata_rva_final = pdata_rva_final + align_up(pdata_size_est, SECTION_ALIGN)

    c_specific_rva = csh_rva_wrapper

    pdata_bytes, xdata_bytes = build_seh_sections(
        all_methods,
        pdata_rva_final,
        xdata_rva_final,
        c_specific_rva,
    )

    IMAGE_REL_BASED_DIR64 = 10
    relocs = []

    wc_spec = WINAPI_STRUCTS["WNDCLASSEXA"]
    wc_cls = wc_spec["cls"]
    for win in windows:
        for field in wc_spec["rva_fields"]:
            field_off = getattr(wc_cls, field).offset
            reloc_rva = data_rva_final + win.wc_off + field_off
            relocs.append((reloc_rva, IMAGE_REL_BASED_DIR64))

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

    total = pe.build_pe(out_path, text_bytes, rdata_bytes, data_bytes,
                        entry_rva=text_rva_final,
                        import_dir_rva=idt_rva, import_dir_size=idt_size,
                        iat_rva=iat_rva, iat_size=iat_size,
                        rsrc_bytes=rsrc_bytes,
                        rsrc_rva=rsrc_rva_final,
                        pdata_bytes=pdata_bytes,
                        pdata_rva=pdata_rva_final,
                        xdata_bytes=xdata_bytes,
                        xdata_rva=xdata_rva_final,
                        relocs=relocs,
                        text_rva=text_rva_final,
                        rdata_rva=rdata_rva_final,
                        timestamp=timestamp,
                        data_rva=data_rva_final,
                        subsystem=IMAGE_SUBSYSTEM_WINDOWS_GUI)
    print(f"Generated {out_path}: {total} bytes")
    print(f"  sections: .text={len(text_bytes)} .rdata={len(rdata_bytes)} "
          f".data={len(data_bytes)}")
    print(f"  imports ({len(used_imports)}): {sorted(used_imports)}")

    return total

def _prepare_icons(windows, icon):
    try:
        from PIL import Image   
    except ImportError:
        for win in windows:
            win.icon_res_id = 1
        return []

    icon_sources = []
    if icon:
        icon_sources.append((icon, True, None))
    else:
        icon_sources.append((pe.make_default_icon(), True, None))
    for win in windows:
        if win.icon:
            icon_sources.append((win.icon, False, win))

    def src_key(s):
        return bytes(s) if isinstance(s, (bytes, bytearray)) else str(s)

    seen = {}
    group_id = 0
    unique = []
    for source, is_exe, win in icon_sources:
        k = src_key(source)
        if k in seen:
            unique.append((source, is_exe, win, seen[k]))
        else:
            group_id += 1
            seen[k] = group_id
            unique.append((source, is_exe, win, group_id))

    for source, is_exe, win, gid in unique:
        if win is not None:
            win.icon_res_id = gid

    for win in windows:
        if win.icon_res_id is None:
            win.icon_res_id = 1

    return unique
