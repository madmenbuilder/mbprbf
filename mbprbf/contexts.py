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


"""contexts.py - контексты эмиссии машинного кода.

Context         - низкоуровневые примитивы (mov/lea/call/jcc/heap/...).
GUIContext      - высокоуровневые GUI-хелперы поверх Context.
ConsoleContext  - высокоуровневые консольные хелперы поверх Context.
"""

import struct

from .consts import (
    SW_SHOW,
    IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE,
    WM_SETICON, ICON_BIG, ICON_SMALL,
    SM_CXSCREEN, SM_CYSCREEN,
    BM_GETCHECK, LB_ADDSTRING, LB_GETCURSEL,
    CB_ADDSTRING, CB_GETCURSEL,
    PBM_SETPOS, PBM_SETRANGE32, PBM_GETPOS,
    TBM_SETRANGE, TBM_SETPOS, TBM_GETPOS,
)
from .data import DATA_OFF_HEAP, DATA_OFF_HINST
from .methods import (MethodsMixin, MethodRegistry, distribute_args,
                     Method, MethodArg, _struct_return_kind, _size_of, LocalVar, FRAME_BASE)
import ctypes

from .memory_tracker import (track_alloc, track_free, track_realloc)

from .seh import (
    SehBuilder, UnwindInfo, ScopeRecord, RuntimeFunction,
    EXCEPTION_EXECUTE_HANDLER, EXCEPTION_CONTINUE_SEARCH,
)

class _TryCtx:
    """Контекстный менеджер для __try."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.block = None

    def __enter__(self):
        if self.ctx._current_method is None:
            raise RuntimeError("try_: вне метода")
        m = self.ctx._current_method
        if m.get('seh_builder') is None:
            m['seh_builder'] = SehBuilder(m['method'])
        sb = m['seh_builder']
        begin_rva = self.ctx.text_rva + len(self.ctx.code)
        self.block = sb.open_try(begin_rva)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            return False
        if self.ctx._current_method is None:
            return False
        m = self.ctx._current_method
        sb = m['seh_builder']
        end_rva = self.ctx.text_rva + len(self.ctx.code)
        sb.close_try(end_rva)
        return False

class _ExceptCtx:
    def __init__(self, ctx, filter_kind):
        self.ctx = ctx
        self.filter_kind = filter_kind
        self.pending = None
        self.jmp_after_except = None

    def __enter__(self):
        if self.ctx._current_method is None:
            raise RuntimeError("except_: вне метода")
        m = self.ctx._current_method
        sb = m.get('seh_builder')
        if sb is None:
            raise RuntimeError("except_: __try не открыт")

        if self.filter_kind == EXCEPTION_EXECUTE_HANDLER:
            filter_rva = 1
            self.pending = None
        else:
            n = len(self.ctx._pending_filters)
            filter_name = f"_except_filter_{n}"
            self.pending = {
                'kind': self.filter_kind,
                'name': filter_name,
                'rva': None,
                'fixups': [],
            }
            self.ctx._pending_filters.append(self.pending)
            filter_rva = 0  

        self.jmp_after_except = self.ctx.jmp_placeholder()

        begin_rva = self.ctx.text_rva + len(self.ctx.code)
        sb.open_except(begin_rva, filter_rva=filter_rva)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            return False
        m = self.ctx._current_method
        sb = m['seh_builder']
        end_rva = self.ctx.text_rva + len(self.ctx.code)
        scope = sb.close_except(end_rva)
        if self.pending is not None:
            self.pending['fixups'].append(scope)
        self.ctx.patch_jmp_here(self.jmp_after_except)
        return False

class _FinallyCtx:
    def __init__(self, ctx, body_fn):
        self.ctx = ctx
        self.body_fn = body_fn
        self.block = None
        self.body_start = None

    def __enter__(self):
        if self.ctx._current_method is None:
            raise RuntimeError("finally_: вне метода")
        m = self.ctx._current_method
        if m.get('seh_builder') is None:
            raise RuntimeError("finally_: __try не открыт")
        sb = m['seh_builder']

        begin_rva = self.ctx.text_rva + len(self.ctx.code)
        self.block = sb.open_finally(begin_rva)

        self.body_start = len(self.ctx.code)
        if self.body_fn is not None:
            self.body_fn(self.ctx)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            return False
        if self.ctx._current_method is None:
            return False

        m = self.ctx._current_method
        sb = m['seh_builder']
        main_ctx = self.ctx

        n = main_ctx._finally_handler_counter
        main_ctx._finally_handler_counter += 1
        handler_name = f"_finally_handler_{n}"

        saved = main_ctx._current_method
        main_ctx._current_method = None
        try:
            main_ctx.start_method(handler_name,
                                  [ctypes.c_void_p] * 4,
                                  ret_type=ctypes.c_int)
            if self.body_fn is not None:
                self.body_fn(main_ctx)
            main_ctx.emit(bytes([0x31, 0xC0]))
            main_ctx.end_method()
        finally:
            main_ctx._current_method = saved

        handler_rva = main_ctx.method_registry.get(handler_name).rva

        end_rva = main_ctx.text_rva + len(main_ctx.code)
        sb.close_finally(end_rva, handler_rva=handler_rva)
        return False

def _find_dll_path(dll_name):
    """Найти путь к DLL в стандартных местах."""
    import os
    search_dirs = [
        os.getcwd(),
        os.path.dirname(os.path.abspath(__file__)),
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
    ]
    path_env = os.environ.get("PATH", "")
    search_dirs.extend(p for p in path_env.split(os.pathsep) if p)

    for d in search_dirs:
        try:
            candidate = os.path.join(d, dll_name)
            if os.path.isfile(candidate):
                return candidate
        except (OSError, ValueError):
            continue
    return None

_LOADED_DLLS = {}

def _check_export_exists(name, dll):
    """Проверить через ctypes, что name экспортируется DLL dll.

    Использует ctypes.WinDLL + getattr (GetProcAddress под капотом).
    Кэширует загруженные DLL — не грузит одну DLL многократно.
    """
    import ctypes

    if dll in _LOADED_DLLS:
        lib = _LOADED_DLLS[dll]
    else:
        dll_path = _find_dll_path(dll)
        if dll_path is None:

            print(f"[ffi] warning: '{dll}' not found on disk — "
                  f"skip export check")
            _LOADED_DLLS[dll] = None
            return
        try:
            lib = ctypes.WinDLL(dll_path)
        except OSError as e:
            raise RuntimeError(
                f"ffi: не удалось загрузить '{dll}' ({dll_path}): {e}"
            )
        _LOADED_DLLS[dll] = lib

    if lib is None:
        return

    try:
        _ = getattr(lib, name)
    except AttributeError:
        raise RuntimeError(
            f"ffi: функция '{name}' не экспортируется из '{dll}'. "
            f"Проверьте имя (опечатка? не та версия DLL? не та DLL?)."
        )

class Context(MethodsMixin):
    def __init__(self, code, text_rva, iat, data_rva, data_alloc, method_registry=None,
                 used_imports=None):
        self.code = code
        self.text_rva = text_rva
        self.iat = iat
        self.data_rva = data_rva
        self.data_alloc = data_alloc
        self.used_imports = used_imports if used_imports is not None else set()
        self._current_method = None
        self.method_registry = method_registry if method_registry is not None \
                               else MethodRegistry()
        self._pending_filters = []
        self._in_pending_filters = False
        self._finally_handler_counter = 0

    def emit(self, b):
        self.code.extend(b)

    def len(self):
        return len(self.code)

    def rva_now(self):
        return self.text_rva + len(self.code)

    @staticmethod
    def i32(v):
        """Упаковать int32 (в т.ч. отрицательный) в 4 байта LE."""
        return struct.pack("<I", v & 0xFFFFFFFF)

    @staticmethod
    def i16(v):
        return struct.pack("<H", v & 0xFFFF)

    @staticmethod
    def i8(v):
        return struct.pack("<B", v & 0xFF)

    def array_get(self, arr, index):
        from .arrays import array_get as _f
        _f(self, arr, index)

    def array_set(self, arr, index, value):
        from .arrays import array_set as _f
        _f(self, arr, index, value)

    def array_len(self, arr):
        from .arrays import array_len as _f
        _f(self, arr)

    def array_free(self, arr):
        from .arrays import array_free as _f
        _f(self, arr)

    def array_append(self, arr, value, type_=None):
        from .array_runtime import array_append as _f
        _f(self, arr, value, type_)

    def array_insert(self, arr, index, value, type_=None):
        from .array_runtime import array_insert as _f
        _f(self, arr, index, value, type_)

    def array_remove(self, arr, index):
        from .array_runtime import array_remove as _f
        _f(self, arr, index)

    def array_resize(self, arr, new_length, type_=None):
        from .array_runtime import array_resize as _f
        _f(self, arr, new_length, type_)

    def patch_i32(self, off, val):
        struct.pack_into("<i", self.code, off, val)

    def rva_of(self, name):
        info = self.data_alloc.get(name)
        if info is None:
            raise KeyError(f"rva_of: '{name}' не зарегистрирован в .data")
        off = info["off"]
        if off is None:
            return self.data_rva + 0
        return self.data_rva + off

    def _data_rva(self, name):
        info = self.data_alloc.get(name)
        if info is None:
            raise KeyError(f"_data_rva: '{name}' не зарегистрирован в .data")
        off = info["off"]
        if off is None:
            return self.data_rva + 0
        return self.data_rva + off

    def _resolve_buf(self, buf):
        if isinstance(buf, str):
            info = self.data_alloc.get(buf)
            if info is None:
                raise KeyError(f"_resolve_buf: '{buf}' не зарегистрирован")
            off = info["off"]
            if off is None:
                return 0
            return off
        return buf

    def call_iat(self, name):
        self.used_imports.add(name)
        iat_rva = self.iat[name]
        next_rva = self.text_rva + len(self.code) + 6
        disp = iat_rva - next_rva
        self.emit(bytes([0xFF, 0x15]) + struct.pack("<i", disp))

    def call_rva(self, target_rva):
        next_rva = self.text_rva + len(self.code) + 5
        disp = target_rva - next_rva
        self.emit(bytes([0xE8]) + struct.pack("<i", disp))

    def lea_rip(self, reg, target_rva):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = self.text_rva + len(self.code) + 7
        disp = target_rva - next_rva
        self.emit(bytes([rex, 0x8D, modrm]) + struct.pack("<i", disp))

    def mov_reg_rva(self, reg, mem_rva):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = self.text_rva + len(self.code) + 7
        disp = mem_rva - next_rva
        self.emit(bytes([rex, 0x8B, modrm]) + struct.pack("<i", disp))

    def mov_mem_reg(self, mem_rva, reg):
        rex = 0x48
        if reg >= 8:
            rex |= 0x04
            reg -= 8
        modrm = 0x05 | (reg << 3)
        next_rva = self.text_rva + len(self.code) + 7
        disp = mem_rva - next_rva
        self.emit(bytes([rex, 0x89, modrm]) + struct.pack("<i", disp))

    def mov_eax_rva(self, rva):
        self.emit(bytes([0x8B, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def mov_ecx_rva(self, rva):
        self.emit(bytes([0x8B, 0x0D]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def mov_edx_rva(self, rva):
        self.emit(bytes([0x8B, 0x15]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def store_eax_rva(self, rva):
        self.emit(bytes([0x89, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def add_eax_rva(self, rva):
        self.emit(bytes([0x03, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def sub_eax_rva(self, rva):
        self.emit(bytes([0x2B, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def cmp_eax_rva(self, rva):
        self.emit(bytes([0x3B, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def store_dword_imm_rva(self, rva, v):
        self.emit(bytes([0xC7, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 10))
                  + struct.pack("<I", v & 0xFFFFFFFF))
    def neg_dword_rva(self, rva):
        self.emit(bytes([0xF7, 0x1D]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def inc_dword_rva(self, rva):
        self.emit(bytes([0xFF, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def mov_r8d_rva(self, rva):
        self.emit(bytes([0x44, 0x8B, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 7)))
    def mov_r9d_mem(self, name):
        rva = self.rva_of(name)
        self.emit(bytes([0x45, 0x8B, 0x0D]) + struct.pack("<i", rva - (self.rva_now() + 7)))

    def mov_eax_mem(self, name):       self.mov_eax_rva(self.rva_of(name))
    def mov_ecx_mem(self, name):       self.mov_ecx_rva(self.rva_of(name))
    def mov_edx_mem(self, name):       self.mov_edx_rva(self.rva_of(name))
    def store_eax_mem(self, name):     self.store_eax_rva(self.rva_of(name))
    def add_eax_mem(self, name):       self.add_eax_rva(self.rva_of(name))
    def sub_eax_mem(self, name):       self.sub_eax_rva(self.rva_of(name))
    def cmp_eax_mem(self, name):       self.cmp_eax_rva(self.rva_of(name))
    def store_dword_imm(self, name, v): self.store_dword_imm_rva(self.rva_of(name), v)
    def neg_dword_mem(self, name):     self.neg_dword_rva(self.rva_of(name))
    def inc_dword_mem(self, name):     self.inc_dword_rva(self.rva_of(name))
    def mov_r8d_mem(self, name):       self.mov_r8d_rva(self.rva_of(name))

    def imul_eax_eax_imm8(self, v):
        self.emit(bytes([0x6B, 0xC0, v & 0xFF]))
    def imul_eax_rva(self, rva):
        self.emit(bytes([0x0F, 0xAF, 0x05])
                  + struct.pack("<i", rva - (self.rva_now() + 7)))
    def shr_eax_1(self):
        self.emit(bytes([0xD1, 0xE8]))
    def cmp_eax_imm32(self, v):
        self.emit(bytes([0x3D]) + struct.pack("<I", v & 0xFFFFFFFF))
    def cmp_edx_imm8(self, v):
        self.emit(bytes([0x83, 0xFA, v & 0xFF]))
    def cmp_edx_imm32(self, v):
        self.emit(bytes([0x81, 0xFA]) + struct.pack("<I", v & 0xFFFFFFFF))
    def cmp_eax_ecx(self):
        self.emit(bytes([0x39, 0xC8]))
    def cmp_ecx_eax(self):
        self.emit(bytes([0x39, 0xC1]))
    def add_eax_imm32(self, v):
        self.emit(bytes([0x05]) + struct.pack("<I", v & 0xFFFFFFFF))
    def sub_eax_imm32(self, v):
        self.emit(bytes([0x2D]) + struct.pack("<I", v & 0xFFFFFFFF))
    def add_ecx_imm32(self, v):
        self.emit(bytes([0x81, 0xC1]) + struct.pack("<I", v & 0xFFFFFFFF))
    def sub_ecx_imm32(self, v):
        self.emit(bytes([0x81, 0xE9]) + struct.pack("<I", v & 0xFFFFFFFF))
    def load_eax_imm(self, v):
        self.emit(bytes([0xB8]) + struct.pack("<I", v & 0xFFFFFFFF))
    def test_eax_eax(self):
        self.emit(bytes([0x85, 0xC0]))

    def mov_rax_rva(self, rva):
        self.mov_reg_rva(0, rva)
    def mov_rax_mem(self, name):
        self.mov_reg_rva(0, self.rva_of(name))
    def store_rax_rva(self, rva):
        self.mov_mem_reg(rva, 0)
    def store_rax_mem(self, name):
        self.mov_mem_reg(self.rva_of(name), 0)
    def store_ecx_rva(self, rva):
        self.emit(bytes([0x89, 0x0D]) + struct.pack("<i", rva - (self.rva_now() + 6)))
    def store_ecx_mem(self, name):
        self.store_ecx_rva(self.rva_of(name))

    def jcc(self, cc):
        self.emit(bytes([0x0F, cc, 0x00, 0x00, 0x00, 0x00]))
        return self.len() - 4

    def _f32_bits(self, x):
        return struct.unpack("<i", struct.pack("<f", float(x)))[0] & 0xFFFFFFFF

    def _emit_float_to_stack(self, val, stack_off):
        """Загрузить float в [rsp+stack_off].

        val: float (imm) или str (имя слота в .data, читается как float32).
        """
        if isinstance(val, str):
            rva = self.rva_of(val)

            self.emit(bytes([0xF3, 0x0F, 0x10, 0x05])
                      + struct.pack("<i", rva - (self.rva_now() + 8)))

            self.emit(bytes([0xF3, 0x0F, 0x11, 0x44, 0x24, stack_off]))
        else:
            bits = self._f32_bits(float(val)) & 0xFFFFFFFF
            self.emit(bytes([0xC7, 0x44, 0x24, stack_off])
                      + struct.pack("<I", bits))

    def if_mem_eq_imm(self, name, imm):
        self.mov_eax_mem(name); self.cmp_eax_imm32(imm); return self.jcc(0x84)
    def if_mem_ne_imm(self, name, imm):
        self.mov_eax_mem(name); self.cmp_eax_imm32(imm); return self.jcc(0x85)
    def if_mem_ge_imm(self, name, imm):
        self.mov_eax_mem(name); self.cmp_eax_imm32(imm); return self.jcc(0x8D)
    def if_mem_le_imm(self, name, imm):
        self.mov_eax_mem(name); self.cmp_eax_imm32(imm); return self.jcc(0x8E)
    def if_mem_gt_imm(self, name, imm):
        self.mov_eax_mem(name); self.cmp_eax_imm32(imm); return self.jcc(0x8F)
    def if_mem_lt_imm(self, name, imm):
        self.mov_eax_mem(name); self.cmp_eax_imm32(imm); return self.jcc(0x8C)

    def if_mem_zero(self, name):
        self.mov_eax_mem(name); self.test_eax_eax(); return self.jcc(0x84)
    def if_mem_nonzero(self, name):
        self.mov_eax_mem(name); self.test_eax_eax(); return self.jcc(0x85)
    def if_rva_nonzero(self, rva):
        self.mov_eax_rva(rva); self.test_eax_eax(); return self.jcc(0x85)
    def if_rva_zero(self, rva):
        self.mov_eax_rva(rva); self.test_eax_eax(); return self.jcc(0x84)

    def if_rax_zero(self, name):
        self.mov_rax_mem(name); self.emit(bytes([0x48, 0x85, 0xC0])); return self.jcc(0x84)
    def if_rax_nonzero(self, name):
        self.mov_rax_mem(name); self.emit(bytes([0x48, 0x85, 0xC0])); return self.jcc(0x85)

    def if_edx_eq_imm(self, name, imm):
        self.mov_edx_mem(name); self.cmp_edx_imm32(imm); return self.jcc(0x84)
    def if_edx_ne_imm(self, name, imm):
        self.mov_edx_mem(name); self.cmp_edx_imm32(imm); return self.jcc(0x85)
    def if_edx_ge_imm(self, name, imm):
        self.mov_edx_mem(name); self.cmp_edx_imm32(imm); return self.jcc(0x8D)
    def if_edx_le_imm(self, name, imm):
        self.mov_edx_mem(name); self.cmp_edx_imm32(imm); return self.jcc(0x8E)
    def if_edx_gt_imm(self, name, imm):
        self.mov_edx_mem(name); self.cmp_edx_imm32(imm); return self.jcc(0x8F)
    def if_edx_lt_imm(self, name, imm):
        self.mov_edx_mem(name); self.cmp_edx_imm32(imm); return self.jcc(0x8C)

    def if_edx_eq_imm_loaded(self, imm):
        self.cmp_edx_imm32(imm); return self.jcc(0x84)
    def if_edx_ne_imm_loaded(self, imm):
        self.cmp_edx_imm32(imm); return self.jcc(0x85)
    def if_edx_ge_imm_loaded(self, imm):
        self.cmp_edx_imm32(imm); return self.jcc(0x8D)
    def if_edx_le_imm_loaded(self, imm):
        self.cmp_edx_imm32(imm); return self.jcc(0x8E)
    def if_edx_gt_imm_loaded(self, imm):
        self.cmp_edx_imm32(imm); return self.jcc(0x8F)
    def if_edx_lt_imm_loaded(self, imm):
        self.cmp_edx_imm32(imm); return self.jcc(0x8C)

    def if_eax_eq_imm_loaded(self, imm):
        self.cmp_eax_imm32(imm); return self.jcc(0x84)
    def if_eax_ne_imm_loaded(self, imm):
        self.cmp_eax_imm32(imm); return self.jcc(0x85)
    def if_eax_ge_imm_loaded(self, imm):
        self.cmp_eax_imm32(imm); return self.jcc(0x8D)
    def if_eax_le_imm_loaded(self, imm):
        self.cmp_eax_imm32(imm); return self.jcc(0x8E)
    def if_eax_gt_imm_loaded(self, imm):
        self.cmp_eax_imm32(imm); return self.jcc(0x8F)
    def if_eax_lt_imm_loaded(self, imm):
        self.cmp_eax_imm32(imm); return self.jcc(0x8C)

    def jmp_placeholder(self):
        off = self.len()
        self.emit(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))
        return off
    def patch_here(self, off):
        self.patch_i32(off, self.len() - (off + 4))
    def patch_jmp_here(self, off):
        self.patch_i32(off + 1, self.len() - (off + 5))

    def heap_alloc(self, name, size):
        rva = self.rva_of(name)
        self.heap_alloc_at_rva(rva, size)

    def heap_free(self, name):
        rva = self.rva_of(name)
        self.heap_free_at_rva(rva)

    def heap_realloc(self, name, new_size):
        rva = self.rva_of(name)
        self.heap_realloc_at_rva(rva, new_size)

    def heap_alloc_at_rva(self, slot_rva, size):
        """HeapAlloc(hHeap, 0, size) → [slot_rva] = rax."""
        name = f"heap@{slot_rva:#x}"
        track_alloc(name, kind="heap")

        self.mov_rax_rva(self.data_rva + DATA_OFF_HEAP)
        self.emit(bytes([0x48, 0x89, 0xC1]))
        self.emit(bytes([0x31, 0xD2]))
        self.emit(bytes([0x49, 0xC7, 0xC0]) + struct.pack("<I", size))
        self.call_iat("HeapAlloc")
        self.mov_mem_reg(slot_rva, 0)

    def heap_free_at_rva(self, slot_rva):
        """HeapFree(hHeap, 0, [slot_rva])."""
        name = f"heap@{slot_rva:#x}"
        track_free(name)

        self.mov_rax_rva(self.data_rva + DATA_OFF_HEAP)
        self.emit(bytes([0x48, 0x89, 0xC1]))
        self.emit(bytes([0x31, 0xD2]))
        self.mov_reg_rva(8, slot_rva)
        self.call_iat("HeapFree")

    def heap_realloc_at_rva(self, slot_rva, new_size):
        """HeapReAlloc(hHeap, 0, [slot_rva], new_size) → [slot_rva]."""
        name = f"heap@{slot_rva:#x}"
        track_realloc(name)

        self.mov_rax_rva(self.data_rva + DATA_OFF_HEAP)
        self.emit(bytes([0x48, 0x89, 0xC1]))
        self.emit(bytes([0x31, 0xD2]))
        self.mov_reg_rva(8, slot_rva)
        self.emit(bytes([0x49, 0xC7, 0xC1]) + struct.pack("<I", new_size))
        self.emit(bytes([0x4D, 0x85, 0xC0]))
        jnz_have = self.jcc(0x85)
        self.mov_rax_rva(self.data_rva + DATA_OFF_HEAP)
        self.emit(bytes([0x48, 0x89, 0xC1]))
        self.emit(bytes([0x31, 0xD2]))
        self.emit(bytes([0x49, 0xC7, 0xC0]) + struct.pack("<I", new_size))
        self.call_iat("HeapAlloc")
        jmp_done = self.jmp_placeholder()
        self.patch_here(jnz_have)
        self.call_iat("HeapReAlloc")
        self.patch_jmp_here(jmp_done)
        self.mov_mem_reg(slot_rva, 0)

    def store_qword_imm_mem(self, name, v):
        rva = self.rva_of(name)
        self.emit(bytes([0x48, 0xC7, 0x05])
                  + struct.pack("<i", rva - (self.rva_now() + 11))
                  + struct.pack("<I", v & 0xFFFFFFFF))

    def store_qword_imm_mem_rva(self, rva, v):
        self.emit(bytes([0x48, 0xC7, 0x05])
                  + struct.pack("<i", rva - (self.rva_now() + 11))
                  + struct.pack("<I", v & 0xFFFFFFFF))

    def cvtsi2ss_xmm_eax(self):
        """cvtsi2ss xmm0, eax."""
        self.emit(bytes([0xF3, 0x0F, 0x2A, 0xC0]))

    def movss_mem_xmm0(self, rva):
        """movss [rip+rva], xmm0."""
        next_rva = self.rva_now() + 8
        disp = rva - next_rva
        self.emit(bytes([0xF3, 0x0F, 0x11, 0x05]) + struct.pack("<i", disp))

    def _push_loop(self, name):
        """Начать цикл. Возвращает dict-состояние."""
        if not hasattr(self, '_loop_stack'):
            self._loop_stack = []
        state = {
            'name': name,
            'start_off': len(self.code),
            'exit_jmps': [],  
        }
        self._loop_stack.append(state)
        return state

    def _pop_loop(self):
        """Закончить цикл. Патчит все exit-прыжки на текущую позицию."""
        state = self._loop_stack.pop()
        exit_off = len(self.code)
        for jmp_off in state['exit_jmps']:
            rel = exit_off - (jmp_off + 6)  
            struct.pack_into("<i", self.code, jmp_off + 2, rel)

    def loop_for(self, name, var_name, start, end, body_fn):
        if not hasattr(self, '_loop_stack'):
            self._loop_stack = []

        state = {
            'name': name,
            'var_name': var_name,
            'start_off': None,
            'exit_jmps': [],  
            'continue_jmps': [],  
        }
        self._loop_stack.append(state)

        self.store_dword_imm(var_name, start)
        state['start_off'] = len(self.code)

        self.mov_eax_mem(var_name)
        self.cmp_eax_imm32(end)
        jge_off = self.jcc(0x8D)  
        state['exit_jmps'].append(jge_off)

        body_fn(self)

        cont_off = len(self.code)
        for off_rel32 in state['continue_jmps']:
            rel = cont_off - (off_rel32 + 4)
            struct.pack_into("<i", self.code, off_rel32, rel)

        self.inc_dword_mem(var_name)

        rel = state['start_off'] - (len(self.code) + 5)
        self.emit(bytes([0xE9]) + struct.pack("<i", rel))

        exit_off = len(self.code)
        for off_rel32 in state['exit_jmps']:
            rel = exit_off - (off_rel32 + 4)
            struct.pack_into("<i", self.code, off_rel32, rel)

        self._loop_stack.pop()

    def loop_break(self, n=1):
        if not hasattr(self, '_loop_stack') or not self._loop_stack:
            raise RuntimeError("loop_break: нет активных циклов")
        if n < 1 or n > len(self._loop_stack):
            raise RuntimeError(f"loop_break: неверный уровень {n}")
        state = self._loop_stack[-n]
        off = len(self.code)
        self.emit(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))  
        state['exit_jmps'].append(off + 1)  

    def loop_continue(self):
        if not hasattr(self, '_loop_stack') or not self._loop_stack:
            raise RuntimeError("loop_continue: нет активных циклов")
        state = self._loop_stack[-1]
        off = len(self.code)
        self.emit(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))
        state['continue_jmps'].append(off + 1)  

    def cvttss2si_eax_xmm0(self):
        self.emit(bytes([0xF3, 0x0F, 0x2C, 0xC0]))  

    def movss_xmm0_mem(self, rva):
        next_rva = self.rva_now() + 8
        disp = rva - next_rva
        self.emit(bytes([0xF3, 0x0F, 0x10, 0x05]) + struct.pack("<i", disp))

    def cvtsi2ss_xmm0_eax(self):
        """cvtsi2ss xmm0, eax (F3 0F 2A C0)."""
        self.emit(bytes([0xF3, 0x0F, 0x2A, 0xC0]))

    def mov_int_to_float_slot(self, int_name, float_name):
        """_float_name = float(_int_name) через cvtsi2ss."""
        self.mov_eax_mem(int_name)
        self.cvtsi2ss_xmm0_eax()
        self.movss_mem_xmm0(self.rva_of(float_name))

    def loop_while(self, name, cond_fn, body_fn):
        """Цикл while.

        name     - имя метки (для отладки),
        cond_fn  - callable(c) -> off_rel32 | None
                   если None → бесконечный цикл (while True)
                   если off → jcc, который прыгает на .exit, когда условие ЛОЖНО
        body_fn  - callable(c) — тело цикла.
        """
        if not hasattr(self, '_loop_stack'):
            self._loop_stack = []

        state = {
            'name': name,
            'start_off': None,
            'exit_jmps': [],
            'continue_jmps': [],
        }
        self._loop_stack.append(state)

        state['start_off'] = len(self.code)

        cond_jmp = cond_fn(self) if cond_fn is not None else None
        if cond_jmp is not None:

            state['exit_jmps'].append(cond_jmp)

        body_fn(self)

        cont_off = len(self.code)
        for off_rel32 in state['continue_jmps']:
            rel = cont_off - (off_rel32 + 4)
            struct.pack_into("<i", self.code, off_rel32, rel)

        rel = state['start_off'] - (len(self.code) + 5)
        self.emit(bytes([0xE9]) + struct.pack("<i", rel))

        exit_off = len(self.code)
        for off_rel32 in state['exit_jmps']:
            rel = exit_off - (off_rel32 + 4)
            struct.pack_into("<i", self.code, off_rel32, rel)

        self._loop_stack.pop()

    def _va_arg_pos(self, index):
        """Абсолютная позиция varargs-аргумента с учётом фиксированных.

        index — 0-based индекс varargs-аргумента.
        """
        if self._current_method is None:
            raise RuntimeError("va_arg_*: вне метода")
        if not self._current_method.get('varargs'):
            raise RuntimeError(
                f"va_arg_*: метод '{self._current_method['name']}' "
                f"не помечен как varargs"
            )
        return self._current_method['n_fixed'] + index

    def va_arg_int(self, ap_name):
        """va_arg(ap, int) → eax."""
        ap_rva = self.rva_of(ap_name)

        self.emit(bytes([0x8B, 0x0D])
                  + struct.pack("<i", ap_rva + 0x18 - (self.rva_now() + 6)))

        self.emit(bytes([0x83, 0xF9, 0x04]))

        jae_stack = self.jcc(0x83)

        self.emit(bytes([0x48, 0x8B, 0x05])
                  + struct.pack("<i", ap_rva + 0x00 - (self.rva_now() + 7)))

        self.emit(bytes([0x8B, 0x04, 0xC8]))

        self.emit(bytes([0x83, 0x05])
                  + struct.pack("<i", ap_rva + 0x18 - (self.rva_now() + 7))
                  + bytes([0x01]))

        jmp_done = self.jmp_placeholder()

        self.patch_here(jae_stack)

        self.emit(bytes([0x48, 0x8B, 0x05])
                  + struct.pack("<i", ap_rva + 0x10 - (self.rva_now() + 7)))

        self.emit(bytes([0x8B, 0x00]))

        self.emit(bytes([0x48, 0x83, 0x05])
                  + struct.pack("<i", ap_rva + 0x10 - (self.rva_now() + 8))
                  + bytes([0x08]))

        self.patch_jmp_here(jmp_done)

    def va_arg_double(self, ap_name):
        """va_arg(ap, double) → xmm0."""
        ap_rva = self.rva_of(ap_name)

        self.emit(bytes([0x8B, 0x0D])
                  + struct.pack("<i", ap_rva + 0x1C - (self.rva_now() + 6)))

        self.emit(bytes([0x83, 0xF9, 0x04]))

        jae_stack = self.jcc(0x83)

        self.emit(bytes([0x48, 0x8B, 0x05])
                  + struct.pack("<i", ap_rva + 0x08 - (self.rva_now() + 7)))

        self.emit(bytes([0xF2, 0x0F, 0x10, 0x04, 0xC8]))

        self.emit(bytes([0x83, 0x05])
                  + struct.pack("<i", ap_rva + 0x1C - (self.rva_now() + 7))
                  + bytes([0x01]))

        jmp_done = self.jmp_placeholder()

        self.patch_here(jae_stack)

        self.emit(bytes([0x48, 0x8B, 0x05])
                  + struct.pack("<i", ap_rva + 0x10 - (self.rva_now() + 7)))

        self.emit(bytes([0xF2, 0x0F, 0x10, 0x00]))

        self.emit(bytes([0x48, 0x83, 0x05])
                  + struct.pack("<i", ap_rva + 0x10 - (self.rva_now() + 8))
                  + bytes([0x08]))

        self.patch_jmp_here(jmp_done)

    def va_arg_int64(self, ap_name):
        """va_arg(ap, long long) → rax."""
        ap_rva = self.rva_of(ap_name)

        self.emit(bytes([0x8B, 0x0D])
                  + struct.pack("<i", ap_rva + 0x18 - (self.rva_now() + 6)))

        self.emit(bytes([0x83, 0xF9, 0x04]))

        jae_stack = self.jcc(0x83)

        self.emit(bytes([0x48, 0x8B, 0x05])
                  + struct.pack("<i", ap_rva + 0x00 - (self.rva_now() + 7)))

        self.emit(bytes([0x48, 0x8B, 0x04, 0xC8]))

        self.emit(bytes([0x83, 0x05])
                  + struct.pack("<i", ap_rva + 0x18 - (self.rva_now() + 7))
                  + bytes([0x01]))

        jmp_done = self.jmp_placeholder()

        self.patch_here(jae_stack)

        self.emit(bytes([0x48, 0x8B, 0x05])
                  + struct.pack("<i", ap_rva + 0x10 - (self.rva_now() + 7)))

        self.emit(bytes([0x48, 0x8B, 0x00]))

        self.emit(bytes([0x48, 0x83, 0x05])
                  + struct.pack("<i", ap_rva + 0x10 - (self.rva_now() + 8))
                  + bytes([0x08]))

        self.patch_jmp_here(jmp_done)

    def va_start(self, ap_name, n_fixed=0):
        ap_rva = self.rva_of(ap_name)

        off = 0x10 + n_fixed * 8
        if off <= 0x7F:

            self.emit(bytes([0x48, 0x8D, 0x45, off]))
        else:

            self.emit(bytes([0x48, 0x8D, 0x85]) + struct.pack("<i", off))

        self.emit(bytes([0x48, 0x89, 0x05])
                  + struct.pack("<i", ap_rva + 0x00 - (self.rva_now() + 7)))

        self.emit(bytes([0x48, 0x89, 0x05])
                  + struct.pack("<i", ap_rva + 0x08 - (self.rva_now() + 7)))

        self.emit(bytes([0x48, 0x8D, 0x45, 0x30]))

        self.emit(bytes([0x48, 0x89, 0x05])
                  + struct.pack("<i", ap_rva + 0x10 - (self.rva_now() + 7)))

        self.emit(bytes([0xC7, 0x05])
                  + struct.pack("<i", ap_rva + 0x18 - (self.rva_now() + 10))
                  + struct.pack("<I", 0))

        self.emit(bytes([0xC7, 0x05])
                  + struct.pack("<i", ap_rva + 0x1C - (self.rva_now() + 10))
                  + struct.pack("<I", 0))

    def local(self, name, ctype, init=None, size=None):
        """Объявить локальную переменную.

        Возвращает LocalVar.
        """
        if self._current_method is None:
            raise RuntimeError("local: вне метода")

        m = self._current_method
        method = m['method']

        for l in method.locals:
            if l.name == name:
                raise ValueError(f"local: '{name}' уже объявлена")

        if size is not None:
            sz = size
        else:
            sz = _size_of(ctype)
        align = min(sz, 8)

        offset = method.local_size
        offset = (offset + align - 1) & ~(align - 1)

        method.local_size = offset + sz

        var = LocalVar(name, ctype, offset, sz, align, method)
        method.locals.append(var)

        if init is not None:
            self.store_local(var, init)

        return var

    def _local_disp(self, var):
        """Смещение локальной от rbp: [rbp - disp]."""
        return -(FRAME_BASE + var.offset)

    def load_local(self, var):
        disp = self._local_disp(var)
        ctype = var.ctype

        if ctype is ctypes.c_int8:

            self.emit(bytes([0x0F, 0xBE, 0x85]) + struct.pack("<i", disp))
        elif ctype is ctypes.c_int16:

            self.emit(bytes([0x0F, 0xBF, 0x85]) + struct.pack("<i", disp))
        elif ctype is ctypes.c_int32:

            self.emit(bytes([0x8B, 0x85]) + struct.pack("<i", disp))
        elif ctype in (ctypes.c_int64, ctypes.c_void_p):

            self.emit(bytes([0x48, 0x8B, 0x85]) + struct.pack("<i", disp))
        elif ctype is ctypes.c_float:

            self.emit(bytes([0xF3, 0x0F, 0x10, 0x85]) + struct.pack("<i", disp))
        elif ctype is ctypes.c_double:

            self.emit(bytes([0xF2, 0x0F, 0x10, 0x85]) + struct.pack("<i", disp))
        else:
            raise TypeError(f"load_local: неподдерживаемый тип {ctype!r}")

    def store_local(self, var, value):
        """Сохранить value в локальную."""
        if self._current_method is None:
            raise RuntimeError("store_local: вне метода")

        disp = self._local_disp(var)
        ctype = var.ctype

        if isinstance(value, int):
            if ctype is ctypes.c_int8:

                self.emit(bytes([0xC6, 0x85]) + struct.pack("<i", disp)
                      + struct.pack("<B", value & 0xFF))
            elif ctype is ctypes.c_int16:

                self.emit(bytes([0x66, 0xC7, 0x85]) + struct.pack("<i", disp)
                      + struct.pack("<H", value & 0xFFFF))
            elif ctype is ctypes.c_int32:

                self.emit(bytes([0xC7, 0x85]) + struct.pack("<i", disp)
                      + struct.pack("<I", value & 0xFFFFFFFF))
        elif isinstance(value, float):
            if ctype is ctypes.c_float:
                bits = struct.unpack("<I", struct.pack("<f", value))[0]

                self.emit(bytes([0xC7, 0x85]) + struct.pack("<i", disp)
                          + struct.pack("<I", bits))
            elif ctype is ctypes.c_double:
                bits = struct.unpack("<Q", struct.pack("<d", value))[0]

                self.emit(bytes([0x48, 0xB8]) + struct.pack("<Q", bits))
                self.emit(bytes([0x48, 0x89, 0x85]) + struct.pack("<i", disp))
        elif isinstance(value, LocalVar):

            self.load_local(value)
            if ctype in (ctypes.c_int8, ctypes.c_int16, ctypes.c_int32):
                self.emit(bytes([0x89, 0x85]) + struct.pack("<i", disp))
            elif ctype in (ctypes.c_int64, ctypes.c_void_p):
                self.emit(bytes([0x48, 0x89, 0x85]) + struct.pack("<i", disp))
            elif ctype is ctypes.c_float:
                self.emit(bytes([0xF3, 0x0F, 0x11, 0x85]) + struct.pack("<i", disp))
            elif ctype is ctypes.c_double:
                self.emit(bytes([0xF2, 0x0F, 0x11, 0x85]) + struct.pack("<i", disp))
        else:
            raise TypeError(f"store_local: неподдерживаемое значение {value!r}")

    def ffi_export_method(self, name, dll, args, ret=None, alias=None,
                          ret_struct=None, varargs=False):
        """Экспортировать C-функцию.

        abi='std'   — Microsoft x64 ABI (MinGW, clang, rustc, go).
        abi='msvc'  — MSVC positional ABI (Debug и Release).
        abi='auto'  — автоопределение по импортам DLL (default).

        Автоопределение срабатывает ТОЛЬКО если нужен:
          - смешанные int+float аргументы, ИЛИ
          - структуры by value.
        Для чистых примитивов ABI совпадают — сразу 'std'.
        """
        self._ensure_method_state()

        from .imports import IMPORT_DLL
        if name not in IMPORT_DLL:
            IMPORT_DLL[name] = dll
        elif IMPORT_DLL[name] != dll:
            raise ValueError(
                f"ffi_export_method: '{name}' уже привязан к "
                f"'{IMPORT_DLL[name]}', а вы просите '{dll}'"
            )

        _check_export_exists(name, dll)

        self.used_imports.add(name)
        iat_rva = self.iat.get(name, 0)

        wrapper_name = "_" + (alias if alias else name)

        jmp_off = len(self.code)
        self.emit(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))

        body_off = len(self.code)
        next_rva = self.text_rva + len(self.code) + 6
        disp = iat_rva - next_rva
        self.emit(bytes([0xFF, 0x25]) + struct.pack("<i", disp))

        self.patch_i32(jmp_off + 1, 6)

        method_args = distribute_args(args)

        if ret_struct is not None:
            sret_kind = None
            if ret_struct is not None:
                sret_kind = _struct_return_kind(ret_struct)
            has_sret = (sret_kind == ('sret',))
            method_args = distribute_args(args, has_sret=has_sret)

            if has_sret:
                method_args = [
                                  MethodArg('rcx', ctypes.c_void_p, False,
                                            struct_cls=ret_struct,
                                            is_struct_pointer=True,
                                            struct_is_first=True),
                              ] + method_args

        method = Method(wrapper_name, method_args, ret,
                        self.text_rva + body_off,
                        ret_struct=ret_struct,
                        varargs=varargs,
                        n_fixed=len(args))
        self.method_registry.register(method)

        if ret_struct is not None:
            from .data import data_alloc
            ret_slot = "_ret_" + wrapper_name
            if ret_slot not in self.data_alloc:
                size = ctypes.sizeof(ret_struct)
                data_alloc(ret_slot, size, 0, type="bytes")

        return method

    def try_(self):
        return _TryCtx(self)

    def except_(self, filter_kind=EXCEPTION_EXECUTE_HANDLER):
        return _ExceptCtx(self, filter_kind)

    def finally_(self, body_fn=None):
        return _FinallyCtx(self, body_fn)

    def _after_end_method(self, method):
        if self._in_pending_filters:
            return
        self._emit_pending_filters()

    def _emit_pending_filters(self):
        if self._in_pending_filters:
            return
        self._in_pending_filters = True
        try:
            for pf in self._pending_filters:
                if pf['rva'] is not None:
                    continue
                kind = pf['kind']
                name = pf['name']

                saved = self._current_method
                self._current_method = None
                try:
                    self.start_method(name, [ctypes.c_void_p],
                                      ret_type=ctypes.c_int)
                    if isinstance(kind, int):
                        v = kind & 0xFFFFFFFF
                        self.emit(bytes([0xB8]) + struct.pack("<I", v))
                    else:
                        raise NotImplementedError(
                            "except_: фильтр-функция пока не поддерживается"
                        )
                    self.end_method()
                finally:
                    self._current_method = saved

                pf['rva'] = self.method_registry.get(name).rva
                for scope in pf['fixups']:
                    scope.handler_rva = pf['rva']
        finally:
            self._in_pending_filters = False

    def fld_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xD9, 0x05]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fstp_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xD9, 0x1D]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fst_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xD9, 0x15]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fadd_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x05]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fsub_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x25]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fmul_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x0D]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fdiv_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x35]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fild_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xDB, 0x05]) + struct.pack("<i", off - (self.rva_now() + 6)))
    def fistp_mem(self, name):
        off = self.rva_of(name)
        self.emit(bytes([0xDB, 0x1D]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def faddp_st1_st0(self):  self.emit(bytes([0xDE, 0xC1]))
    def fsubp_st1_st0(self):  self.emit(bytes([0xDE, 0xE9]))
    def fmulp_st1_st0(self):  self.emit(bytes([0xDE, 0xC9]))
    def fdivp_st1_st0(self):  self.emit(bytes([0xDE, 0xF9]))
    def fchs(self):           self.emit(bytes([0xD9, 0xE0]))
    def fabs(self):           self.emit(bytes([0xD9, 0xE1]))
    def fxch_st1(self):       self.emit(bytes([0xD9, 0xC9]))
    def fcomip_st0_st1(self): self.emit(bytes([0xDF, 0xF1]))
    def fldz(self):           self.emit(bytes([0xD9, 0xEE]))
    def fld1(self):           self.emit(bytes([0xD9, 0xE8]))
    def fstp_st0(self):       self.emit(bytes([0xDD, 0xD8]))

    def fld_dword_mem(self, name):
        """fld dword [name] — загрузить float32."""
        off = self.rva_of(name)
        self.emit(bytes([0xD9, 0x05]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fstp_dword_mem(self, name):
        """fstp dword [name] — сохранить float32."""
        off = self.rva_of(name)
        self.emit(bytes([0xD9, 0x1D]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fadd_dword_mem(self, name):
        """fadd dword [name] — st0 += [name]."""
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x05]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fsub_dword_mem(self, name):
        """fsub dword [name] — st0 -= [name]."""
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x25]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fmul_dword_mem(self, name):
        """fmul dword [name] — st0 *= [name]."""
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x0D]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fdiv_dword_mem(self, name):
        """fdiv dword [name] — st0 /= [name]."""
        off = self.rva_of(name)
        self.emit(bytes([0xD8, 0x35]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fcos(self):
        """fcos — st0 = cos(st0)."""
        self.emit(bytes([0xD9, 0xFF]))

    def fsin(self):
        """fsin — st0 = sin(st0)."""
        self.emit(bytes([0xD9, 0xFE]))

    def fldpi(self):
        """fldpi — st0 = pi."""
        self.emit(bytes([0xD9, 0xEB]))

    def fld_st0(self):
        """fld st0 — дублировать верхушку стека."""
        self.emit(bytes([0xD9, 0xC0]))

    def fld_1_0(self):
        """fld1 — st0 = 1.0."""
        self.emit(bytes([0xD9, 0xE8]))

    def fdivrp_st1_st0(self):
        """fdivrp st1, st0 — st1 = st0 / st1, pop."""
        self.emit(bytes([0xDE, 0xF1]))

    def fabs_(self):
        """fabs — st0 = |st0|."""
        self.emit(bytes([0xD9, 0xE1]))

    def fninit(self):
        """fninit — инициализация FPU."""
        self.emit(bytes([0xDB, 0xE3]))

    def fcomip_st1_st0(self):
        """fcomip st1, st0 — сравнить и вытолкнуть (другой порядок)."""
        self.emit(bytes([0xDF, 0xF1]))  

    def fild_dword_mem(self, name):
        """fild dword [name] — загрузить int32 → float."""
        off = self.rva_of(name)
        self.emit(bytes([0xDB, 0x05]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fistp_dword_mem(self, name):
        """fistp dword [name] — сохранить float → int32 (округление)."""
        off = self.rva_of(name)
        self.emit(bytes([0xDB, 0x1D]) + struct.pack("<i", off - (self.rva_now() + 6)))

    def fld_dword_mem_rva(self, rva):
        """fld dword [rva]."""
        self.emit(bytes([0xD9, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))

    def fstp_dword_mem_rva(self, rva):
        """fstp dword [rva]."""
        self.emit(bytes([0xD9, 0x1D]) + struct.pack("<i", rva - (self.rva_now() + 6)))

    def fmul_dword_mem_rva(self, rva):
        """fmul dword [rva]."""
        self.emit(bytes([0xD8, 0x0D]) + struct.pack("<i", rva - (self.rva_now() + 6)))

    def fadd_dword_mem_rva(self, rva):
        """fadd dword [rva]."""
        self.emit(bytes([0xD8, 0x05]) + struct.pack("<i", rva - (self.rva_now() + 6)))

class GUIContext(Context):
    def __init__(self, code, text_rva, iat, data_rva, text_buf_off,
                 empty_str_rva, string_rvas, window, data_alloc,
                 used_imports=None, method_registry=None):
        super().__init__(code, text_rva, iat, data_rva, data_alloc,
                         used_imports=used_imports,
                         method_registry=method_registry)
        self.text_buf_off = text_buf_off
        self.empty_str_rva = empty_str_rva
        self.string_rvas = string_rvas
        self.window = window
        self.create_window = None

    def _hwnd_rva(self):
        return self.data_rva + self.window.hwnd_off

    def hwnd_rva_of(self, win):
        return self.data_rva + win.hwnd_off

    def set_text_buf(self, widget, buf):
        off = self._resolve_buf(buf)
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.lea_rip(2, self.data_rva + off)
        self.call_iat("SetWindowTextA")

    def set_clear_text(self, widget):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.lea_rip(2, self.empty_str_rva)
        self.call_iat("SetWindowTextA")

    def get_text(self, widget, buf, size):
        off = self._resolve_buf(buf)
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.lea_rip(2, self.data_rva + off)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", size))
        self.call_iat("GetWindowTextA")

    def set_text_rva(self, widget, str_rva):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.lea_rip(2, str_rva)
        self.call_iat("SetWindowTextA")

    def get_text_rva(self, widget, buf_rva, size):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.lea_rip(2, buf_rva)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", size & 0xFFFFFFFF))
        self.call_iat("GetWindowTextA")

    def set_widget_text_rva(self, widget, str_rva):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.lea_rip(2, str_rva)
        self.call_iat("SetWindowTextA")

    def set_widget_text_str(self, widget, name):
        self.set_widget_text_rva(widget, self.string_rvas[name])

    def redraw(self):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.emit(bytes([0x31, 0xD2]))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", 0x0185))
        self.call_iat("RedrawWindow")

    def get_client_rect(self, rect_name):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.lea_rip(2, self._data_rva(rect_name))
        self.call_iat("GetClientRect")

    def begin_update(self):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.emit(bytes([0xBA]) + struct.pack("<I", 0x000B))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def end_update(self):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.emit(bytes([0xBA]) + struct.pack("<I", 0x000B))
        self.emit(bytes([0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def set_timer(self, id_val, ms, hwnd_win=None):
        if hwnd_win is None:
            self.mov_reg_rva(1, self._hwnd_rva())
        else:
            self.mov_reg_rva(1, self.hwnd_rva_of(hwnd_win))
        self.emit(bytes([0xBA]) + struct.pack("<I", id_val))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", ms))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SetTimer")

    def kill_timer(self, id_val, hwnd_win=None):
        if hwnd_win is None:
            self.mov_reg_rva(1, self._hwnd_rva())
        else:
            self.mov_reg_rva(1, self.hwnd_rva_of(hwnd_win))
        self.emit(bytes([0xBA]) + struct.pack("<I", id_val))
        self.call_iat("KillTimer")

    def move_window_widget(self, widget, x, y, w, h, repaint=1):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", x & 0xFFFFFFFF))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", y & 0xFFFFFFFF))
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", w & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + struct.pack("<I", h & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28]) + struct.pack("<I", repaint & 0xFFFFFFFF))
        self.call_iat("MoveWindow")

    def move_window_widget_rva(self, widget, x_rva, y_rva, w, h, repaint=1):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.mov_edx_rva(x_rva)
        self.mov_r8d_rva(y_rva)
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", w & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + struct.pack("<I", h & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28]) + struct.pack("<I", repaint & 0xFFFFFFFF))
        self.call_iat("MoveWindow")

    def move_window(self, win, x, y, w, h, repaint=1):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.emit(bytes([0xBA]) + struct.pack("<I", x & 0xFFFFFFFF))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", y & 0xFFFFFFFF))
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", w & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + struct.pack("<I", h & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28]) + struct.pack("<I", repaint & 0xFFFFFFFF))
        self.call_iat("MoveWindow")

    def move_window_rva(self, win, x_rva, y_rva, w, h, repaint=1):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.mov_edx_rva(x_rva)
        self.mov_r8d_rva(y_rva)
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", w & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + struct.pack("<I", h & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28]) + struct.pack("<I", repaint & 0xFFFFFFFF))
        self.call_iat("MoveWindow")

    def move_widget(self, widget, x, y, w, h):
        self.move_window_widget(widget, x, y, w, h)

    def show_window(self, win, show=SW_SHOW):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.emit(bytes([0xBA]) + struct.pack("<I", show & 0xFFFFFFFF))
        self.call_iat("ShowWindow")

    def destroy_window(self, win):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.call_iat("DestroyWindow")

    def enable_window(self, win, enable=True):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.emit(bytes([0xBA]) + struct.pack("<I", 1 if enable else 0))
        self.call_iat("EnableWindow")

    def set_window_title_rva(self, win, str_rva):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.lea_rip(2, str_rva)
        self.call_iat("SetWindowTextA")

    def set_window_title_str(self, win, name):
        self.set_window_title_rva(win, self.string_rvas[name])

    def get_window_title(self, win, buf_rva, size):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.lea_rip(2, buf_rva)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", size & 0xFFFFFFFF))
        self.call_iat("GetWindowTextA")

    def is_window_visible(self, win):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.call_iat("IsWindowVisible")

    def set_foreground(self, win):
        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.call_iat("SetForegroundWindow")

    def show_widget(self, widget, show=SW_SHOW):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", show & 0xFFFFFFFF))
        self.call_iat("ShowWindow")

    def enable_widget(self, widget, enable=True):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", 1 if enable else 0))
        self.call_iat("EnableWindow")

    def set_focus_widget(self, widget):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.call_iat("SetFocus")

    def message_box(self, text_rva, caption_rva, flags=0):
        self.emit(bytes([0x31, 0xC9]))
        self.lea_rip(2, text_rva)
        self.lea_rip(8, caption_rva)
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", flags & 0xFFFFFFFF))
        self.call_iat("MessageBoxA")

    def message_box_str(self, text_name, caption_name=None, flags=0):
        text_rva = self.string_rvas[text_name]
        if caption_name is None:
            caption_rva = self.empty_str_rva
        else:
            caption_rva = self.string_rvas[caption_name]
        self.message_box(text_rva, caption_rva, flags)

    def message_box_widget_text(self, widget, caption_name=None, flags=0):
        self.get_text(widget, self.text_buf_off, 256)
        if caption_name is None:
            caption_rva = self.empty_str_rva
        else:
            caption_rva = self.string_rvas[caption_name]
        self.message_box(self.data_rva + self.text_buf_off, caption_rva, flags)

    def message_box_fmt_int(self, fmt_name, caption_name, flags, value_rva):
        self.lea_rip(1, self.data_rva + self.text_buf_off)
        self.lea_rip(2, self.string_rvas[fmt_name])
        self.mov_r8d_rva(value_rva)
        self.emit(bytes([0x31, 0xC0]))
        self.call_iat("wsprintfA")
        cap_rva = self.string_rvas.get(caption_name, self.empty_str_rva) \
            if caption_name else self.empty_str_rva
        self.message_box(self.data_rva + self.text_buf_off, cap_rva, flags)

    def center_window(self, win):
        self.emit(bytes([0xB9]) + struct.pack("<I", SM_CXSCREEN))
        self.call_iat("GetSystemMetrics")
        self.sub_eax_imm32(win.w)
        self.shr_eax_1()
        self.store_eax_rva(self.rva_of("_center_x"))
        self.emit(bytes([0xB9]) + struct.pack("<I", SM_CYSCREEN))
        self.call_iat("GetSystemMetrics")
        self.sub_eax_imm32(win.h)
        self.shr_eax_1()
        self.store_eax_rva(self.rva_of("_center_y"))
        self.move_window_rva(win,
                             self.rva_of("_center_x"),
                             self.rva_of("_center_y"),
                             win.w, win.h)

    def get_client_size(self, rect_name, out_w_rva, out_h_rva):
        self.get_client_rect(rect_name)
        rect_rva = self._data_rva(rect_name)
        self.mov_eax_rva(rect_rva + 8)
        self.sub_eax_rva(rect_rva + 0)
        self.store_eax_rva(out_w_rva)
        self.mov_eax_rva(rect_rva + 12)
        self.sub_eax_rva(rect_rva + 4)
        self.store_eax_rva(out_h_rva)

    def sleep(self, ms):
        self.emit(bytes([0xB9]) + struct.pack("<I", ms & 0xFFFFFFFF))
        self.call_iat("Sleep")

    def get_tick_count(self):
        self.call_iat("GetTickCount")

    def beep(self, freq, dur):
        self.emit(bytes([0xB9]) + struct.pack("<I", freq & 0xFFFFFFFF))
        self.emit(bytes([0xBA]) + struct.pack("<I", dur & 0xFFFFFFFF))
        self.call_iat("Beep")

    def set_window_icon(self, win, icon_path_rva):
        self.emit(bytes([0x31, 0xC9]))
        self.lea_rip(2, icon_path_rva)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", IMAGE_ICON))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28])
                  + struct.pack("<I", LR_LOADFROMFILE | LR_DEFAULTSIZE))
        self.call_iat("LoadImageA")

        self.emit(bytes([0x48, 0x85, 0xC0]))
        jz_fail = self.jcc(0x84)

        self.mov_mem_reg(self.rva_of("_hicon"), 0)

        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.emit(bytes([0xBA]) + struct.pack("<I", WM_SETICON))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", ICON_BIG))
        self.mov_reg_rva(9, self.rva_of("_hicon"))
        self.call_iat("SendMessageA")

        self.mov_reg_rva(1, self.hwnd_rva_of(win))
        self.emit(bytes([0xBA]) + struct.pack("<I", WM_SETICON))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", ICON_SMALL))
        self.mov_reg_rva(9, self.rva_of("_hicon"))
        self.call_iat("SendMessageA")

        self.patch_here(jz_fail)

    def open_file_dialog(self, ofn_rva, **kwargs):
        self.mov_reg_rva(0, self._hwnd_rva())
        self.mov_mem_reg(ofn_rva + 0x08, 0)
        self.lea_rip(1, ofn_rva)
        self.call_iat("GetOpenFileNameA")

    def save_file_dialog(self, ofn_rva, **kwargs):
        self.mov_reg_rva(0, self._hwnd_rva())
        self.mov_mem_reg(ofn_rva + 0x08, 0)
        self.lea_rip(1, ofn_rva)
        self.call_iat("GetSaveFileNameA")

    def create_file(self, path_rva, access, share, creation):
        self.emit(bytes([0x31, 0xC9]))
        self.lea_rip(1, path_rva)
        self.emit(bytes([0xBA]) + struct.pack("<I", access & 0xFFFFFFFF))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", share & 0xFFFFFFFF))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20])
                  + struct.pack("<I", creation & 0xFFFFFFFF))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00]))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00]))
        self.call_iat("CreateFileA")

    def read_file(self, handle_rva, buf_rva, size):
        self.mov_reg_rva(1, handle_rva)
        self.lea_rip(2, buf_rva)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", size & 0xFFFFFFFF))
        self.emit(bytes([0x4C, 0x8D, 0x4C, 0x24, 0x30]))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]))
        self.call_iat("ReadFile")

    def write_file(self, handle_rva, buf_rva, size):
        self.mov_reg_rva(1, handle_rva)
        self.lea_rip(2, buf_rva)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", size & 0xFFFFFFFF))
        self.emit(bytes([0x4C, 0x8D, 0x4C, 0x24, 0x30]))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]))
        self.call_iat("WriteFile")

    def close_handle(self, handle_rva):
        self.mov_reg_rva(1, handle_rva)
        self.call_iat("CloseHandle")

    def checkbox_is_checked(self, widget):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", BM_GETCHECK))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def listbox_add_str(self, widget, str_name):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", LB_ADDSTRING))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.lea_rip(9, self.string_rvas[str_name])
        self.call_iat("SendMessageA")

    def listbox_get_sel(self, widget):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", LB_GETCURSEL))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def combobox_add_str(self, widget, str_name):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", CB_ADDSTRING))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.lea_rip(9, self.string_rvas[str_name])
        self.call_iat("SendMessageA")

    def combobox_get_sel(self, widget):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", CB_GETCURSEL))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def progressbar_set_pos(self, widget, pos):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", PBM_SETPOS))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", pos & 0xFFFFFFFF))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def progressbar_set_range(self, widget, low, high):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", PBM_SETRANGE32))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", low & 0xFFFFFFFF))
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", high & 0xFFFFFFFF))
        self.call_iat("SendMessageA")

    def progressbar_get_pos(self, widget):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", PBM_GETPOS))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def trackbar_set_range(self, widget, low, high):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", TBM_SETRANGE))
        self.emit(bytes([0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]))
        lparam = (low & 0xFFFF) | ((high & 0xFFFF) << 16)
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", lparam))
        self.call_iat("SendMessageA")

    def trackbar_set_pos(self, widget, pos):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", TBM_SETPOS))
        self.emit(bytes([0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]))
        self.emit(bytes([0x41, 0xB9]) + struct.pack("<I", pos & 0xFFFFFFFF))
        self.call_iat("SendMessageA")

    def trackbar_get_pos(self, widget):
        self.mov_reg_rva(1, self.data_rva + widget.data_off)
        self.emit(bytes([0xBA]) + struct.pack("<I", TBM_GETPOS))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x45, 0x31, 0xC9]))
        self.call_iat("SendMessageA")

    def invalidate(self):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.emit(bytes([0x31, 0xD2]))
        self.emit(bytes([0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]))
        self.call_iat("InvalidateRect")

class ConsoleContext(Context):
    def __init__(self, code, text_rva, iat, data_rva, data_alloc,
                 stdout_rva, stdin_rva, buf_rva,
                 written_rva=0, read_rva=0, scratch_rva=0,
                 string_rvas=None, strings=None,
                 used_imports=None, method_registry=None):
        super().__init__(code, text_rva, iat, data_rva, data_alloc,
                         used_imports=used_imports,
                         method_registry=method_registry)
        self.stdout_rva  = stdout_rva
        self.stdin_rva   = stdin_rva
        self.buf_rva     = buf_rva
        self.written_rva = written_rva
        self.read_rva    = read_rva
        self.scratch_rva = scratch_rva
        self.string_rvas = string_rvas or {}
        self.strings     = strings or {}

    def write(self, buf_rva, size, handle_rva=None):
        """WriteFile(handle, buf, size, &written, NULL)."""
        if handle_rva is None:
            handle_rva = self.stdout_rva
        self.mov_reg_rva(1, handle_rva)
        self.lea_rip(2, buf_rva)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", size & 0xFFFFFFFF))
        if self.written_rva:
            self.lea_rip(9, self.written_rva)
        else:
            self.emit(bytes([0x4C, 0x8D, 0x4C, 0x24, 0x30]))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]))
        self.call_iat("WriteFile")

    def read(self, buf_rva, size, handle_rva=None):
        """ReadFile(handle, buf, size, &read, NULL)."""
        if handle_rva is None:
            handle_rva = self.stdin_rva
        self.mov_reg_rva(1, handle_rva)
        self.lea_rip(2, buf_rva)
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", size & 0xFFFFFFFF))
        if self.read_rva:
            self.lea_rip(9, self.read_rva)
        else:
            self.emit(bytes([0x4C, 0x8D, 0x4C, 0x24, 0x38]))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]))
        self.call_iat("ReadFile")

    def write_counted(self, buf_rva, count_rva=None, handle_rva=None):
        """WriteFile(handle, buf, [count_rva], &written, NULL)."""
        if handle_rva is None:
            handle_rva = self.stdout_rva
        if count_rva is None:
            count_rva = self.read_rva
        self.mov_reg_rva(1, handle_rva)
        self.lea_rip(2, buf_rva)
        self.mov_r8d_rva(count_rva)
        if self.written_rva:
            self.lea_rip(9, self.written_rva)
        else:
            self.emit(bytes([0x4C, 0x8D, 0x4C, 0x24, 0x30]))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]))
        self.call_iat("WriteFile")

    def write_str(self, str_name, handle_rva=None):
        """WriteFile(handle, str, len(str), &written, NULL)."""
        s = self.strings[str_name]
        size = len(s.encode("ascii"))
        self.write(self.string_rvas[str_name], size, handle_rva)

    def writeln_str(self, str_name, handle_rva=None):
        """write_str + "\\r\\n"."""
        self.write_str(str_name, handle_rva)
        self.write_str("_crlf", handle_rva)

    def writeln(self, handle_rva=None):
        """Только "\\r\\n"."""
        self.write_str("_crlf", handle_rva)

    def print_fmt(self, fmt_name, value_rva, handle_rva=None):
        if handle_rva is None:
            handle_rva = self.stdout_rva

        self.lea_rip(1, self.buf_rva)
        self.lea_rip(2, self.string_rvas[fmt_name])
        if value_rva is not None:
            self.mov_r8d_rva(value_rva)             
            self.mov_reg_rva(9, value_rva)          
        else:
            self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x31, 0xC0]))
        self.call_iat("wsprintfA")

        self.store_eax_rva(self.scratch_rva)

        self.mov_reg_rva(1, handle_rva)
        self.lea_rip(2, self.buf_rva)
        self.mov_r8d_rva(self.scratch_rva)
        if self.written_rva:
            self.lea_rip(9, self.written_rva)
        else:
            self.emit(bytes([0x4C, 0x8D, 0x4C, 0x24, 0x30]))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]))
        self.call_iat("WriteFile")

    def print_int(self, value_rva, handle_rva=None):
        """print_fmt с fmt = "_fmt_d" ("%d")."""
        self.print_fmt("_fmt_d", value_rva, handle_rva)

    def write_int(self, value_rva, handle_rva=None):
        """Алиас для print_int."""
        self.print_int(value_rva, handle_rva)

    def read_into(self, buf_rva, size, handle_rva=None):
        """ReadFile + null-терминатор по индексу read_count."""
        self.read(buf_rva, size, handle_rva)
        self.mov_eax_rva(self.read_rva)
        self.lea_rip(1, buf_rva)
        self.emit(bytes([0x48, 0x89, 0xC2]))            
        self.emit(bytes([0xC6, 0x04, 0x11, 0x00]))      

    def read_str(self, buf_rva=None, size=None, handle_rva=None):
        """ReadFile в buf + null-терминатор."""
        if buf_rva is None:
            buf_rva = self.buf_rva
        if size is None:
            size = 255
        self.read_into(buf_rva, size, handle_rva)

    def read_line(self, buf_rva=None, size=None, handle_rva=None):
        """read_str + обрезка одного "\\n" и одного "\\r" в конце.

        После вызова read_count уменьшается на число обрезанных байт.
        """
        if buf_rva is None:
            buf_rva = self.buf_rva
        if size is None:
            size = 255
        self.read_into(buf_rva, size, handle_rva)

        self.lea_rip(2, buf_rva)

        self.mov_ecx_rva(self.read_rva)

        self.emit(bytes([0x85, 0xC9]))                  
        jz_skip = self.jcc(0x84)

        self.emit(bytes([0x8A, 0x44, 0x0A, 0xFF]))      
        self.emit(bytes([0x3C, 0x0A]))                  
        jne_lf = self.jcc(0x85)

        self.emit(bytes([0xC6, 0x44, 0x0A, 0xFF, 0x00]))
        self.emit(bytes([0x48, 0xFF, 0xC9]))            
        self.patch_here(jne_lf)

        self.emit(bytes([0x85, 0xC9]))
        jz_skip2 = self.jcc(0x84)

        self.emit(bytes([0x8A, 0x44, 0x0A, 0xFF]))      
        self.emit(bytes([0x3C, 0x0D]))                  
        jne_cr = self.jcc(0x85)
        self.emit(bytes([0xC6, 0x44, 0x0A, 0xFF, 0x00]))
        self.emit(bytes([0x48, 0xFF, 0xC9]))            
        self.patch_here(jne_cr)

        self.emit(bytes([0x89, 0x0D]) + struct.pack(
            "<i", self.read_rva - (self.rva_now() + 6)))

        self.patch_here(jz_skip)
        self.patch_here(jz_skip2)

    def echo(self, buf_rva=None, size=None):
        """read_str + write_counted (с \\r\\n из ввода)."""
        if buf_rva is None:
            buf_rva = self.buf_rva
        if size is None:
            size = 255
        self.read_into(buf_rva, size)
        self.write_counted(buf_rva)

    def echo_line(self, buf_rva=None, size=None):
        """read_line + write_counted (без \\r\\n из ввода)."""
        if buf_rva is None:
            buf_rva = self.buf_rva
        if size is None:
            size = 255
        self.read_line(buf_rva, size)
        self.write_counted(buf_rva)

    def exit(self, code=0):
        self.emit(bytes([0xB9]) + struct.pack("<I", code & 0xFFFFFFFF))
        self.call_iat("ExitProcess")

class GDIContext(Context):
    def __init__(self, code, text_rva, iat, data_rva, data_alloc,
                 hdc_rva, ps_rva, window,
                 hbrush_rva=0, hbrush_old_rva=0,
                 hpen_rva=0, hpen_old_rva=0,
                 hfont_rva=0, hfont_old_rva=0,
                 target_rva=None,
                 string_rvas=None,
                 wstring_rvas=None,
                 used_imports=None,
                 method_registry=None):
        super().__init__(code, text_rva, iat, data_rva, data_alloc,
                         used_imports=used_imports,
                         method_registry=method_registry)
        self.hdc_rva        = hdc_rva
        self.target_rva     = target_rva if target_rva is not None else hdc_rva
        self.ps_rva         = ps_rva
        self.window         = window
        self.hbrush_rva     = hbrush_rva
        self.hbrush_old_rva = hbrush_old_rva
        self.hpen_rva       = hpen_rva
        self.hpen_old_rva   = hpen_old_rva
        self.hfont_rva      = hfont_rva
        self.hfont_old_rva  = hfont_old_rva
        self.string_rvas    = string_rvas or {}
        self.wstring_rvas   = wstring_rvas or {}

    def _hwnd_rva(self):
        return self.data_rva + self.window.hwnd_off

    def begin_paint(self):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.lea_rip(2, self.ps_rva)
        self.call_iat("BeginPaint")
        self.store_rax_rva(self.hdc_rva)

    def end_paint(self):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.lea_rip(2, self.ps_rva)
        self.call_iat("EndPaint")

    def begin_buffer(self, hmemdc_rva, hbmp_rva, hbmp_old_rva, rect_rva):
        """Создать memdc и битмап, выбрать bitmap, target_rva := memdc.

        GetClientRect(hwnd, &rect) → right, bottom.
        hmemdc = CreateCompatibleDC(hdc)
        hbmp = CreateCompatibleBitmap(hdc, right, bottom)
        hbmp_old = SelectObject(hmemdc, hbmp)
        [hmemdc_rva] = hmemdc
        target_rva := hmemdc_rva (рисование идёт в memdc)
        """

        self.mov_reg_rva(1, self._hwnd_rva())
        self.lea_rip(2, rect_rva)
        self.call_iat("GetClientRect")

        self.mov_reg_rva(1, self.hdc_rva)
        self.call_iat("CreateCompatibleDC")
        self.store_rax_rva(hmemdc_rva)

        self.mov_reg_rva(1, self.hdc_rva)
        self.mov_edx_rva(rect_rva + 8)      
        self.mov_r8d_rva(rect_rva + 12)     
        self.call_iat("CreateCompatibleBitmap")
        self.store_rax_rva(hbmp_rva)

        self.mov_reg_rva(1, hmemdc_rva)
        self.mov_reg_rva(2, hbmp_rva)
        self.call_iat("SelectObject")
        self.store_rax_rva(hbmp_old_rva)

        self.target_rva = hmemdc_rva

    def present(self, hmemdc_rva, hbmp_rva, hbmp_old_rva, rect_rva):
        """BitBlt(hdc, 0, 0, right, bottom, hmemdc, 0, 0, SRCCOPY).

        Затем — восстановление: SelectObject(hmemdc, hbmp_old),
        DeleteObject(hbmp), DeleteDC(hmemdc).
        """

        self.mov_reg_rva(1, self.hdc_rva)               
        self.emit(bytes([0x31, 0xD2]))                  
        self.emit(bytes([0x45, 0x31, 0xC0]))            
        self.mov_reg_rva(9, rect_rva + 8)               

        self.mov_eax_rva(rect_rva + 12)
        self.emit(bytes([0x89, 0x44, 0x24, 0x20]))

        self.mov_rax_rva(hmemdc_rva)
        self.emit(bytes([0x48, 0x89, 0x44, 0x24, 0x28]))

        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x30, 0, 0, 0, 0]))

        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x38, 0, 0, 0, 0]))

        self.emit(bytes([0xC7, 0x44, 0x24, 0x40])
                  + struct.pack("<I", 0x00CC0020))

        self.call_iat("BitBlt")

        self.mov_reg_rva(1, hmemdc_rva)
        self.mov_reg_rva(2, hbmp_old_rva)
        self.call_iat("SelectObject")

        self.mov_reg_rva(1, hbmp_rva)
        self.call_iat("DeleteObject")

        self.mov_reg_rva(1, hmemdc_rva)
        self.call_iat("DeleteDC")

        self.target_rva = self.hdc_rva

    def _to_colorref(self, color):
        """(r,g,b) или int 0xRRGGBB → COLORREF (0x00BBGGRR)."""
        if isinstance(color, tuple):
            if len(color) != 3:
                raise ValueError(f"цвет: ожидалось (r,g,b), получено {color!r}")
            r, g, b = color
            if not (0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255):
                raise ValueError(f"цвет: значения 0..255, получено {color!r}")
            return (b << 16) | (g << 8) | r
        if isinstance(color, int):

            r = (color >> 16) & 0xFF
            g = (color >> 8) & 0xFF
            b = color & 0xFF
            return (b << 16) | (g << 8) | r
        raise ValueError(f"цвет: неизвестный формат {color!r}")

    def set_brush(self, color):
        color = self._to_colorref(color)
        self.emit(bytes([0xB9]) + struct.pack("<I", color & 0xFFFFFFFF))
        self.call_iat("CreateSolidBrush")
        self.store_rax_rva(self.hbrush_rva)
        self.mov_reg_rva(1, self.target_rva)     
        self.mov_reg_rva(2, self.hbrush_rva)
        self.call_iat("SelectObject")
        self.store_rax_rva(self.hbrush_old_rva)

    def restore_brush(self):
        self.mov_reg_rva(1, self.target_rva)     
        self.mov_reg_rva(2, self.hbrush_old_rva)
        self.call_iat("SelectObject")
        self.mov_reg_rva(1, self.hbrush_rva)
        self.call_iat("DeleteObject")

    def set_pen(self, color, width=1):
        color = self._to_colorref(color)
        self.emit(bytes([0x31, 0xC9]))
        self.emit(bytes([0xBA]) + struct.pack("<I", width & 0xFFFFFFFF))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", color & 0xFFFFFFFF))
        self.call_iat("CreatePen")
        self.store_rax_rva(self.hpen_rva)
        self.mov_reg_rva(1, self.target_rva)     
        self.mov_reg_rva(2, self.hpen_rva)
        self.call_iat("SelectObject")
        self.store_rax_rva(self.hpen_old_rva)

    def restore_pen(self):
        self.mov_reg_rva(1, self.target_rva)     
        self.mov_reg_rva(2, self.hpen_old_rva)
        self.call_iat("SelectObject")
        self.mov_reg_rva(1, self.hpen_rva)
        self.call_iat("DeleteObject")

    def enable_advanced_graphics(self):
        """SetGraphicsMode(target, GM_ADVANCED=2)."""
        self.mov_reg_rva(1, self.target_rva)
        self.emit(bytes([0xBA]) + struct.pack("<I", 2))
        self.call_iat("SetGraphicsMode")

    def push_rotation(self, cos, sin, edx, edy, stack_off=0x20):
        """XFORM на стеке из готовых cos/sin/edx/edy (float)."""

        def _f(v):
            return struct.pack("<I", self._f32_bits(v))

        self.emit(bytes([0xC7, 0x44, 0x24, stack_off + 0x00]) + _f(cos))  
        self.emit(bytes([0xC7, 0x44, 0x24, stack_off + 0x04]) + _f(sin))  
        self.emit(bytes([0xC7, 0x44, 0x24, stack_off + 0x08]) + _f(-sin))  
        self.emit(bytes([0xC7, 0x44, 0x24, stack_off + 0x0C]) + _f(cos))  
        self.emit(bytes([0xC7, 0x44, 0x24, stack_off + 0x10]) + _f(edx))  
        self.emit(bytes([0xC7, 0x44, 0x24, stack_off + 0x14]) + _f(edy))  

        self.mov_reg_rva(1, self.target_rva)
        self.emit(bytes([0x48, 0x8D, 0x54, 0x24, stack_off]))
        self.call_iat("SetWorldTransform")

    def pop_rotation(self):
        """SetWorldTransform(target, &identity)."""
        def _f(v):
            return struct.pack("<I", self._f32_bits(v))

        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + _f(1.0))     
        self.emit(bytes([0xC7, 0x44, 0x24, 0x24]) + _f(0.0))     
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28]) + _f(0.0))     
        self.emit(bytes([0xC7, 0x44, 0x24, 0x2C]) + _f(1.0))     
        self.emit(bytes([0xC7, 0x44, 0x24, 0x30]) + _f(0.0))     
        self.emit(bytes([0xC7, 0x44, 0x24, 0x34]) + _f(0.0))     

        self.mov_reg_rva(1, self.target_rva)
        self.emit(bytes([0x48, 0x8D, 0x54, 0x24, 0x20]))
        self.call_iat("SetWorldTransform")

    def push_rotation_dynamic_pivot(self, angle_rva, k_rva, cos_rva, sin_rva,
                                    px, py, stack_off=0x20):
        self.compute_cos_sin(angle_rva, k_rva, cos_rva, sin_rva)
        self.apply_xform_from_cos_sin(cos_rva, sin_rva, px, py, stack_off)

    def image_load_dib_from_resource(self, res_id, himg_key,
                                     hdc_rva=None,
                                     img_w_key="_img_w",
                                     img_h_key="_img_h"):
        """Загрузить DIB-блоб из RT_RCDATA в 32bpp HBITMAP через CreateDIBSection."""
        if hdc_rva is None:
            hdc_rva = self.target_rva

        self.mov_rax_mem(himg_key)
        self.emit(bytes([0x48, 0x85, 0xC0]))
        jnz_skip = self.jcc(0x85)

        self.mov_rax_rva(hdc_rva)
        self.emit(bytes([0x48, 0x85, 0xC0]))
        jz_no_hdc = self.jcc(0x84)

        hinst_rva = self.data_rva + DATA_OFF_HINST

        self.mov_reg_rva(1, hinst_rva)
        self.emit(bytes([0xBA]) + struct.pack("<I", res_id))
        self.emit(bytes([0x41, 0xB8]) + struct.pack("<I", 10))
        self.call_iat("FindResourceA")
        self.store_rax_mem("_res_hrsrc")

        self.emit(bytes([0x48, 0x85, 0xC0]))
        jz_no_res = self.jcc(0x84)

        self.mov_reg_rva(1, hinst_rva)
        self.mov_reg_rva(2, self.rva_of("_res_hrsrc"))
        self.call_iat("LoadResource")
        self.emit(bytes([0x48, 0x89, 0xC1]))
        self.call_iat("LockResource")
        self.store_rax_mem("_res_ptr")

        self.emit(bytes([0x48, 0x85, 0xC0]))
        jz_no_ptr = self.jcc(0x84)

        self.mov_rax_mem("_res_ptr")
        self.emit(bytes([0x8B, 0x08]))  
        self.store_ecx_mem(img_w_key)
        self.emit(bytes([0x8B, 0x48, 0x04]))  
        self.store_ecx_mem(img_h_key)

        self.emit(bytes([0xC7, 0x44, 0x24, 0x40, 40, 0, 0, 0]))
        self.mov_eax_mem(img_w_key)
        self.emit(bytes([0x89, 0x44, 0x24, 0x44]))
        self.mov_eax_mem(img_h_key)
        self.emit(bytes([0xF7, 0xD8]))  
        self.emit(bytes([0x89, 0x44, 0x24, 0x48]))
        self.emit(bytes([0x66, 0xC7, 0x44, 0x24, 0x4C, 0x01, 0x00]))
        self.emit(bytes([0x66, 0xC7, 0x44, 0x24, 0x4E, 0x20, 0x00]))
        for off in (0x50, 0x54, 0x58, 0x5C, 0x60, 0x64):
            self.emit(bytes([0xC7, 0x44, 0x24, off, 0, 0, 0, 0]))

        self.mov_reg_rva(1, hdc_rva)
        self.emit(bytes([0x48, 0x8D, 0x54, 0x24, 0x40]))  
        self.emit(bytes([0x45, 0x31, 0xC0]))  
        self.emit(bytes([0x4C, 0x8D, 0x4C, 0x24, 0x38]))  
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]))  
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]))  
        self.call_iat("CreateDIBSection")
        self.store_rax_mem(himg_key)

        self.emit(bytes([0x48, 0x85, 0xC0]))
        jz_no_bmp = self.jcc(0x84)

        self.mov_eax_mem(img_w_key)  
        self.mov_edx_mem(img_h_key)  
        self.emit(bytes([0x0F, 0xAF, 0xC2]))  
        self.emit(bytes([0xC1, 0xE0, 0x02]))  
        self.emit(bytes([0x41, 0x89, 0xC0]))  

        self.emit(bytes([0x48, 0x8B, 0x4C, 0x24, 0x38]))  

        self.mov_rax_mem("_res_ptr")
        self.emit(bytes([0x48, 0x8D, 0x50, 0x08]))  

        self.call_iat("RtlMoveMemory")

        jmp_done = self.jmp_placeholder()
        self.patch_here(jz_no_hdc)
        self.patch_here(jz_no_res)
        self.patch_here(jz_no_ptr)
        self.patch_here(jz_no_bmp)
        self.patch_jmp_here(jmp_done)

        self.patch_here(jnz_skip)

    def _bitblt(self, dst_rva, dst_x, dst_y, w, h,
                src_rva, src_x, src_y, rop):
        """BitBlt(dst, dst_x, dst_y, w, h, src, src_x, src_y, rop)."""
        self.mov_reg_rva(1, dst_rva)
        self.emit(bytes([0xBA]) + self.i32(dst_x))
        self.emit(bytes([0x41, 0xB8]) + self.i32(dst_y))
        self.emit(bytes([0x41, 0xB9]) + self.i32(w))

        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + self.i32(h))

        self.mov_rax_rva(src_rva)
        self.emit(bytes([0x48, 0x89, 0x44, 0x24, 0x28]))

        self.emit(bytes([0xC7, 0x44, 0x24, 0x30]) + self.i32(src_x))

        self.emit(bytes([0xC7, 0x44, 0x24, 0x38]) + self.i32(src_y))

        self.emit(bytes([0xC7, 0x44, 0x24, 0x40]) + struct.pack("<I", rop))
        self.call_iat("BitBlt")

    def image_free_sprite(self,
                          himg_key,
                          mask_dc_key, mask_bmp_key, mask_old_key,
                          mask_inv_dc_key, mask_inv_bmp_key, mask_inv_old_key,
                          sprite_dc_key, sprite_bmp_key, sprite_old_key):

        self.mov_reg_rva(1, self.rva_of(mask_dc_key))
        self.mov_reg_rva(2, self.rva_of(mask_old_key))
        self.call_iat("SelectObject")
        self.mov_reg_rva(1, self.rva_of(mask_bmp_key))
        self.call_iat("DeleteObject")
        self.mov_reg_rva(1, self.rva_of(mask_dc_key))
        self.call_iat("DeleteDC")
        self.store_qword_imm_mem(mask_dc_key, 0)
        self.store_qword_imm_mem(mask_bmp_key, 0)
        self.store_qword_imm_mem(mask_old_key, 0)

        self.mov_reg_rva(1, self.rva_of(mask_inv_dc_key))
        self.mov_reg_rva(2, self.rva_of(mask_inv_old_key))
        self.call_iat("SelectObject")
        self.mov_reg_rva(1, self.rva_of(mask_inv_bmp_key))
        self.call_iat("DeleteObject")
        self.mov_reg_rva(1, self.rva_of(mask_inv_dc_key))
        self.call_iat("DeleteDC")
        self.store_qword_imm_mem(mask_inv_dc_key, 0)
        self.store_qword_imm_mem(mask_inv_bmp_key, 0)
        self.store_qword_imm_mem(mask_inv_old_key, 0)

        self.mov_reg_rva(1, self.rva_of(sprite_dc_key))
        self.mov_reg_rva(2, self.rva_of(sprite_old_key))
        self.call_iat("SelectObject")
        self.mov_reg_rva(1, self.rva_of(sprite_bmp_key))
        self.call_iat("DeleteObject")
        self.mov_reg_rva(1, self.rva_of(sprite_dc_key))
        self.call_iat("DeleteDC")
        self.store_qword_imm_mem(sprite_dc_key, 0)
        self.store_qword_imm_mem(sprite_bmp_key, 0)
        self.store_qword_imm_mem(sprite_old_key, 0)

        self.mov_reg_rva(1, self.rva_of(himg_key))
        self.call_iat("DeleteObject")
        self.store_qword_imm_mem(himg_key, 0)

    def image_draw_sprite(self, sprite_dc_key, mask_dc_key,
                          src_w, src_h, dst_x, dst_y, dst_w, dst_h):

        self._bitblt(self.target_rva, dst_x, dst_y, dst_w, dst_h,
                     self.rva_of(mask_dc_key), 0, 0, 0x008800C6)  

        self._bitblt(self.target_rva, dst_x, dst_y, dst_w, dst_h,
                     self.rva_of(sprite_dc_key), 0, 0, 0x00EE0086)  

    def image_build_sprite(self, shape, w, h, himg_key,
                           mask_dc_key, mask_bmp_key, mask_old_key,
                           mask_inv_dc_key, mask_inv_bmp_key, mask_inv_old_key,
                           sprite_dc_key, sprite_bmp_key, sprite_old_key):

        self.mov_rax_mem(mask_dc_key)
        self.emit(bytes([0x48, 0x85, 0xC0]))  
        jnz_already = self.jcc(0x85)  

        self.mov_reg_rva(1, self.target_rva)
        self.call_iat("CreateCompatibleDC")
        self.store_rax_mem(mask_dc_key)

        self.emit(bytes([0xB9]) + self.i32(w))
        self.emit(bytes([0xBA]) + self.i32(h))
        self.emit(bytes([0x41, 0xB8]) + self.i32(1))
        self.emit(bytes([0x41, 0xB9]) + self.i32(1))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]))
        self.call_iat("CreateBitmap")
        self.store_rax_mem(mask_bmp_key)

        self.mov_reg_rva(1, self.rva_of(mask_dc_key))
        self.mov_reg_rva(2, self.rva_of(mask_bmp_key))
        self.call_iat("SelectObject")
        self.store_rax_mem(mask_old_key)

        self.mov_reg_rva(1, self.rva_of(mask_dc_key))
        self.emit(bytes([0x31, 0xD2]))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x41, 0xB9]) + self.i32(w))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + self.i32(h))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28])
                  + struct.pack("<I", 0x00000042))  
        self.call_iat("PatBlt")

        old_target = self.target_rva
        self.target_rva = self.rva_of(mask_dc_key)

        self.emit(bytes([0xBA]) + self.i32(0))  
        self.call_iat("GetStockObject")
        self.mov_reg_rva(1, self.target_rva)
        self.emit(bytes([0x48, 0x89, 0xC2]))
        self.call_iat("SelectObject")

        shape.emit_mask(self)

        self.target_rva = old_target

        self.mov_reg_rva(1, self.target_rva)
        self.call_iat("CreateCompatibleDC")
        self.store_rax_mem(mask_inv_dc_key)

        self.emit(bytes([0xB9]) + self.i32(w))
        self.emit(bytes([0xBA]) + self.i32(h))
        self.emit(bytes([0x41, 0xB8]) + self.i32(1))
        self.emit(bytes([0x41, 0xB9]) + self.i32(1))
        self.emit(bytes([0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]))
        self.call_iat("CreateBitmap")
        self.store_rax_mem(mask_inv_bmp_key)

        self.mov_reg_rva(1, self.rva_of(mask_inv_dc_key))
        self.mov_reg_rva(2, self.rva_of(mask_inv_bmp_key))
        self.call_iat("SelectObject")
        self.store_rax_mem(mask_inv_old_key)

        self._bitblt(self.rva_of(mask_inv_dc_key),
                     0, 0, w, h,
                     self.rva_of(mask_dc_key),
                     0, 0, 0x00CC0020)  

        self.mov_reg_rva(1, self.rva_of(mask_inv_dc_key))
        self.emit(bytes([0x31, 0xD2]))
        self.emit(bytes([0x45, 0x31, 0xC0]))
        self.emit(bytes([0x41, 0xB9]) + self.i32(w))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + self.i32(h))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x28])
                  + struct.pack("<I", 0x00550009))  
        self.call_iat("PatBlt")

        self.mov_reg_rva(1, self.target_rva)
        self.call_iat("CreateCompatibleDC")
        self.store_rax_mem(sprite_dc_key)

        self.mov_reg_rva(1, self.target_rva)
        self.emit(bytes([0xBA]) + self.i32(w))
        self.emit(bytes([0x41, 0xB8]) + self.i32(h))
        self.call_iat("CreateCompatibleBitmap")
        self.store_rax_mem(sprite_bmp_key)

        self.mov_reg_rva(1, self.rva_of(sprite_dc_key))
        self.mov_reg_rva(2, self.rva_of(sprite_bmp_key))
        self.call_iat("SelectObject")
        self.store_rax_mem(sprite_old_key)

        self.mov_reg_rva(1, self.target_rva)
        self.call_iat("CreateCompatibleDC")
        self.store_rax_mem("_img_src_dc")

        self.mov_reg_rva(1, self.rva_of("_img_src_dc"))
        self.mov_reg_rva(2, self.rva_of(himg_key))
        self.call_iat("SelectObject")
        self.store_rax_mem("_img_src_old")

        self._bitblt(self.rva_of(sprite_dc_key),
                     0, 0, w, h,
                     self.rva_of("_img_src_dc"),
                     0, 0, 0x00CC0020)

        self._bitblt(self.rva_of(sprite_dc_key),
                     0, 0, w, h,
                     self.rva_of(mask_dc_key),
                     0, 0, 0x008800C6)  

        self.mov_reg_rva(1, self.rva_of("_img_src_dc"))
        self.mov_reg_rva(2, self.rva_of("_img_src_old"))
        self.call_iat("SelectObject")
        self.mov_reg_rva(1, self.rva_of("_img_src_dc"))
        self.call_iat("DeleteDC")

        self.patch_here(jnz_already)

    def compute_cos_sin(self, angle_rva, k_rva, cos_rva, sin_rva):
        """Посчитать cos/sin угла в .data. World transform НЕ трогает.

        Читает angle из [angle_rva] (float32, градусы),
        умножает на k из [k_rva] (перевод в радианы),
        сохраняет cos в [cos_rva], sin в [sin_rva] (float32).
        """
        self.fninit()
        self.fld_dword_mem_rva(angle_rva)
        self.fmul_dword_mem_rva(k_rva)
        self.fld_st0()
        self.fcos()
        self.fstp_dword_mem_rva(cos_rva)
        self.fsin()
        self.fstp_dword_mem_rva(sin_rva)

    def apply_xform_from_cos_sin(self, cos_rva, sin_rva, px, py, stack_off=0x20):
        """Построить XFORM из уже посчитанных cos/sin + pivot, вызвать SetWorldTransform.

        Требует, чтобы [cos_rva] и [sin_rva] содержали float32.
        """
        px_f = self._f32_bits(float(px)) & 0xFFFFFFFF
        py_f = self._f32_bits(float(py)) & 0xFFFFFFFF

        self.emit(bytes([0xC7, 0x44, 0x24, 0x40]) + struct.pack("<I", px_f))
        self.emit(bytes([0xC7, 0x44, 0x24, 0x44]) + struct.pack("<I", py_f))

        self.fld_dword_mem_rva(cos_rva)  
        self.fld_1_0()  
        self.emit(bytes([0xD8, 0xE1]))  
        self.fld_dword_mem_rva(sin_rva)  
        self.emit(bytes([0xD8, 0x4C, 0x24, 0x44]))  
        self.fxch_st1()  
        self.emit(bytes([0xD8, 0x4C, 0x24, 0x40]))  
        self.faddp_st1_st0()  
        self.emit(bytes([0xD9, 0x5C, 0x24, 0x48]))  

        self.fld_1_0()  
        self.emit(bytes([0xD8, 0xE1]))  
        self.emit(bytes([0xD8, 0x4C, 0x24, 0x44]))  
        self.fld_dword_mem_rva(sin_rva)  
        self.emit(bytes([0xD8, 0x4C, 0x24, 0x40]))  
        self.emit(bytes([0xDE, 0xE9]))  
        self.emit(bytes([0xD9, 0x5C, 0x24, 0x4C]))  

        self.mov_eax_rva(cos_rva)
        self.emit(bytes([0x89, 0x44, 0x24, stack_off + 0x00]))  
        self.emit(bytes([0x89, 0x44, 0x24, stack_off + 0x0C]))  
        self.mov_eax_rva(sin_rva)
        self.emit(bytes([0x89, 0x44, 0x24, stack_off + 0x04]))  
        self.emit(bytes([0x35]) + struct.pack("<I", 0x80000000))  
        self.emit(bytes([0x89, 0x44, 0x24, stack_off + 0x08]))  
        self.emit(bytes([0x8B, 0x44, 0x24, 0x48]))  
        self.emit(bytes([0x89, 0x44, 0x24, stack_off + 0x10]))
        self.emit(bytes([0x8B, 0x44, 0x24, 0x4C]))  
        self.emit(bytes([0x89, 0x44, 0x24, stack_off + 0x14]))

        self.mov_reg_rva(1, self.target_rva)
        self.emit(bytes([0x48, 0x8D, 0x54, 0x24, stack_off]))
        self.call_iat("SetWorldTransform")

    def draw(self, shape):
        shape.emit(self)

    def draw_all(self, shapes):
        for shape in shapes:
            shape.emit(self)

    def invalidate(self):
        self.mov_reg_rva(1, self._hwnd_rva())
        self.emit(bytes([0x31, 0xD2]))
        self.emit(bytes([0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]))
        self.call_iat("InvalidateRect")
