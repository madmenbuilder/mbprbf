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


"""arrays.py - регистрация, инициализация, get/set/len/free массивов MBPRBF.

Runtime-функции (append, insert, remove, resize) — в array_runtime.py.
Все heap-операции — через ctx.heap_alloc_at_rva / heap_realloc_at_rva / heap_free_at_rva.
"""

import ctypes
import struct

from .mb_array import (
    Array, ARR_SLOT_SIZE,
    ARR_PTR_OFF, ARR_LENGTH_OFF, ARR_CAPACITY_OFF, ARR_USED_BYTES_OFF,
    ARR_TYPES_PTR_OFF, ARR_OFFSETS_PTR_OFF, ARR_OFFSETS_CAPACITY_OFF,
    ARR_ELEM_SIZE_OFF, ARR_FLAGS_OFF,
    FLAG_DYNAMIC, FLAG_HOMOGENEOUS, FLAG_INITIALIZED,
    T_ERROR, T_INT8, T_INT16, T_INT32, T_INT64,
    T_FLOAT, T_DOUBLE, T_CHAR_P,
    type_to_code, code_to_size, code_to_align, code_is_float,
    align_up, type_of_value,
)
from .data import data_alloc, add_string, DATA_ALLOC, DATA_OFF_HEAP
from .methods import Rva, Mem, MethodArg

from .array_validator import ensure_alive, check_bounds_static

ARRAYS = []    

def register_array(name, values=None, types=None, size=None):
    """Зарегистрировать массив в .data.

    Статический: задан size (или явно, или через array(10)).
    Динамический: задан values без size.

    Смешивать size и values нельзя.
    """
    if name in DATA_ALLOC:
        raise ValueError(f"array: '{name}' уже занят")

    if size is not None and values is not None:
        raise ValueError(
            f"array '{name}': нельзя одновременно задать size и values"
        )

    if size is not None:

        is_static = True
        if types is None:
            type_ = ctypes.c_int32
        elif isinstance(types, list):
            if len(types) != 1:
                raise ValueError(
                    f"array '{name}': для статического массива types "
                    f"должен быть один тип, а не список"
                )
            type_ = types[0]
        else:
            type_ = types
        values = [0] * size
        types = [type_] * size
    else:

        is_static = False
        if values is None:
            values = []
        if not values and types is None:
            raise ValueError(
                f"array '{name}': пустой массив требует явных types="
            )
        if types is None:
            types = [type_of_value(v) for v in values]
        else:
            types = list(types)
            if not values:
                pass
            elif len(types) == 1 and len(values) > 1:
                types = types * len(values)
            elif len(types) != len(values):
                raise ValueError(
                    f"array '{name}': types({len(types)}) != values({len(values)})"
                )

    str_keys = {}
    for i, (v, t) in enumerate(zip(values, types)):
        if t is ctypes.c_char_p:
            if isinstance(v, str):
                key = f"_arr_{name}_str_{i}"
                add_string(key, v)
                str_keys[i] = key
            elif isinstance(v, (bytes, bytearray)):
                key = f"_arr_{name}_bytes_{i}"
                add_string(key, bytes(v).decode("latin-1"))
                str_keys[i] = key

    arr = Array(name, values, types)
    arr.str_keys = str_keys
    arr.is_static = is_static
    if is_static:
        arr.is_dynamic = False
    data_alloc(name, ARR_SLOT_SIZE, 0, type="array")
    ARRAYS.append(arr)
    try:
        from .array_validator import track_array
        track_array(arr)
    except ImportError:
        pass
    return arr

def array(values=None, types=None, size=None, type=None):
    """Создать массив.

    Формы вызова:
        array([1, 2, 3])                — динамический (без size)
        array([1.5], types=[c_float])   — динамический с явным типом
        array(size=10)                  — статический, тип по умолчанию int32
        array(size=10, type=c_float)    — статический с явным типом
        array(size=10, types=[c_float]) — то же, что type=
    """
    from . import data as _data

    if isinstance(values, int) and not isinstance(values, bool):
        if size is not None:
            raise ValueError("array(): size указан дважды")
        size = values
        values = None

    if type is not None and types is None:
        types = [type]

    if values is None and types is None and size is None:
        raise ValueError(
            "array(): нужны values, либо size, либо types="
        )

    n = len(_data.DATA_ALLOC)
    name = f"_arr_{n}"
    while name in _data.DATA_ALLOC:
        n += 1
        name = f"_arr_{n}"

    return register_array(name, values=values, types=types, size=size)

def reset_arrays():
    ARRAYS.clear()

def emit_array_alloc(ctx, arr):
    """HeapAlloc данных, types, offsets + заполнение слота + начальные значения."""
    slot_rva = ctx.rva_of(arr.name)

    data_bytes = max(arr.capacity, 16)
    ctx.heap_alloc_at_rva(slot_rva + ARR_PTR_OFF, data_bytes)

    types_count = max(arr.length, 16)
    ctx.heap_alloc_at_rva(slot_rva + ARR_TYPES_PTR_OFF, types_count * 4)
    ctx.heap_alloc_at_rva(slot_rva + ARR_OFFSETS_PTR_OFF, types_count * 4)

    _store_imm64_to_slot(ctx, slot_rva, ARR_LENGTH_OFF, arr.length)
    _store_imm64_to_slot(ctx, slot_rva, ARR_CAPACITY_OFF, data_bytes)
    _store_imm64_to_slot(ctx, slot_rva, ARR_USED_BYTES_OFF, arr.used_bytes)
    _store_imm64_to_slot(ctx, slot_rva, ARR_OFFSETS_CAPACITY_OFF, types_count)
    _store_imm32_to_slot(ctx, slot_rva, ARR_ELEM_SIZE_OFF, arr.elem_size)

    flags = FLAG_DYNAMIC | FLAG_INITIALIZED
    if arr.is_homogeneous:
        flags |= FLAG_HOMOGENEOUS
    _store_imm32_to_slot(ctx, slot_rva, ARR_FLAGS_OFF, flags)

    for i in range(arr.length):
        code = arr.type_codes[i]
        off = arr.offsets[i]
        _write_u32_to_heap_at_index(ctx, slot_rva, ARR_OFFSETS_PTR_OFF, i, off)
        _write_u32_to_heap_at_index(ctx, slot_rva, ARR_TYPES_PTR_OFF, i, code)

    for i, (v, t) in enumerate(zip(arr.values, arr.types)):
        _emit_init_value(ctx, arr, i, v, t)

def _write_u32_to_heap_at_index(ctx, slot_rva, heap_ptr_off, i, value):
    """[[slot_rva + heap_ptr_off] + i*4] = value (uint32)."""
    ctx.mov_rax_rva(slot_rva + heap_ptr_off)
    ctx.emit(bytes([0xC7, 0x80])
             + ctx.i32(i * 4)
             + struct.pack("<I", value & 0xFFFFFFFF))

def _emit_init_value(ctx, arr, i, v, t):
    """Записать i-й элемент по offset arr.offsets[i]."""
    slot_rva = ctx.rva_of(arr.name)
    off = arr.offsets[i]
    code = type_to_code(t)
    ctx.mov_rax_rva(slot_rva + ARR_PTR_OFF)
    _emit_store_to_rax_off(ctx, arr, code, off, v, i)

def _store_imm64_to_slot(ctx, slot_rva, off, v):
    addr = slot_rva + off
    ctx.emit(bytes([0x48, 0xC7, 0x05])
             + ctx.i32(addr - (ctx.rva_now() + 11))
             + struct.pack("<I", v & 0xFFFFFFFF))

def _store_imm32_to_slot(ctx, slot_rva, off, v):
    addr = slot_rva + off
    ctx.emit(bytes([0xC7, 0x05])
             + ctx.i32(addr - (ctx.rva_now() + 10))
             + struct.pack("<I", v & 0xFFFFFFFF))

def array_get(ctx, arr, index):
    ensure_alive(ctx, arr)
    check_bounds_static(arr, index, "array_get")
    slot_rva = ctx.rva_of(arr.name)

    if isinstance(index, int) and arr.is_static:
        _emit_load_const(ctx, arr, slot_rva, index)
    else:
        _emit_load_var(ctx, arr, slot_rva, index)

def _emit_load_const(ctx, arr, slot_rva, i):
    off = arr.offsets[i]
    code = arr.type_codes[i]
    ctx.mov_rax_rva(slot_rva + ARR_PTR_OFF)
    _emit_load_from_rax_off(ctx, code, off)

def _emit_load_from_rax_off(ctx, code, off):
    if code == T_INT8:
        ctx.emit(bytes([0x48, 0x0F, 0xBE, 0x80]) + ctx.i32(off))
    elif code == T_INT16:
        ctx.emit(bytes([0x48, 0x0F, 0xBF, 0x80]) + ctx.i32(off))
    elif code == T_INT32:
        ctx.emit(bytes([0x8B, 0x80]) + ctx.i32(off))
    elif code == T_INT64:
        ctx.emit(bytes([0x48, 0x8B, 0x80]) + ctx.i32(off))
    elif code == T_FLOAT:
        ctx.emit(bytes([0xF3, 0x0F, 0x10, 0x80]) + ctx.i32(off))
    elif code == T_DOUBLE:
        ctx.emit(bytes([0xF2, 0x0F, 0x10, 0x80]) + ctx.i32(off))
    elif code == T_CHAR_P:
        ctx.emit(bytes([0x48, 0x8B, 0x80]) + ctx.i32(off))
    else:
        raise ValueError(f"_emit_load_from_rax_off: code {code}")

def _emit_load_var(ctx, arr, slot_rva, index):
    """Переменный индекс. r10 = data, r11d = offset, edx = code."""
    ctx.mov_rax_rva(slot_rva + ARR_PTR_OFF)
    ctx.emit(bytes([0x49, 0x89, 0xC2]))                     

    _load_index_to_rcx(ctx, index)

    ctx.mov_reg_rva(9, slot_rva + ARR_OFFSETS_PTR_OFF)
    ctx.mov_reg_rva(8, slot_rva + ARR_TYPES_PTR_OFF)

    ctx.emit(bytes([0x45, 0x8B, 0x1C, 0x89]))                
    ctx.emit(bytes([0x41, 0x8B, 0x14, 0x88]))                

    _emit_switch_load(ctx)

def array_set(ctx, arr, index, value):
    ensure_alive(ctx, arr)
    check_bounds_static(arr, index, "array_set")
    slot_rva = ctx.rva_of(arr.name)

    if isinstance(index, int):
        _emit_store_const(ctx, arr, slot_rva, index, value)
    else:
        _emit_store_var(ctx, arr, slot_rva, index, value)

def _emit_store_const(ctx, arr, slot_rva, i, value):
    off = arr.offsets[i]
    code = arr.type_codes[i]
    ctx.mov_rax_rva(slot_rva + ARR_PTR_OFF)
    _emit_store_to_rax_off(ctx, arr, code, off, value, i)

def _emit_store_to_rax_off(ctx, arr, code, off, value, idx=None):
    """Записать value в [rax + off] по коду типа.

    idx — индекс для случаев, когда value = str, и нужно взять конкретную строку.
    """
    if code == T_CHAR_P:
        _load_charp_to_rdx(ctx, value, arr, idx)
        ctx.emit(bytes([0x48, 0x89, 0x90]) + ctx.i32(off))
    elif code == T_FLOAT:
        _load_float_to_xmm0(ctx, value, is_double=False)
        ctx.emit(bytes([0xF3, 0x0F, 0x11, 0x80]) + ctx.i32(off))
    elif code == T_DOUBLE:
        _load_float_to_xmm0(ctx, value, is_double=True)
        ctx.emit(bytes([0xF2, 0x0F, 0x11, 0x80]) + ctx.i32(off))
    elif code == T_INT8:
        _load_int_to_rdx(ctx, value, 8)
        ctx.emit(bytes([0x88, 0x90]) + ctx.i32(off))
    elif code == T_INT16:
        _load_int_to_rdx(ctx, value, 16)
        ctx.emit(bytes([0x66, 0x89, 0x90]) + ctx.i32(off))
    elif code == T_INT32:
        _load_int_to_rdx(ctx, value, 32)
        ctx.emit(bytes([0x89, 0x90]) + ctx.i32(off))
    elif code == T_INT64:
        _load_int_to_rdx(ctx, value, 64)
        ctx.emit(bytes([0x48, 0x89, 0x90]) + ctx.i32(off))
    else:
        raise ValueError(f"_emit_store_to_rax_off: code {code}")

def _emit_store_var(ctx, arr, slot_rva, index, value):
    """Переменный индекс set."""
    ctx.mov_rax_rva(slot_rva + ARR_PTR_OFF)
    ctx.emit(bytes([0x49, 0x89, 0xC2]))                     

    _load_index_to_rcx(ctx, index)

    ctx.mov_reg_rva(9, slot_rva + ARR_OFFSETS_PTR_OFF)
    ctx.mov_reg_rva(8, slot_rva + ARR_TYPES_PTR_OFF)
    ctx.emit(bytes([0x45, 0x8B, 0x1C, 0x89]))                
    ctx.emit(bytes([0x41, 0x8B, 0x14, 0x88]))                

    _emit_switch_store(ctx, arr, value)

def array_len(ctx, arr):
    slot_rva = ctx.rva_of(arr.name)
    ctx.mov_rax_rva(slot_rva + ARR_LENGTH_OFF)

def array_free(ctx, arr):
    ensure_alive(ctx, arr)
    slot_rva = ctx.rva_of(arr.name)
    ctx.heap_free_at_rva(slot_rva + ARR_PTR_OFF)
    ctx.heap_free_at_rva(slot_rva + ARR_TYPES_PTR_OFF)
    ctx.heap_free_at_rva(slot_rva + ARR_OFFSETS_PTR_OFF)
    _store_imm64_to_slot(ctx, slot_rva, ARR_PTR_OFF, 0)
    _store_imm64_to_slot(ctx, slot_rva, ARR_TYPES_PTR_OFF, 0)
    _store_imm64_to_slot(ctx, slot_rva, ARR_OFFSETS_PTR_OFF, 0)
    _store_imm64_to_slot(ctx, slot_rva, ARR_LENGTH_OFF, 0)
    _store_imm64_to_slot(ctx, slot_rva, ARR_CAPACITY_OFF, 0)
    _store_imm64_to_slot(ctx, slot_rva, ARR_USED_BYTES_OFF, 0)
    _store_imm64_to_slot(ctx, slot_rva, ARR_OFFSETS_CAPACITY_OFF, 0)

def _load_index_to_rcx(ctx, index):
    if isinstance(index, int):
        ctx.emit(bytes([0xB9]) + ctx.i32(index & 0xFFFFFFFF))
    elif isinstance(index, str):
        rva = ctx.rva_of(index)
        ctx.emit(bytes([0x8B, 0x0D]) + ctx.i32(rva - (ctx.rva_now() + 6)))
    elif isinstance(index, Mem):
        ctx.emit(bytes([0x8B, 0x0D]) + ctx.i32(index.rva - (ctx.rva_now() + 6)))
    elif isinstance(index, Rva):
        ctx.emit(bytes([0xB9]) + ctx.i32(index.rva & 0xFFFFFFFF))
    elif isinstance(index, MethodArg):
        index.emit_load(ctx, 'rcx')
    elif isinstance(index, tuple) and len(index) == 2 and isinstance(index[0], str):
        name, off = index
        rva = ctx.rva_of(name) + off
        ctx.emit(bytes([0x8B, 0x0D]) + ctx.i32(rva - (ctx.rva_now() + 6)))
    else:
        raise TypeError(f"array: неизвестный источник индекса {index!r}")

def _load_int_to_rdx(ctx, value, bits):
    if isinstance(value, bool):
        v = int(value)
    elif isinstance(value, int):
        v = value
    elif isinstance(value, str):
        rva = ctx.rva_of(value)
        if bits <= 32:
            ctx.emit(bytes([0x8B, 0x15]) + ctx.i32(rva - (ctx.rva_now() + 6)))
        else:
            ctx.emit(bytes([0x48, 0x8B, 0x15]) + ctx.i32(rva - (ctx.rva_now() + 7)))
        return
    elif isinstance(value, Mem):
        if bits <= 32:
            ctx.emit(bytes([0x8B, 0x15]) + ctx.i32(value.rva - (ctx.rva_now() + 6)))
        else:
            ctx.emit(bytes([0x48, 0x8B, 0x15]) + ctx.i32(value.rva - (ctx.rva_now() + 7)))
        return
    elif isinstance(value, MethodArg):
        value.emit_load(ctx, 'rdx')
        return
    else:
        raise TypeError(f"array: не могу загрузить int из {value!r}")

    v_masked = v & ((1 << bits) - 1) if bits < 64 else v & 0xFFFFFFFFFFFFFFFF
    if bits <= 32:
        ctx.emit(bytes([0xBA]) + ctx.i32(v_masked & 0xFFFFFFFF))
    else:
        if -0x80000000 <= v <= 0x7FFFFFFF:
            ctx.emit(bytes([0x48, 0xC7, 0xC2]) + ctx.i32(v_masked & 0xFFFFFFFF))
        else:
            ctx.emit(bytes([0x48, 0xBA]) + struct.pack("<Q", v_masked))

def _load_float_to_xmm0(ctx, value, is_double):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        if is_double:
            bits = struct.unpack("<Q", struct.pack("<d", v))[0]
            ctx.emit(bytes([0x48, 0xB9]) + struct.pack("<Q", bits))   
            ctx.emit(bytes([0x66, 0x48, 0x0F, 0x6E, 0xC1]))           
        else:
            bits = struct.unpack("<I", struct.pack("<f", v))[0]
            ctx.emit(bytes([0xB9]) + struct.pack("<I", bits))          
            ctx.emit(bytes([0x66, 0x0F, 0x6E, 0xC1]))                  
    elif isinstance(value, str):
        rva = ctx.rva_of(value)
        if is_double:
            ctx.emit(bytes([0xF2, 0x0F, 0x10, 0x05])
                     + ctx.i32(rva - (ctx.rva_now() + 8)))
        else:
            ctx.emit(bytes([0xF3, 0x0F, 0x10, 0x05])
                     + ctx.i32(rva - (ctx.rva_now() + 8)))
    elif isinstance(value, Mem):
        if is_double:
            ctx.emit(bytes([0xF2, 0x0F, 0x10, 0x05])
                     + ctx.i32(value.rva - (ctx.rva_now() + 8)))
        else:
            ctx.emit(bytes([0xF3, 0x0F, 0x10, 0x05])
                     + ctx.i32(value.rva - (ctx.rva_now() + 8)))
    elif isinstance(value, MethodArg):
        value.emit_load_float(ctx, 'xmm0')
    else:
        raise TypeError(f"array: не могу загрузить float из {value!r}")

def _load_charp_to_rdx(ctx, value, arr=None, idx=None):
    """Загрузить указатель-строку в rdx.

    Если value — имя строки из add_string — берём ctx.string_rvas[value].
    Если value — str и arr/idx заданы — берём arr.str_keys[idx].
    """
    if isinstance(value, str) and arr is not None and idx is not None:
        if idx in arr.str_keys:
            key = arr.str_keys[idx]
            rva = ctx.string_rvas[key]
            ctx.emit(bytes([0x48, 0x8D, 0x15])
                     + ctx.i32(rva - (ctx.rva_now() + 7)))
            return
    if isinstance(value, str):
        rva = ctx.string_rvas[value]
        ctx.emit(bytes([0x48, 0x8D, 0x15])
                 + ctx.i32(rva - (ctx.rva_now() + 7)))
    elif isinstance(value, Rva):
        ctx.emit(bytes([0x48, 0x8D, 0x15])
                 + ctx.i32(value.rva - (ctx.rva_now() + 7)))
    elif isinstance(value, Mem):
        ctx.emit(bytes([0x48, 0x8B, 0x15])
                 + ctx.i32(value.rva - (ctx.rva_now() + 7)))
    elif isinstance(value, MethodArg):
        value.emit_load(ctx, 'rdx')
    elif value is None:
        ctx.emit(bytes([0x48, 0x31, 0xD2]))
    elif isinstance(value, int):
        ctx.emit(bytes([0x48, 0xC7, 0xC2]) + ctx.i32(value & 0xFFFFFFFF))
    else:
        raise TypeError(f"array: не могу загрузить c_char_p из {value!r}")

def _emit_switch_load(ctx):
    """r10 = data, r11d = offset, edx = code. Результат: eax/rax/xmm0."""
    cases = [T_INT8, T_INT16, T_INT32, T_INT64, T_FLOAT, T_DOUBLE, T_CHAR_P]
    jccs = []
    for c in cases:
        ctx.emit(bytes([0x81, 0xFA]) + struct.pack("<I", c))
        je = ctx.jcc(0x84)
        jccs.append((c, je))

    ctx.emit(bytes([0x31, 0xC0]))
    jmp_default = ctx.jmp_placeholder()

    case_jmps = []
    for c, je in jccs:
        ctx.patch_here(je)
        if c == T_INT8:
            ctx.emit(bytes([0x43, 0x0F, 0xBE, 0x04, 0x1A]))    
        elif c == T_INT16:
            ctx.emit(bytes([0x43, 0x0F, 0xBF, 0x04, 0x1A]))
        elif c == T_INT32:
            ctx.emit(bytes([0x43, 0x8B, 0x04, 0x1A]))
        elif c == T_INT64:
            ctx.emit(bytes([0x4B, 0x8B, 0x04, 0x1A]))          
        elif c == T_FLOAT:
            ctx.emit(bytes([0xF3, 0x43, 0x0F, 0x10, 0x04, 0x1A]))
        elif c == T_DOUBLE:
            ctx.emit(bytes([0xF2, 0x43, 0x0F, 0x10, 0x04, 0x1A]))
        elif c == T_CHAR_P:
            ctx.emit(bytes([0x4B, 0x8B, 0x04, 0x1A]))
        j = ctx.jmp_placeholder()
        case_jmps.append(j)

    ctx.patch_jmp_here(jmp_default)
    for j in case_jmps:
        ctx.patch_jmp_here(j)

def _emit_switch_store(ctx, arr, value):
    """r10 = data, r11d = offset, edx = code. Записать value."""
    cases = [T_INT8, T_INT16, T_INT32, T_INT64, T_FLOAT, T_DOUBLE, T_CHAR_P]
    jccs = []
    for c in cases:
        ctx.emit(bytes([0x81, 0xFA]) + struct.pack("<I", c))
        je = ctx.jcc(0x84)
        jccs.append((c, je))

    jmp_default = ctx.jmp_placeholder()

    case_jmps = []
    for c, je in jccs:
        ctx.patch_here(je)
        if c == T_INT8:
            try:
                iv = int(value) & 0xFF
            except (TypeError, ValueError):
                iv = 0
            _load_int_to_rdx(ctx, iv, 8)
            ctx.emit(bytes([0x43, 0x88, 0x14, 0x1A]))

        elif c == T_INT16:
            try:
                iv = int(value) & 0xFFFF
            except (TypeError, ValueError):
                iv = 0
            _load_int_to_rdx(ctx, iv, 16)
            ctx.emit(bytes([0x66, 0x43, 0x89, 0x14, 0x1A]))

        elif c == T_INT32:
            try:
                iv = int(value) & 0xFFFFFFFF
            except (TypeError, ValueError):
                iv = 0
            _load_int_to_rdx(ctx, iv, 32)
            ctx.emit(bytes([0x43, 0x89, 0x14, 0x1A]))

        elif c == T_INT64:
            try:
                iv = int(value) & 0xFFFFFFFFFFFFFFFF
            except (TypeError, ValueError):
                iv = 0
            _load_int_to_rdx(ctx, iv, 64)
            ctx.emit(bytes([0x4B, 0x89, 0x14, 0x1A]))

        elif c == T_FLOAT:
            try:
                fv = float(value)
            except (TypeError, ValueError):
                fv = 0.0
            _load_float_to_xmm0(ctx, fv, is_double=False)
            ctx.emit(bytes([0xF3, 0x43, 0x0F, 0x11, 0x04, 0x1A]))

        elif c == T_DOUBLE:
            try:
                fv = float(value)
            except (TypeError, ValueError):
                fv = 0.0
            _load_float_to_xmm0(ctx, fv, is_double=True)
            ctx.emit(bytes([0xF2, 0x43, 0x0F, 0x11, 0x04, 0x1A]))

        elif c == T_CHAR_P:
            try:
                _load_charp_to_rdx(ctx, value, arr, None)
            except TypeError:
                ctx.emit(bytes([0x48, 0x31, 0xD2]))  
            ctx.emit(bytes([0x4B, 0x89, 0x14, 0x1A]))  

        j = ctx.jmp_placeholder()
        case_jmps.append(j)

    ctx.patch_jmp_here(jmp_default)
    for j in case_jmps:
        ctx.patch_jmp_here(j)
