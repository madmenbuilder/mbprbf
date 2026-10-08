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


"""array_runtime.py - runtime-функции массивов MBPRBF.

Все локальные переменные и сохранённые аргументы — на стеке.
Регистры используются только для загрузки аргументов перед call_iat.
"""

import ctypes
import struct

from . import asm_helper as a
from .mb_array import (
    ARR_PTR_OFF, ARR_LENGTH_OFF, ARR_CAPACITY_OFF, ARR_USED_BYTES_OFF,
    ARR_TYPES_PTR_OFF, ARR_OFFSETS_PTR_OFF, ARR_OFFSETS_CAPACITY_OFF,
    T_INT8, T_INT16, T_INT32, T_INT64, T_FLOAT, T_DOUBLE, T_CHAR_P,
    type_to_code, code_to_size, code_to_align, type_of_value,
)
from .data import DATA_OFF_HEAP
from .methods import Rva
from .array_validator import ensure_alive

L_SLOT      = 0x00
L_ARG2      = 0x08
L_ARG3      = 0x10
L_ARG4      = 0x18
L_ALIGN     = 0x20
L_OFFSET    = 0x28
L_NEED      = 0x30
L_NEWCAP    = 0x38
L_DATA      = 0x40
L_OFFSETS   = 0x48
L_TYPES     = 0x50
L_TEMP      = 0x58
L_NEWOFFCAP = 0x60
L_NEWUSED   = 0x68
L_COUNTER   = 0x70
L_SCRATCH   = 0x78

def _ensure_state(ctx):
    if not hasattr(ctx, '_arr_runtime_done'):
        ctx._arr_runtime_done = set()

def _gen_recompute_offsets(ctx):
    ctx.start_method('_arr_recompute_offsets',
                     [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p],
                     ret_type=ctypes.c_uint64)

    LOCAL = 0x80
    a.sub_rsp(ctx, LOCAL)
    a.store(ctx, 0x00, 'rcx')       
    a.store(ctx, 0x08, 'rdx')       
    a.store(ctx, 0x10, 'r8')        
    a.store_imm64(ctx, 0x18, 0)     
    a.store_imm64(ctx, 0x20, 0)     
    a.store_imm64(ctx, 0x28, 1)     

    loop_off = ctx.len()

    a.load(ctx, 'rax', 0x18)
    a.load(ctx, 'rcx', 0x08)
    a.cmp(ctx, 'rax', 'rcx')
    jge_done = a.jcc(ctx, 0x8D)

    a.load(ctx, 'rcx', 0x00)            
    a.load(ctx, 'rax', 0x18)            
    a.load_idx32(ctx, 'edx', 'rcx', 'rax', 4, 0)

    a.store_imm64(ctx, 0x30, 1)         
    a.store_imm64(ctx, 0x38, 0)         
    ends = []
    for c, align, size in [(T_INT8,1,1),(T_INT16,2,2),(T_INT32,4,4),
                            (T_INT64,8,8),(T_FLOAT,4,4),(T_DOUBLE,8,8),
                            (T_CHAR_P,8,8)]:
        a.load_imm32(ctx, 'eax', c)
        a.cmp32(ctx, 'edx', 'eax')
        jne = a.jcc(ctx, 0x85)
        a.store_imm64(ctx, 0x30, align)
        a.store_imm64(ctx, 0x38, size)
        j = a.jmp(ctx)
        ends.append(j)
        a.patch(ctx, jne)
    for j in ends:
        a.patch(ctx, j)

    a.load(ctx, 'rax', 0x30)
    a.load(ctx, 'rcx', 0x28)
    a.cmp(ctx, 'rcx', 'rax')
    jae_skip = a.jcc(ctx, 0x83)
    a.store(ctx, 0x28, 'rax')
    a.patch(ctx, jae_skip)

    a.load(ctx, 'rax', 0x20)            
    a.load(ctx, 'rcx', 0x30)            
    a.add(ctx, 'rax', 'rcx')
    a.load_imm64(ctx, 'rcx', 1)
    a.sub(ctx, 'rax', 'rcx')            
    a.load(ctx, 'rcx', 0x30)
    a.neg64(ctx, 'rcx')                 
    a.and64(ctx, 'rax', 'rcx')
    a.store(ctx, 0x20, 'rax')

    a.load(ctx, 'rcx', 0x10)
    a.load(ctx, 'rax', 0x18)
    a.load(ctx, 'rdx', 0x20)
    a.store_idx32(ctx, 'rcx', 'rax', 4, 0, 'edx')

    a.load(ctx, 'rax', 0x20)
    a.load(ctx, 'rcx', 0x38)
    a.add(ctx, 'rax', 'rcx')
    a.store(ctx, 0x20, 'rax')

    a.load(ctx, 'rax', 0x18)
    a.inc64(ctx, 'rax')
    a.store(ctx, 0x18, 'rax')

    rel = loop_off - (ctx.len() + 5)
    ctx.emit(bytes([0xE9]) + ctx.i32(rel))

    a.patch(ctx, jge_done)

    a.load(ctx, 'rax', 0x20)
    a.load(ctx, 'rcx', 0x28)
    a.add(ctx, 'rax', 'rcx')
    a.load_imm64(ctx, 'rcx', 1)
    a.sub(ctx, 'rax', 'rcx')
    a.load(ctx, 'rcx', 0x28)
    a.neg64(ctx, 'rcx')
    a.and64(ctx, 'rax', 'rcx')

    a.add_rsp(ctx, LOCAL)
    ctx.end_method()

def _gen_append(ctx):
    ctx.start_method('_arr_append',
                     [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32,
                      ctypes.c_uint32, ctypes.c_uint32],
                     ret_type=ctypes.c_uint64)

    LOCAL = 0x80
    a.sub_rsp(ctx, LOCAL)
    a.store(ctx, 0x00, 'rcx')       
    a.store(ctx, 0x08, 'rdx')       
    a.store(ctx, 0x10, 'r8')        
    a.store(ctx, 0x18, 'r9')        
    a.load_disp(ctx, 'rax', 'rsp', LOCAL + 0x68)
    a.store(ctx, 0x20, 'rax')       

    a.mov_rax_mem_abs(ctx, ctx.data_rva + DATA_OFF_HEAP)
    a.store(ctx, 0x58, 'rax')

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_PTR_OFF)
    a.store(ctx, 0x40, 'rcx')
    a.load_disp(ctx, 'rcx', 'rax', ARR_OFFSETS_PTR_OFF)
    a.store(ctx, 0x48, 'rcx')
    a.load_disp(ctx, 'rcx', 'rax', ARR_TYPES_PTR_OFF)
    a.store(ctx, 0x50, 'rcx')

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.test64(ctx, 'rcx', 'rcx')
    jz_len0 = a.jcc(ctx, 0x84)

    a.load_disp(ctx, 'rax', 'rax', ARR_USED_BYTES_OFF)
    a.load(ctx, 'rcx', 0x20)
    a.add(ctx, 'rax', 'rcx')
    a.load_imm64(ctx, 'rcx', 1)
    a.sub(ctx, 'rax', 'rcx')
    a.load(ctx, 'rcx', 0x20)
    a.neg64(ctx, 'rcx')
    a.and64(ctx, 'rax', 'rcx')
    a.store(ctx, 0x28, 'rax')
    jmp_have_off = a.jmp(ctx)

    a.patch(ctx, jz_len0)
    a.store_imm64(ctx, 0x28, 0)
    a.patch(ctx, jmp_have_off)

    a.load(ctx, 'rax', 0x28)
    a.load(ctx, 'rcx', 0x18)
    a.add(ctx, 'rax', 'rcx')
    a.store(ctx, 0x30, 'rax')

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_CAPACITY_OFF)
    a.load(ctx, 'rdx', 0x30)
    a.cmp(ctx, 'rdx', 'rcx')
    jle_cap = a.jcc(ctx, 0x8E)

    a.load_disp(ctx, 'rax', 'rax', ARR_CAPACITY_OFF)
    a.shl64(ctx, 'rax', 1)
    a.load(ctx, 'rdx', 0x30)
    a.load_imm64(ctx, 'rcx', 64)
    a.add(ctx, 'rdx', 'rcx')
    a.cmp(ctx, 'rax', 'rdx')
    jae_rax = a.jcc(ctx, 0x83)
    a.mov(ctx, 'rax', 'rdx')
    a.patch(ctx, jae_rax)
    a.store(ctx, 0x38, 'rax')

    a.load(ctx, 'r9', 0x38)
    a.load(ctx, 'r8', 0x40)
    a.load(ctx, 'rcx', 0x58)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapReAlloc")

    a.store(ctx, 0x40, 'rax')
    a.load(ctx, 'rcx', 0x00)
    a.store_disp(ctx, 'rcx', ARR_PTR_OFF, 'rax')
    a.load(ctx, 'rdx', 0x38)
    a.store_disp(ctx, 'rcx', ARR_CAPACITY_OFF, 'rdx')

    a.patch(ctx, jle_cap)

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.inc64(ctx, 'rcx')
    a.load_disp(ctx, 'rdx', 'rax', ARR_OFFSETS_CAPACITY_OFF)
    a.cmp(ctx, 'rcx', 'rdx')
    jle_offcap = a.jcc(ctx, 0x8E)

    a.load_disp(ctx, 'rax', 'rax', ARR_OFFSETS_CAPACITY_OFF)
    a.shl64(ctx, 'rax', 1)
    a.load(ctx, 'rcx', 0x00)
    a.load_disp(ctx, 'rcx', 'rcx', ARR_LENGTH_OFF)
    a.inc64(ctx, 'rcx')
    a.load_imm64(ctx, 'rdx', 16)
    a.add(ctx, 'rcx', 'rdx')
    a.cmp(ctx, 'rax', 'rcx')
    jae_rax2 = a.jcc(ctx, 0x83)
    a.mov(ctx, 'rax', 'rcx')
    a.patch(ctx, jae_rax2)
    a.store(ctx, 0x60, 'rax')

    a.load(ctx, 'rax', 0x60)
    a.shl64(ctx, 'rax', 2)
    a.mov(ctx, 'r9', 'rax')
    a.load(ctx, 'r8', 0x50)
    a.load(ctx, 'rcx', 0x58)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapReAlloc")
    a.store(ctx, 0x50, 'rax')
    a.load(ctx, 'rcx', 0x00)
    a.store_disp(ctx, 'rcx', ARR_TYPES_PTR_OFF, 'rax')

    a.load(ctx, 'rax', 0x60)
    a.shl64(ctx, 'rax', 2)
    a.mov(ctx, 'r9', 'rax')
    a.load(ctx, 'r8', 0x48)
    a.load(ctx, 'rcx', 0x58)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapReAlloc")
    a.store(ctx, 0x48, 'rax')
    a.load(ctx, 'rcx', 0x00)
    a.store_disp(ctx, 'rcx', ARR_OFFSETS_PTR_OFF, 'rax')

    a.load(ctx, 'rcx', 0x00)
    a.load(ctx, 'rdx', 0x60)
    a.store_disp(ctx, 'rcx', ARR_OFFSETS_CAPACITY_OFF, 'rdx')

    a.patch(ctx, jle_offcap)

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rax', 'rax', ARR_LENGTH_OFF)
    a.load(ctx, 'rcx', 0x48)
    a.load(ctx, 'rdx', 0x28)
    a.store_idx32(ctx, 'rcx', 'rax', 4, 0, 'edx')

    a.load(ctx, 'rcx', 0x50)
    a.load(ctx, 'rdx', 0x10)
    a.store_idx32(ctx, 'rcx', 'rax', 4, 0, 'edx')

    a.load(ctx, 'r10', 0x40)
    a.load(ctx, 'rax', 0x28)
    a.add(ctx, 'r10', 'rax')

    ends2 = []
    for c, kind in [(T_INT8,'i8'),(T_INT16,'i16'),(T_INT32,'i32'),
                     (T_INT64,'i64'),(T_FLOAT,'i32'),(T_DOUBLE,'i64')]:
        a.load_imm32(ctx, 'eax', c)
        a.load(ctx, 'rcx', 0x10)
        a.cmp32(ctx, 'ecx', 'eax')
        jne = a.jcc(ctx, 0x85)
        if kind == 'i8':
            a.load(ctx, 'rdx', 0x08); a.store8_disp(ctx, 'r10', 0, 'dl')
        elif kind == 'i16':
            a.load(ctx, 'rdx', 0x08); a.store16(ctx, 'r10', 0, 'edx')
        elif kind == 'i32':
            a.load(ctx, 'rdx', 0x08); a.store32_disp(ctx, 'r10', 0, 'edx')
        elif kind == 'i64':
            a.load(ctx, 'rdx', 0x08); a.store_disp(ctx, 'r10', 0, 'rdx')
        j = a.jmp(ctx)
        ends2.append(j)
        a.patch(ctx, jne)
    a.load(ctx, 'rdx', 0x08)
    a.store_disp(ctx, 'r10', 0, 'rdx')
    for j in ends2:
        a.patch(ctx, j)

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.inc64(ctx, 'rcx')
    a.store_disp(ctx, 'rax', ARR_LENGTH_OFF, 'rcx')

    a.load(ctx, 'rdx', 0x28)
    a.load(ctx, 'rcx', 0x18)
    a.add(ctx, 'rdx', 'rcx')
    a.load(ctx, 'rax', 0x00)
    a.store_disp(ctx, 'rax', ARR_USED_BYTES_OFF, 'rdx')

    a.xor64(ctx, 'rax', 'rax')
    a.add_rsp(ctx, LOCAL)
    ctx.end_method()

def _gen_insert(ctx):
    ctx.start_method('_arr_insert',
                     [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64,
                      ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32],
                     ret_type=ctypes.c_uint64)

    LOCAL = 0x100
    a.sub_rsp(ctx, LOCAL)
    a.store(ctx, 0x00, 'rcx')       
    a.store(ctx, 0x08, 'rdx')       
    a.store(ctx, 0x10, 'r8')        
    a.store(ctx, 0x18, 'r9')        
    a.load_disp(ctx, 'rax', 'rsp', LOCAL + 0x68)  
    a.store(ctx, 0x20, 'rax')
    a.load_disp(ctx, 'rax', 'rsp', LOCAL + 0x70)  
    a.store(ctx, 0x28, 'rax')

    a.mov_rax_mem_abs(ctx, ctx.data_rva + DATA_OFF_HEAP)
    a.store(ctx, 0x48, 'rax')       

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.load(ctx, 'rdx', 0x08)
    a.cmp(ctx, 'rdx', 'rcx')
    jbe_ok = a.jcc(ctx, 0x86)
    a.load_imm64(ctx, 'rax', 1)
    jmp_err = a.jmp(ctx)
    a.patch(ctx, jbe_ok)

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.store(ctx, 0x50, 'rcx')       
    a.inc64(ctx, 'rcx')
    a.store(ctx, 0x58, 'rcx')       

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rdx', 'rax', ARR_OFFSETS_CAPACITY_OFF)
    a.load(ctx, 'rcx', 0x58)
    a.cmp(ctx, 'rcx', 'rdx')
    jle_offcap = a.jcc(ctx, 0x8E)

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rax', 'rax', ARR_OFFSETS_CAPACITY_OFF)
    a.shl64(ctx, 'rax', 1)
    a.load(ctx, 'rcx', 0x58)
    a.load_imm64(ctx, 'rdx', 16)
    a.add(ctx, 'rcx', 'rdx')
    a.cmp(ctx, 'rax', 'rcx')
    jae_rax = a.jcc(ctx, 0x83)
    a.mov(ctx, 'rax', 'rcx')
    a.patch(ctx, jae_rax)
    a.store(ctx, 0xA0, 'rax')       

    a.load(ctx, 'rax', 0xA0)
    a.shl64(ctx, 'rax', 2)
    a.mov(ctx, 'r9', 'rax')
    a.load(ctx, 'rcx', 0x00)
    a.load_disp(ctx, 'r8', 'rcx', ARR_TYPES_PTR_OFF)
    a.load(ctx, 'rcx', 0x48)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapReAlloc")
    a.load(ctx, 'rcx', 0x00)
    a.store_disp(ctx, 'rcx', ARR_TYPES_PTR_OFF, 'rax')

    a.load(ctx, 'rax', 0xA0)
    a.shl64(ctx, 'rax', 2)
    a.mov(ctx, 'r9', 'rax')
    a.load(ctx, 'rcx', 0x00)
    a.load_disp(ctx, 'r8', 'rcx', ARR_OFFSETS_PTR_OFF)
    a.load(ctx, 'rcx', 0x48)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapReAlloc")
    a.load(ctx, 'rcx', 0x00)
    a.store_disp(ctx, 'rcx', ARR_OFFSETS_PTR_OFF, 'rax')

    a.load(ctx, 'rcx', 0x00)
    a.load(ctx, 'rdx', 0xA0)
    a.store_disp(ctx, 'rcx', ARR_OFFSETS_CAPACITY_OFF, 'rdx')

    a.patch(ctx, jle_offcap)

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_PTR_OFF)
    a.store(ctx, 0x30, 'rcx')
    a.load_disp(ctx, 'rcx', 'rax', ARR_OFFSETS_PTR_OFF)
    a.store(ctx, 0x38, 'rcx')
    a.load_disp(ctx, 'rcx', 'rax', ARR_TYPES_PTR_OFF)
    a.store(ctx, 0x40, 'rcx')

    a.load(ctx, 'rax', 0x58)
    a.shl64(ctx, 'rax', 2)
    a.mov(ctx, 'r8', 'rax')
    a.load(ctx, 'rcx', 0x48)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapAlloc")
    a.store(ctx, 0x60, 'rax')

    a.load(ctx, 'rcx', 0x60)
    a.load(ctx, 'rdx', 0x38)
    a.load(ctx, 'r8', 0x58)
    a.shl64(ctx, 'r8', 2)
    a.call_iat(ctx, "RtlMoveMemory")

    a.load(ctx, 'rax', 0x50)
    a.load_imm64(ctx, 'rcx', 1)
    a.sub(ctx, 'rax', 'rcx')
    a.store(ctx, 0x80, 'rax')

    shift_loop = ctx.len()
    a.load(ctx, 'rax', 0x80)
    a.load(ctx, 'rcx', 0x08)
    a.cmp(ctx, 'rax', 'rcx')
    jl_shift_done = a.jcc(ctx, 0x8C)

    a.load(ctx, 'rcx', 0x40)
    a.load(ctx, 'rax', 0x80)
    a.load_idx32(ctx, 'edx', 'rcx', 'rax', 4, 0)
    a.store_idx32(ctx, 'rcx', 'rax', 4, 4, 'edx')

    a.load(ctx, 'rax', 0x80)
    a.dec64(ctx, 'rax')
    a.store(ctx, 0x80, 'rax')
    rel = shift_loop - (ctx.len() + 5)
    ctx.emit(bytes([0xE9]) + ctx.i32(rel))
    a.patch(ctx, jl_shift_done)

    a.load(ctx, 'rcx', 0x40)
    a.load(ctx, 'rax', 0x08)
    a.load(ctx, 'rdx', 0x18)
    a.store_idx32(ctx, 'rcx', 'rax', 4, 0, 'edx')

    a.load(ctx, 'rcx', 0x00)
    a.load(ctx, 'rdx', 0x58)
    a.store_disp(ctx, 'rcx', ARR_LENGTH_OFF, 'rdx')

    a.load(ctx, 'rcx', 0x40)
    a.load(ctx, 'rdx', 0x58)
    a.load(ctx, 'r8', 0x38)
    a.call_rva(ctx, ctx.method_registry.get('_arr_recompute_offsets').rva)
    a.store(ctx, 0x68, 'rax')

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_CAPACITY_OFF)
    a.load(ctx, 'rdx', 0x68)
    a.cmp(ctx, 'rdx', 'rcx')
    jle_cap = a.jcc(ctx, 0x8E)

    a.load_disp(ctx, 'rax', 'rax', ARR_CAPACITY_OFF)
    a.shl64(ctx, 'rax', 1)
    a.load(ctx, 'rdx', 0x68)
    a.load_imm64(ctx, 'rcx', 64)
    a.add(ctx, 'rdx', 'rcx')
    a.cmp(ctx, 'rax', 'rdx')
    jae_rax2 = a.jcc(ctx, 0x83)
    a.mov(ctx, 'rax', 'rdx')
    a.patch(ctx, jae_rax2)
    a.store(ctx, 0x70, 'rax')

    a.load(ctx, 'r9', 0x70)
    a.load(ctx, 'r8', 0x30)
    a.load(ctx, 'rcx', 0x48)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapReAlloc")
    a.store(ctx, 0x30, 'rax')
    a.load(ctx, 'rcx', 0x00)
    a.store_disp(ctx, 'rcx', ARR_PTR_OFF, 'rax')
    a.load(ctx, 'rdx', 0x70)
    a.store_disp(ctx, 'rcx', ARR_CAPACITY_OFF, 'rdx')
    a.patch(ctx, jle_cap)

    a.load(ctx, 'rax', 0x50)
    a.load_imm64(ctx, 'rcx', 1)
    a.sub(ctx, 'rax', 'rcx')
    a.store(ctx, 0x80, 'rax')

    data_shift_loop = ctx.len()
    a.load(ctx, 'rax', 0x80)
    a.load(ctx, 'rcx', 0x08)
    a.cmp(ctx, 'rax', 'rcx')
    jl_data_done = a.jcc(ctx, 0x8C)

    a.load(ctx, 'rcx', 0x60)                        
    a.load(ctx, 'rax', 0x80)                        
    a.load_idx32(ctx, 'edx', 'rcx', 'rax', 4, 0)    
    a.load(ctx, 'rcx', 0x30)                        
    a.mov32(ctx, 'eax', 'edx')                      
    a.mov(ctx, 'rdx', 'rax')
    a.add(ctx, 'rdx', 'rcx')                        
    a.store(ctx, 0x88, 'rdx')

    a.load(ctx, 'rcx', 0x38)                        
    a.load(ctx, 'rax', 0x80)
    a.load_idx32(ctx, 'eax', 'rcx', 'rax', 4, 4)    
    a.load(ctx, 'rcx', 0x30)
    a.add(ctx, 'rcx', 'rax')                        
    a.store(ctx, 0x90, 'rcx')

    a.load(ctx, 'r8', 0x40)
    a.load(ctx, 'rax', 0x80)
    a.load_idx32(ctx, 'r8d', 'r8', 'rax', 4, 4)     

    a.load_imm64(ctx, 'r9', 8)
    ends = []
    for c, sz in [(T_INT8,1),(T_INT16,2),(T_INT32,4),
                   (T_FLOAT,4),(T_INT64,8),(T_DOUBLE,8),(T_CHAR_P,8)]:
        a.load_imm32(ctx, 'eax', c)
        a.cmp32(ctx, 'r8d', 'eax')
        jne = a.jcc(ctx, 0x85)
        a.load_imm64(ctx, 'r9', sz)
        j = a.jmp(ctx)
        ends.append(j)
        a.patch(ctx, jne)
    for j in ends:
        a.patch(ctx, j)

    a.load(ctx, 'rcx', 0x90)
    a.load(ctx, 'rdx', 0x88)
    a.mov(ctx, 'r8', 'r9')
    a.call_iat(ctx, "RtlMoveMemory")

    a.load(ctx, 'rax', 0x80)
    a.dec64(ctx, 'rax')
    a.store(ctx, 0x80, 'rax')
    rel = data_shift_loop - (ctx.len() + 5)
    ctx.emit(bytes([0xE9]) + ctx.i32(rel))
    a.patch(ctx, jl_data_done)

    a.load(ctx, 'rcx', 0x38)
    a.load(ctx, 'rax', 0x08)
    a.load_idx32(ctx, 'eax', 'rcx', 'rax', 4, 0)
    a.load(ctx, 'rcx', 0x30)
    a.add(ctx, 'rcx', 'rax')

    ends2 = []
    for c, kind in [(T_INT8,'i8'),(T_INT16,'i16'),(T_INT32,'i32'),
                     (T_INT64,'i64'),(T_FLOAT,'i32'),(T_DOUBLE,'i64')]:
        a.load_imm32(ctx, 'eax', c)
        a.load(ctx, 'rdx', 0x18)
        a.cmp32(ctx, 'edx', 'eax')
        jne = a.jcc(ctx, 0x85)
        if kind == 'i8':
            a.load(ctx, 'rdx', 0x10); a.store8_disp(ctx, 'rcx', 0, 'dl')
        elif kind == 'i16':
            a.load(ctx, 'rdx', 0x10); a.store16(ctx, 'rcx', 0, 'edx')
        elif kind == 'i32':
            a.load(ctx, 'rdx', 0x10); a.store32_disp(ctx, 'rcx', 0, 'edx')
        elif kind == 'i64':
            a.load(ctx, 'rdx', 0x10); a.store_disp(ctx, 'rcx', 0, 'rdx')
        j = a.jmp(ctx)
        ends2.append(j)
        a.patch(ctx, jne)
    a.load(ctx, 'rdx', 0x10)
    a.store_disp(ctx, 'rcx', 0, 'rdx')
    for j in ends2:
        a.patch(ctx, j)

    a.load(ctx, 'r8', 0x60)
    a.load(ctx, 'rcx', 0x48)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapFree")

    a.load(ctx, 'rax', 0x00)
    a.load(ctx, 'rdx', 0x68)
    a.store_disp(ctx, 'rax', ARR_USED_BYTES_OFF, 'rdx')

    a.xor64(ctx, 'rax', 'rax')
    jmp_done = a.jmp(ctx)
    a.patch(ctx, jmp_err)
    a.patch(ctx, jmp_done)
    a.add_rsp(ctx, LOCAL)
    ctx.end_method()

def _gen_remove(ctx):
    ctx.start_method('_arr_remove',
                     [ctypes.c_void_p, ctypes.c_uint64],
                     ret_type=ctypes.c_uint64)

    LOCAL = 0x100
    a.sub_rsp(ctx, LOCAL)
    a.store(ctx, 0x00, 'rcx')       
    a.store(ctx, 0x08, 'rdx')       
    a.mov_rax_mem_abs(ctx, ctx.data_rva + DATA_OFF_HEAP)
    a.store(ctx, 0x28, 'rax')       

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.load(ctx, 'rdx', 0x08)
    a.cmp(ctx, 'rdx', 'rcx')
    jb_ok = a.jcc(ctx, 0x82)
    a.load_imm64(ctx, 'rax', 1)
    jmp_err = a.jmp(ctx)
    a.patch(ctx, jb_ok)

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.store(ctx, 0x30, 'rcx')
    a.load_imm64(ctx, 'rdx', 1)
    a.sub(ctx, 'rcx', 'rdx')
    a.store(ctx, 0x38, 'rcx')

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_PTR_OFF)
    a.store(ctx, 0x10, 'rcx')
    a.load_disp(ctx, 'rcx', 'rax', ARR_OFFSETS_PTR_OFF)
    a.store(ctx, 0x18, 'rcx')
    a.load_disp(ctx, 'rcx', 'rax', ARR_TYPES_PTR_OFF)
    a.store(ctx, 0x20, 'rcx')

    a.load(ctx, 'rax', 0x30)
    a.shl64(ctx, 'rax', 2)
    a.mov(ctx, 'r8', 'rax')
    a.load(ctx, 'rcx', 0x28)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapAlloc")
    a.store(ctx, 0x40, 'rax')

    a.load(ctx, 'rcx', 0x40)
    a.load(ctx, 'rdx', 0x18)
    a.load(ctx, 'r8', 0x30)
    a.shl64(ctx, 'r8', 2)
    a.call_iat(ctx, "RtlMoveMemory")

    a.load(ctx, 'rax', 0x08)
    a.store(ctx, 0x50, 'rax')

    shift_types_loop = ctx.len()
    a.load(ctx, 'rax', 0x30)
    a.load_imm64(ctx, 'rcx', 1)
    a.sub(ctx, 'rax', 'rcx')
    a.load(ctx, 'rcx', 0x50)
    a.cmp(ctx, 'rcx', 'rax')
    jge_types_done = a.jcc(ctx, 0x8D)

    a.load(ctx, 'rcx', 0x20)
    a.load(ctx, 'rax', 0x50)
    a.load_idx32(ctx, 'edx', 'rcx', 'rax', 4, 4)
    a.store_idx32(ctx, 'rcx', 'rax', 4, 0, 'edx')

    a.load(ctx, 'rax', 0x50)
    a.inc64(ctx, 'rax')
    a.store(ctx, 0x50, 'rax')
    rel = shift_types_loop - (ctx.len() + 5)
    ctx.emit(bytes([0xE9]) + ctx.i32(rel))
    a.patch(ctx, jge_types_done)

    a.load(ctx, 'rcx', 0x00)
    a.load(ctx, 'rdx', 0x38)
    a.store_disp(ctx, 'rcx', ARR_LENGTH_OFF, 'rdx')

    a.load(ctx, 'rcx', 0x20)
    a.load(ctx, 'rdx', 0x38)
    a.load(ctx, 'r8', 0x18)
    a.call_rva(ctx, ctx.method_registry.get('_arr_recompute_offsets').rva)
    a.store(ctx, 0x48, 'rax')

    a.load(ctx, 'rax', 0x08)
    a.store(ctx, 0x50, 'rax')

    data_shift_loop = ctx.len()
    a.load(ctx, 'rax', 0x50)
    a.load(ctx, 'rcx', 0x38)
    a.cmp(ctx, 'rax', 'rcx')
    jge_data_done = a.jcc(ctx, 0x8D)

    a.load(ctx, 'rcx', 0x40)
    a.load(ctx, 'rax', 0x50)
    a.load_idx32(ctx, 'edx', 'rcx', 'rax', 4, 4)
    a.load(ctx, 'rcx', 0x10)
    a.mov32(ctx, 'eax', 'edx')
    a.mov(ctx, 'rdx', 'rax')
    a.add(ctx, 'rdx', 'rcx')
    a.store(ctx, 0x58, 'rdx')

    a.load(ctx, 'rcx', 0x18)
    a.load(ctx, 'rax', 0x50)
    a.load_idx32(ctx, 'eax', 'rcx', 'rax', 4, 0)
    a.load(ctx, 'rcx', 0x10)
    a.add(ctx, 'rcx', 'rax')
    a.store(ctx, 0x60, 'rcx')

    a.load(ctx, 'r8', 0x20)
    a.load(ctx, 'rax', 0x50)
    a.load_idx32(ctx, 'r8d', 'r8', 'rax', 4, 0)

    a.load_imm64(ctx, 'r9', 8)
    ends = []
    for c, sz in [(T_INT8,1),(T_INT16,2),(T_INT32,4),
                   (T_FLOAT,4),(T_INT64,8),(T_DOUBLE,8),(T_CHAR_P,8)]:
        a.load_imm32(ctx, 'eax', c)
        a.cmp32(ctx, 'r8d', 'eax')
        jne = a.jcc(ctx, 0x85)
        a.load_imm64(ctx, 'r9', sz)
        j = a.jmp(ctx)
        ends.append(j)
        a.patch(ctx, jne)
    for j in ends:
        a.patch(ctx, j)

    a.load(ctx, 'rcx', 0x60)
    a.load(ctx, 'rdx', 0x58)
    a.mov(ctx, 'r8', 'r9')
    a.call_iat(ctx, "RtlMoveMemory")

    a.load(ctx, 'rax', 0x50)
    a.inc64(ctx, 'rax')
    a.store(ctx, 0x50, 'rax')
    rel = data_shift_loop - (ctx.len() + 5)
    ctx.emit(bytes([0xE9]) + ctx.i32(rel))
    a.patch(ctx, jge_data_done)

    a.load(ctx, 'r8', 0x40)
    a.load(ctx, 'rcx', 0x28)
    a.xor32(ctx, 'edx', 'edx')
    a.call_iat(ctx, "HeapFree")

    a.load(ctx, 'rax', 0x00)
    a.load(ctx, 'rdx', 0x48)
    a.store_disp(ctx, 'rax', ARR_USED_BYTES_OFF, 'rdx')

    a.xor64(ctx, 'rax', 'rax')
    jmp_done = a.jmp(ctx)
    a.patch(ctx, jmp_err)
    a.patch(ctx, jmp_done)
    a.add_rsp(ctx, LOCAL)
    ctx.end_method()

def _gen_resize(ctx):
    ctx.start_method('_arr_resize',
                     [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32,
                      ctypes.c_uint32, ctypes.c_uint32],
                     ret_type=ctypes.c_uint64)

    LOCAL = 0x80
    a.sub_rsp(ctx, LOCAL)
    a.store(ctx, 0x00, 'rcx')       
    a.store(ctx, 0x08, 'rdx')       
    a.store(ctx, 0x10, 'r8')        
    a.store(ctx, 0x18, 'r9')        
    a.load_disp(ctx, 'rax', 'rsp', LOCAL + 0x68)  
    a.store(ctx, 0x20, 'rax')

    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.store(ctx, 0x28, 'rcx')

    a.load(ctx, 'rax', 0x08)
    a.load(ctx, 'rcx', 0x28)
    a.cmp(ctx, 'rax', 'rcx')
    je_done = a.jcc(ctx, 0x84)

    a.load(ctx, 'rax', 0x08)
    a.load(ctx, 'rcx', 0x28)
    a.cmp(ctx, 'rax', 'rcx')
    jb_shrink = a.jcc(ctx, 0x82)

    grow_loop = ctx.len()
    a.load(ctx, 'rax', 0x00)
    a.load_disp(ctx, 'rcx', 'rax', ARR_LENGTH_OFF)
    a.load(ctx, 'rdx', 0x08)
    a.cmp(ctx, 'rcx', 'rdx')
    jge_grow_done = a.jcc(ctx, 0x8D)

    a.load(ctx, 'rcx', 0x00)                
    a.xor64(ctx, 'rdx', 'rdx')              
    a.load(ctx, 'r8', 0x10)                 
    a.load(ctx, 'r9', 0x18)                 

    a.sub_rsp(ctx, 0x30)
    a.load(ctx, 'rax', 0x20 + 0x30)
    a.mov32(ctx, 'eax', 'eax')
    a.store(ctx, 0x20, 'rax')               
    a.call_rva(ctx, ctx.method_registry.get('_arr_append').rva)
    a.add_rsp(ctx, 0x30)

    a.test64(ctx, 'rax', 'rax')
    jnz_err = a.jcc(ctx, 0x85)

    rel = grow_loop - (ctx.len() + 5)
    ctx.emit(bytes([0xE9]) + ctx.i32(rel))
    a.patch(ctx, jge_grow_done)

    a.xor64(ctx, 'rax', 'rax')
    jmp_ok = a.jmp(ctx)

    a.patch(ctx, jb_shrink)

    a.load(ctx, 'rax', 0x00)
    a.load(ctx, 'rdx', 0x08)
    a.store_disp(ctx, 'rax', ARR_LENGTH_OFF, 'rdx')

    a.load(ctx, 'rcx', 0x00)
    a.load_disp(ctx, 'rcx', 'rcx', ARR_TYPES_PTR_OFF)
    a.load(ctx, 'rdx', 0x08)
    a.load(ctx, 'r8', 0x00)
    a.load_disp(ctx, 'r8', 'r8', ARR_OFFSETS_PTR_OFF)
    a.call_rva(ctx, ctx.method_registry.get('_arr_recompute_offsets').rva)

    a.load(ctx, 'rcx', 0x00)
    a.store_disp(ctx, 'rcx', ARR_USED_BYTES_OFF, 'rax')

    a.xor64(ctx, 'rax', 'rax')
    jmp_shrink_done = a.jmp(ctx)

    a.patch(ctx, jnz_err)
    a.load_imm64(ctx, 'rax', 1)

    a.patch(ctx, jmp_ok)
    a.patch(ctx, jmp_shrink_done)
    a.patch(ctx, je_done)

    a.add_rsp(ctx, LOCAL)
    ctx.end_method()

_RUNTIME_GENERATORS = {
    '_arr_recompute_offsets': _gen_recompute_offsets,
    '_arr_append':            _gen_append,
    '_arr_insert':            _gen_insert,
    '_arr_remove':            _gen_remove,
    '_arr_resize':            _gen_resize,
}

_RUNTIME_DEPS = {
    '_arr_append':            ('_arr_recompute_offsets',),
    '_arr_insert':            ('_arr_recompute_offsets',),
    '_arr_remove':            ('_arr_recompute_offsets',),
    '_arr_resize':            ('_arr_recompute_offsets', '_arr_append'),
    '_arr_recompute_offsets': (),
}

def _ensure_one(ctx, name):
    """Сгенерить один runtime-метод и его зависимости, если ещё не сгенерены."""
    if name in ctx._arr_runtime_done:
        return
    for dep in _RUNTIME_DEPS.get(name, ()):
        _ensure_one(ctx, dep)
    if name in ctx._arr_runtime_done:
        return
    _RUNTIME_GENERATORS[name](ctx)
    ctx._arr_runtime_done.add(name)

def ensure_runtime(ctx, only):
    """Ленивая генерация array runtime.

    only=None  — сгенерить всё (обратная совместимость, но лучше не звать).
    only=[...] — сгенерить только указанные методы + их зависимости.
    """
    _ensure_state(ctx)
    if only is None:

        for name in _RUNTIME_GENERATORS:
            _ensure_one(ctx, name)
        return
    for name in only:
        _ensure_one(ctx, name)

def array_append(ctx, arr, value, type_=None):
    ensure_alive(ctx, arr)
    arr.forbid_dynamic("array_append")
    ensure_runtime(ctx, only=['_arr_append'])
    if type_ is None:
        if arr.is_homogeneous and arr.types:
            type_ = arr.types[0]
        elif arr.types:

            raise ValueError(
                f"array_append: для смешанного массива укажите type_ явно"
            )
        else:
            type_ = type_of_value(value)
    code = type_to_code(type_)
    size = code_to_size(code)
    align = code_to_align(code)
    value_bits = _value_to_bits(value, code)
    slot_rva = ctx.rva_of(arr.name)
    ctx.call_method('_arr_append', (
        Rva(slot_rva),
        value_bits,
        code,
        size,
        align,
    ))

def array_insert(ctx, arr, index, value, type_=None):
    ensure_alive(ctx, arr)
    arr.forbid_dynamic("array_insert")
    ensure_runtime(ctx, only=['_arr_insert'])
    if type_ is None:
        if arr.is_homogeneous and arr.types:
            type_ = arr.types[0]
        elif arr.types:

            raise ValueError(
                f"array_append: для смешанного массива укажите type_ явно"
            )
        else:
            type_ = type_of_value(value)
    code = type_to_code(type_)
    size = code_to_size(code)
    align = code_to_align(code)
    value_bits = _value_to_bits(value, code)
    slot_rva = ctx.rva_of(arr.name)

    ctx.call_method('_arr_insert', (
        Rva(slot_rva),
        index,
        value_bits,
        code,
        size,
        align,
    ))

def array_remove(ctx, arr, index):
    ensure_alive(ctx, arr)
    arr.forbid_dynamic("array_remove")
    ensure_runtime(ctx, only=['_arr_remove'])
    slot_rva = ctx.rva_of(arr.name)
    ctx.call_method('_arr_remove', (
        Rva(slot_rva),
        index,
    ))

def array_resize(ctx, arr, new_length, type_=None):
    ensure_alive(ctx, arr)
    arr.forbid_dynamic("array_resize")
    ensure_runtime(ctx, only=['_arr_resize'])
    if type_ is None:
        if arr.types:
            type_ = arr.types[-1]
        else:
            type_ = ctypes.c_int32
    code = type_to_code(type_)
    size = code_to_size(code)
    align = code_to_align(code)
    slot_rva = ctx.rva_of(arr.name)

    ctx.call_method('_arr_resize', (
        Rva(slot_rva),
        new_length,
        code,
        size,
        align,
    ))

def _value_to_bits(value, code):
    """value + code → uint64 bits."""
    if code == T_FLOAT:
        return struct.unpack("<I", struct.pack("<f", float(value)))[0]
    if code == T_DOUBLE:
        return struct.unpack("<Q", struct.pack("<d", float(value)))[0]
    if code == T_CHAR_P:
        if isinstance(value, Rva):
            return value.rva
        if isinstance(value, str):
            raise ValueError(
                "array: для c_char_p передавайте Rva(string_rva) — "
                "имя строки в этом контексте недоступно"
            )
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        raise TypeError(f"array: не могу преобразовать c_char_p {value!r}")
    if isinstance(value, bool):
        return int(value) & 0xFFFFFFFFFFFFFFFF
    if isinstance(value, int):
        return value & 0xFFFFFFFFFFFFFFFF
    raise TypeError(f"array: не могу преобразовать {value!r} в bits")
