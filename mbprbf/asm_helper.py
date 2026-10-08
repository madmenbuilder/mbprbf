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


"""asm_helper.py - эмиттеры для runtime-функций MBPRBF.

Дисциплина:
  - Внутри функции все локальные переменные и сохранённые аргументы
    живут на стеке по смещениям от RSP (0x00, 0x08, 0x10, ...).
  - Регистры используются только для:
      * загрузки аргументов непосредственно перед call_iat
      * коротких промежуточных вычислений между двумя call_iat
  - Перед call_iat ВСЕ нужные аргументы загружаются из стека в rcx/rdx/r8/r9.
  - После call_iat результат (rax) сразу сохраняется на стек.
  - Регистры после call_iat считаются испорченными, восстанавливаем из стека.
"""

import struct

_R64 = {'rax':0,'rcx':1,'rdx':2,'rbx':3,'rsp':4,'rbp':5,'rsi':6,'rdi':7,
        'r8':8,'r9':9,'r10':10,'r11':11,'r12':12,'r13':13,'r14':14,'r15':15}
_R32 = {'eax':0,'ecx':1,'edx':2,'ebx':3,'esp':4,'ebp':5,'esi':6,'edi':7,
        'r8d':8,'r9d':9,'r10d':10,'r11d':11,'r12d':12,'r13d':13,'r14d':14,'r15d':15}
_R8  = {'al':0,'cl':1,'dl':2,'bl':3,'spl':4,'bpl':5,'sil':6,'dil':7,
        'r8b':8,'r9b':9,'r10b':10,'r11b':11,'r12b':12,'r13b':13,'r14b':14,'r15b':15}

def _rex(w=0, r=0, x=0, b=0):
    return 0x40 | (w << 3) | (r << 2) | (x << 1) | b

def _disp32(ctx, val):
    return ctx.i32(val)

def load(ctx, dst64, rsp_off):
    """mov dst64, [rsp + disp32]."""
    n = _R64[dst64]
    rex = _rex(w=1, r=(n >> 3) & 1)
    modrm = 0x84 | ((n & 7) << 3)     
    sib = 0x24                        
    ctx.emit(bytes([rex, 0x8B, modrm, sib]) + _disp32(ctx, rsp_off))

def load32(ctx, dst32, rsp_off):
    """mov dst32, [rsp + disp32]."""
    n = _R32[dst32]
    rex = 0x40 | ((n >> 3) << 2)
    modrm = 0x84 | ((n & 7) << 3)
    sib = 0x24
    if rex == 0x40:
        ctx.emit(bytes([0x8B, modrm, sib]) + _disp32(ctx, rsp_off))
    else:
        ctx.emit(bytes([rex, 0x8B, modrm, sib]) + _disp32(ctx, rsp_off))

def store(ctx, rsp_off, src64):
    """mov [rsp + disp32], src64."""
    s = _R64[src64]
    rex = _rex(w=1, r=(s >> 3) & 1)
    modrm = 0x84 | ((s & 7) << 3)
    sib = 0x24
    ctx.emit(bytes([rex, 0x89, modrm, sib]) + _disp32(ctx, rsp_off))

def store32(ctx, rsp_off, src32):
    """mov [rsp + disp32], src32."""
    s = _R32[src32]
    rex = 0x40 | ((s >> 3) << 2)
    modrm = 0x84 | ((s & 7) << 3)
    sib = 0x24
    if rex == 0x40:
        ctx.emit(bytes([0x89, modrm, sib]) + _disp32(ctx, rsp_off))
    else:
        ctx.emit(bytes([rex, 0x89, modrm, sib]) + _disp32(ctx, rsp_off))

def store_imm64(ctx, rsp_off, imm):
    """mov qword [rsp + disp32], imm32 (sign-extended)."""
    modrm = 0x84 | (0 << 3)
    sib = 0x24
    ctx.emit(bytes([0x48, 0xC7, modrm, sib]) + _disp32(ctx, rsp_off)
             + struct.pack("<I", imm & 0xFFFFFFFF))

def store_imm32(ctx, rsp_off, imm):
    """mov dword [rsp + disp32], imm32."""
    modrm = 0x84 | (0 << 3)
    sib = 0x24
    ctx.emit(bytes([0xC7, modrm, sib]) + _disp32(ctx, rsp_off)
             + struct.pack("<I", imm & 0xFFFFFFFF))

def load_imm64(ctx, dst64, imm):
    """mov dst64, imm64."""
    n = _R64[dst64]
    rex = _rex(w=1, b=(n >> 3) & 1)
    opcode = 0xB8 + (n & 7)
    ctx.emit(bytes([rex, opcode]) + struct.pack("<Q", imm & 0xFFFFFFFFFFFFFFFF))

def load_imm32(ctx, dst32, imm):
    """mov dst32, imm32."""
    n = _R32[dst32]
    rex = 0x40 | (n >> 3)
    opcode = 0xB8 + (n & 7)
    if rex == 0x40:
        ctx.emit(bytes([opcode]) + struct.pack("<I", imm & 0xFFFFFFFF))
    else:
        ctx.emit(bytes([rex, opcode]) + struct.pack("<I", imm & 0xFFFFFFFF))

def add(ctx, dst64, src64):
    d = _R64[dst64]; s = _R64[src64]
    ctx.emit(bytes([_rex(w=1, r=(s >> 3) & 1, b=(d >> 3) & 1),
                    0x01, 0xC0 | ((s & 7) << 3) | (d & 7)]))

def add32(ctx, dst32, src32):
    d = _R32[dst32]; s = _R32[src32]
    rex = 0x40 | ((s >> 3) << 2) | (d >> 3)
    modrm = 0xC0 | ((s & 7) << 3) | (d & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x01, modrm]))
    else:
        ctx.emit(bytes([rex, 0x01, modrm]))

def sub(ctx, dst64, src64):
    d = _R64[dst64]; s = _R64[src64]
    ctx.emit(bytes([_rex(w=1, r=(s >> 3) & 1, b=(d >> 3) & 1),
                    0x29, 0xC0 | ((s & 7) << 3) | (d & 7)]))

def cmp(ctx, a64, b64):
    x = _R64[a64]; y = _R64[b64]
    ctx.emit(bytes([_rex(w=1, r=(y >> 3) & 1, b=(x >> 3) & 1),
                    0x39, 0xC0 | ((y & 7) << 3) | (x & 7)]))

def mov(ctx, dst64, src64):
    d = _R64[dst64]; s = _R64[src64]
    ctx.emit(bytes([_rex(w=1, r=(s >> 3) & 1, b=(d >> 3) & 1),
                    0x89, 0xC0 | ((s & 7) << 3) | (d & 7)]))

def mov32(ctx, dst32, src32):
    d = _R32[dst32]; s = _R32[src32]
    rex = 0x40 | ((s >> 3) << 2) | (d >> 3)
    modrm = 0xC0 | ((s & 7) << 3) | (d & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x89, modrm]))
    else:
        ctx.emit(bytes([rex, 0x89, modrm]))

def movsxd(ctx, dst64, src32):
    d = _R64[dst64]; s = _R32[src32]
    ctx.emit(bytes([_rex(w=1, r=(d >> 3) & 1, b=(s >> 3) & 1),
                    0x63, 0xC0 | ((d & 7) << 3) | (s & 7)]))

def xor32(ctx, a32, b32):
    x = _R32[a32]; y = _R32[b32]
    rex = 0x40 | ((y >> 3) << 2) | (x >> 3)
    modrm = 0xC0 | ((y & 7) << 3) | (x & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x31, modrm]))
    else:
        ctx.emit(bytes([rex, 0x31, modrm]))

def xor64(ctx, a64, b64):
    x = _R64[a64]; y = _R64[b64]
    ctx.emit(bytes([_rex(w=1, r=(y >> 3) & 1, b=(x >> 3) & 1),
                    0x31, 0xC0 | ((y & 7) << 3) | (x & 7)]))

def neg64(ctx, r):
    n = _R64[r]
    ctx.emit(bytes([_rex(w=1, b=(n >> 3) & 1), 0xF7, 0xC0 | (3 << 3) | (n & 7)]))

def and64(ctx, dst64, src64):
    d = _R64[dst64]; s = _R64[src64]
    ctx.emit(bytes([_rex(w=1, r=(s >> 3) & 1, b=(d >> 3) & 1),
                    0x21, 0xC0 | ((s & 7) << 3) | (d & 7)]))

def test64(ctx, a64, b64):
    x = _R64[a64]; y = _R64[b64]
    ctx.emit(bytes([_rex(w=1, r=(y >> 3) & 1, b=(x >> 3) & 1),
                    0x85, 0xC0 | ((y & 7) << 3) | (x & 7)]))

def shl64(ctx, r, imm):
    n = _R64[r]
    ctx.emit(bytes([_rex(w=1, b=(n >> 3) & 1),
                    0xC1, 0xC0 | (4 << 3) | (n & 7), imm & 0xFF]))

def inc64(ctx, r):
    n = _R64[r]
    if n >= 8:
        ctx.emit(bytes([0x49, 0xFF, 0xC0 | (n & 7)]))
    else:
        ctx.emit(bytes([0x48, 0xFF, 0xC0 | (n & 7)]))

def dec64(ctx, r):
    n = _R64[r]
    if n >= 8:
        ctx.emit(bytes([0x49, 0xFF, 0xC8 | (n & 7)]))
    else:
        ctx.emit(bytes([0x48, 0xFF, 0xC8 | (n & 7)]))

def load_idx(ctx, dst64, base, index, scale, disp=0):
    """mov dst64, [base + index*scale + disp32]. scale: 1, 2, 4, 8."""
    d = _R64[dst64]; b = _R64[base]; i = _R64[index]
    sc = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
    rex = _rex(w=1, r=(d >> 3) & 1, x=(i >> 3) & 1, b=(b >> 3) & 1)
    modrm = 0x84 | ((d & 7) << 3)               
    sib = (sc << 6) | ((i & 7) << 3) | (b & 7)
    ctx.emit(bytes([rex, 0x8B, modrm, sib]) + _disp32(ctx, disp))

def load_idx32(ctx, dst32, base, index, scale, disp=0):
    """mov dst32, [base + index*scale + disp32]."""
    d = _R32[dst32]; b = _R64[base]; i = _R64[index]
    sc = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
    rex = 0x40 | ((d >> 3) << 2) | ((i >> 3) << 1) | (b >> 3)
    modrm = 0x84 | ((d & 7) << 3)
    sib = (sc << 6) | ((i & 7) << 3) | (b & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x8B, modrm, sib]) + _disp32(ctx, disp))
    else:
        ctx.emit(bytes([rex, 0x8B, modrm, sib]) + _disp32(ctx, disp))

def store_idx(ctx, base, index, scale, disp, src64):
    """mov [base + index*scale + disp32], src64."""
    s = _R64[src64]; b = _R64[base]; i = _R64[index]
    sc = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
    rex = _rex(w=1, r=(s >> 3) & 1, x=(i >> 3) & 1, b=(b >> 3) & 1)
    modrm = 0x84 | ((s & 7) << 3)
    sib = (sc << 6) | ((i & 7) << 3) | (b & 7)
    ctx.emit(bytes([rex, 0x89, modrm, sib]) + _disp32(ctx, disp))

def store_idx32(ctx, base, index, scale, disp, src32):
    """mov [base + index*scale + disp32], src32."""
    s = _R32[src32]; b = _R64[base]; i = _R64[index]
    sc = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
    rex = 0x40 | ((s >> 3) << 2) | ((i >> 3) << 1) | (b >> 3)
    modrm = 0x84 | ((s & 7) << 3)
    sib = (sc << 6) | ((i & 7) << 3) | (b & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x89, modrm, sib]) + _disp32(ctx, disp))
    else:
        ctx.emit(bytes([rex, 0x89, modrm, sib]) + _disp32(ctx, disp))

def load_disp(ctx, dst64, base, disp):
    d = _R64[dst64]; b = _R64[base]
    rex = _rex(w=1, r=(d >> 3) & 1, b=(b >> 3) & 1)
    if base in ('rbp', 'r13'):
        modrm = 0x80 | ((d & 7) << 3) | 5
    elif b == 4:  
        modrm = 0x84 | ((d & 7) << 3)
        ctx.emit(bytes([rex, 0x8B, modrm, 0x24]) + _disp32(ctx, disp))
        return
    else:
        modrm = 0x80 | ((d & 7) << 3) | (b & 7)
    ctx.emit(bytes([rex, 0x8B, modrm]) + _disp32(ctx, disp))

def store_disp(ctx, base, disp, src64):
    s = _R64[src64]; b = _R64[base]
    rex = _rex(w=1, r=(s >> 3) & 1, b=(b >> 3) & 1)
    if base in ('rbp', 'r13'):
        modrm = 0x80 | ((s & 7) << 3) | 5
    elif b == 4:
        modrm = 0x84 | ((s & 7) << 3)
        ctx.emit(bytes([rex, 0x89, modrm, 0x24]) + _disp32(ctx, disp))
        return
    else:
        modrm = 0x80 | ((s & 7) << 3) | (b & 7)
    ctx.emit(bytes([rex, 0x89, modrm]) + _disp32(ctx, disp))

def store8(ctx, base, disp, src8):
    s = _R8[src8]; b = _R64[base]
    rex = 0x40 | ((s >> 3) << 2) | (b >> 3)
    if rex == 0x40:
        rex = 0                          
    if base in ('rbp', 'r13'):
        modrm = 0x80 | ((s & 7) << 3) | 5
    else:
        modrm = 0x80 | ((s & 7) << 3) | (b & 7)
    if rex == 0:
        ctx.emit(bytes([0x88, modrm]) + _disp32(ctx, disp))
    else:
        ctx.emit(bytes([rex, 0x88, modrm]) + _disp32(ctx, disp))

def store16(ctx, base, disp, src32):
    s = _R32[src32]; b = _R64[base]
    rex = 0x40 | ((s >> 3) << 2) | (b >> 3)
    if base in ('rbp', 'r13'):
        modrm = 0x80 | ((s & 7) << 3) | 5
    else:
        modrm = 0x80 | ((s & 7) << 3) | (b & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x66, 0x89, modrm]) + _disp32(ctx, disp))
    else:
        ctx.emit(bytes([0x66, rex, 0x89, modrm]) + _disp32(ctx, disp))

def store32_disp(ctx, base, disp, src32):
    s = _R32[src32]; b = _R64[base]
    rex = 0x40 | ((s >> 3) << 2) | (b >> 3)
    if base in ('rbp', 'r13'):
        modrm = 0x80 | ((s & 7) << 3) | 5
    else:
        modrm = 0x80 | ((s & 7) << 3) | (b & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x89, modrm]) + _disp32(ctx, disp))
    else:
        ctx.emit(bytes([rex, 0x89, modrm]) + _disp32(ctx, disp))

def store8_disp(ctx, base, disp, src8):
    s = _R8[src8]; b = _R64[base]
    rex = 0x40 | ((s >> 3) << 2) | (b >> 3)
    if rex == 0x40:
        rex = 0
    if base in ('rbp', 'r13'):
        modrm = 0x80 | ((s & 7) << 3) | 5
    else:
        modrm = 0x80 | ((s & 7) << 3) | (b & 7)
    if rex == 0:
        ctx.emit(bytes([0x88, modrm]) + _disp32(ctx, disp))
    else:
        ctx.emit(bytes([rex, 0x88, modrm]) + _disp32(ctx, disp))

def jmp(ctx):
    """jmp placeholder. Возвращает offset rel32."""
    off = ctx.len()
    ctx.emit(bytes([0xE9, 0, 0, 0, 0]))
    return off

def jcc(ctx, cc):
    """Условный jump placeholder. cc — код условия (0x84=je, 0x85=jne, ...)."""
    off = ctx.len()
    ctx.emit(bytes([0x0F, cc, 0, 0, 0, 0]))
    return off

def patch(ctx, off):
    """Патч 6-байтового jcc или 5-байтового jmp на текущую позицию."""

    b0 = ctx.code[off]
    if b0 == 0xE9:
        rel = ctx.len() - (off + 5)
        ctx.patch_i32(off + 1, rel)
    elif b0 == 0x0F:
        rel = ctx.len() - (off + 6)
        ctx.patch_i32(off + 2, rel)
    else:
        raise ValueError(f"patch: неизвестный опкод {b0:#x}")

def call_iat(ctx, name):
    ctx.used_imports.add(name)
    iat_rva = ctx.iat[name]
    ctx.emit(bytes([0x48, 0x83, 0xEC, 0x20]))       
    rel = iat_rva - (ctx.rva_now() + 6)
    ctx.emit(bytes([0xFF, 0x15]) + _disp32(ctx, rel))
    ctx.emit(bytes([0x48, 0x83, 0xC4, 0x20]))       

def call_rva(ctx, target_rva):
    rel = target_rva - (ctx.rva_now() + 5)
    ctx.emit(bytes([0xE8]) + _disp32(ctx, rel))

def sub_rsp(ctx, n):
    """sub rsp, imm32. n кратен 16."""
    if n <= 0x7F:
        ctx.emit(bytes([0x48, 0x83, 0xEC, n & 0xFF]))
    else:
        ctx.emit(bytes([0x48, 0x81, 0xEC]) + _disp32(ctx, n))

def add_rsp(ctx, n):
    if n <= 0x7F:
        ctx.emit(bytes([0x48, 0x83, 0xC4, n & 0xFF]))
    else:
        ctx.emit(bytes([0x48, 0x81, 0xC4]) + _disp32(ctx, n))

def cmp32(ctx, a32, b32):
    """cmp a32, b32. Устанавливает флаги."""
    x = _R32[a32]; y = _R32[b32]
    rex = 0x40 | ((y >> 3) << 2) | (x >> 3)
    modrm = 0xC0 | ((y & 7) << 3) | (x & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x39, modrm]))
    else:
        ctx.emit(bytes([rex, 0x39, modrm]))

def add_imm32(ctx, r32, imm):
    """add r32, imm32."""
    n = _R32[r32]
    rex = 0x40 | (n >> 3)
    modrm = 0xC0 | (0 << 3) | (n & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x81, modrm]) + _disp32(ctx, imm))
    else:
        ctx.emit(bytes([rex, 0x81, modrm]) + _disp32(ctx, imm))

def sub_imm32(ctx, r32, imm):
    """sub r32, imm32."""
    n = _R32[r32]
    rex = 0x40 | (n >> 3)
    modrm = 0xC0 | (5 << 3) | (n & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x81, modrm]) + _disp32(ctx, imm))
    else:
        ctx.emit(bytes([rex, 0x81, modrm]) + _disp32(ctx, imm))

def cmp_imm32(ctx, r32, imm):
    """cmp r32, imm32."""
    n = _R32[r32]
    rex = 0x40 | (n >> 3)
    modrm = 0xC0 | (7 << 3) | (n & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x81, modrm]) + _disp32(ctx, imm))
    else:
        ctx.emit(bytes([rex, 0x81, modrm]) + _disp32(ctx, imm))

def test32(ctx, a32, b32):
    """test a32, b32."""
    x = _R32[a32]; y = _R32[b32]
    rex = 0x40 | ((y >> 3) << 2) | (x >> 3)
    modrm = 0xC0 | ((y & 7) << 3) | (x & 7)
    if rex == 0x40:
        ctx.emit(bytes([0x85, modrm]))
    else:
        ctx.emit(bytes([rex, 0x85, modrm]))

def test_imm32(ctx, r32, imm):
    """test r32, imm32."""
    n = _R32[r32]
    rex = 0x40 | (n >> 3)
    modrm = 0xC0 | (0 << 3) | (n & 7)
    if rex == 0x40:
        ctx.emit(bytes([0xF7, modrm]) + _disp32(ctx, imm))
    else:
        ctx.emit(bytes([rex, 0xF7, modrm]) + _disp32(ctx, imm))

def neg32(ctx, r32):
    """neg r32."""
    n = _R32[r32]
    rex = 0x40 | (n >> 3)
    modrm = 0xC0 | (3 << 3) | (n & 7)
    if rex == 0x40:
        ctx.emit(bytes([0xF7, modrm]))
    else:
        ctx.emit(bytes([rex, 0xF7, modrm]))

def mov_rax_mem_abs(ctx, mem_rva):
    """mov rax, [rip + disp32]."""
    ctx.emit(bytes([0x48, 0x8B, 0x05]) + _disp32(ctx, mem_rva - (ctx.rva_now() + 7)))

def mov_rcx_mem_abs(ctx, mem_rva):
    ctx.emit(bytes([0x48, 0x8B, 0x0D]) + _disp32(ctx, mem_rva - (ctx.rva_now() + 7)))

def mov_rdx_mem_abs(ctx, mem_rva):
    ctx.emit(bytes([0x48, 0x8B, 0x15]) + _disp32(ctx, mem_rva - (ctx.rva_now() + 7)))

def mov_r8_mem_abs(ctx, mem_rva):
    ctx.emit(bytes([0x4C, 0x8B, 0x05]) + _disp32(ctx, mem_rva - (ctx.rva_now() + 7)))

def mov_r9_mem_abs(ctx, mem_rva):
    ctx.emit(bytes([0x4C, 0x8B, 0x0D]) + _disp32(ctx, mem_rva - (ctx.rva_now() + 7)))

def mov_mem_abs_rax(ctx, mem_rva):
    ctx.emit(bytes([0x48, 0x89, 0x05]) + _disp32(ctx, mem_rva - (ctx.rva_now() + 7)))
