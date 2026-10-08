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


"""methods.py - система методов по Microsoft x64 Calling Convention.

Полная реализация:
  - пролог/эпилог по ABI (8 push callee-saved),
  - распределение аргументов (RCX/RDX/R8/R9, XMM0-3, стек),
  - независимые счётчики int и float,
  - forward references (рекурсия),
  - правильное выравнивание RSP.
"""

import ctypes
import struct
from .ffi_struct import FFIStruct
from .seh import UnwindCode, UWOP_PUSH_NONVOL, UWOP_SET_FPREG, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL

PROLOGUE_SIZE = 64

def _size_of(t):
    """Размер ctypes-типа в байтах."""
    if t in (ctypes.c_bool, ctypes.c_char, ctypes.c_byte, ctypes.c_ubyte):
        return 1
    if t in (ctypes.c_short, ctypes.c_ushort):
        return 2
    if t in (ctypes.c_int, ctypes.c_uint, ctypes.c_long, ctypes.c_ulong):
        return 4
    if t in (ctypes.c_longlong, ctypes.c_ulonglong,
             ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ssize_t):
        return 8
    if t is ctypes.c_float:
        return 4
    if t is ctypes.c_double:
        return 8
    raise ValueError(f"Неизвестный ctypes-тип: {t!r}")

def _is_float_type(t):
    return t in (ctypes.c_float, ctypes.c_double)

def _struct_field_info(t):
    result = []
    for name, ftype in t._fields_:
        field = getattr(t, name)
        result.append({
            'name': name,
            'offset': field.offset,
            'size': field.size,
            'ctype': ftype,
            'is_float': _is_float_type(ftype),
        })
    return result

def _is_struct_type(t):
    return (isinstance(t, type)
            and issubclass(t, FFIStruct)
            and t is not FFIStruct)

def _classify_struct(t):
    """MinGW x64: структура ≤8 байт → INTEGER, >8 байт → MEMORY."""
    return 'INTEGER' if ctypes.sizeof(t) <= 8 else 'MEMORY'

def _struct_classify(t):
    """MinGW x64: ≤8 байт → значение в GP, >8 байт → указатель в RCX."""
    size = ctypes.sizeof(t)
    if size > 8:
        return [{'off': 0, 'size': 8, 'is_float': False, 'is_pointer': True}]
    return [{'off': 0, 'size': size, 'is_float': False, 'is_pointer': False}]

def _struct_return_kind(t):
    """MinGW x64: >8 байт → sret, ≤8 байт → RAX."""
    return ('sret',) if ctypes.sizeof(t) > 8 else ('rax',)

class Rva:
    """Обёртка для передачи RVA-указателя в call_method.

    Значение загружается через lea reg, [rip + rva],
    а не как immediate.
    """
    __slots__ = ('rva',)

    def __init__(self, rva):
        self.rva = rva

class Mem:
    """Загрузить значение из памяти по RVA: mov reg, [rip + rva]."""
    __slots__ = ('rva',)

    def __init__(self, rva):
        self.rva = rva

class MethodArg:
    __slots__ = ('loc', 'ctype', 'is_float', 'stack_off',
                 'struct_cls', 'struct_off', 'struct_size',
                 'struct_is_first', 'is_struct_pointer')

    def __init__(self, loc, ctype, is_float, stack_off=None,
                 struct_cls=None, struct_off=0, struct_size=8,
                 struct_is_first=False, is_struct_pointer=False):
        self.loc = loc
        self.ctype = ctype
        self.is_float = is_float
        self.stack_off = stack_off
        self.struct_cls = struct_cls
        self.struct_off = struct_off
        self.struct_size = struct_size
        self.struct_is_first = struct_is_first
        self.is_struct_pointer = is_struct_pointer

    def __repr__(self):
        if self.struct_cls is not None:
            return (f"MethodArg({self.loc}, "
                    f"{self.struct_cls.__name__}"
                    f"+{self.struct_off}/{self.struct_size}"
                    f"{' FIRST' if self.struct_is_first else ''})")
        if self.loc == 'stack':
            return (f"MethodArg(stack+{self.stack_off:#x}, "
                    f"{self.ctype.__name__})")
        return f"MethodArg({self.loc}, {self.ctype.__name__})"

    def emit_load(self, ctx, dst_reg):
        if self.loc == 'stack':
            emit_mov_reg_mem_rsp(ctx, dst_reg,
                                 self.stack_off + PROLOGUE_SIZE)
        else:
            if dst_reg != self.loc:
                emit_mov_reg_reg(ctx, dst_reg, self.loc)

    def emit_load_float(self, ctx, xmm):
        if self.loc == 'stack':
            off = self.stack_off + PROLOGUE_SIZE
            n = XMM_NUM[xmm]
            rex = _rex(r=(n >> 3) & 1)
            modrm = 0x84 | ((n & 0x07) << 3)
            sib = 0x24
            ctx.emit(bytes([0xF3, rex, 0x0F, 0x10, modrm, sib])
                     + struct.pack("<i", off))
        else:
            if xmm != self.loc:
                emit_movss_xmm_xmm(ctx, xmm, self.loc)

class Method:
    __slots__ = ('name', 'args', 'ret_type', 'rva',
                 'call_fixups', 'ret_struct', 'varargs', 'n_fixed',
                 'seh_builder', 'seh_scopes', 'unwind_info',
                 'has_seh', 'body_begin_rva', 'body_end_rva',
                 'end_rva', 'prologue_size', 'prologue_codes',
                 'locals', 'local_size', 'frame_size',
                 'sub_rsp_off', 'add_rsp_off')

    def __init__(self, name, args, ret_type, rva,
                 ret_struct=None, varargs=False, n_fixed=0):
        self.name = name
        self.args = args
        self.ret_type = ret_type
        self.rva = rva
        self.call_fixups = []
        self.ret_struct = ret_struct
        self.varargs = varargs
        self.n_fixed = n_fixed
        self.seh_builder = None
        self.seh_scopes = []
        self.unwind_info = None
        self.has_seh = False
        self.body_begin_rva = None
        self.body_end_rva = None
        self.end_rva = None
        self.prologue_size = 0
        self.prologue_codes = []
        self.locals = []  
        self.local_size = 0  
        self.frame_size = 0  
        self.sub_rsp_off = None  
        self.add_rsp_off = None  

class LocalVar:
    """Локальная переменная метода.

    Живёт в стековом фрейме метода, адресуется через [rbp - disp].
    Каждый вызов метода имеет свой экземпляр.
    Поддерживает рекурсию.
    """
    __slots__ = ('name', 'ctype', 'offset', 'size', 'align', 'method')

    def __init__(self, name, ctype, offset, size, align, method):
        self.name = name
        self.ctype = ctype
        self.offset = offset  
        self.size = size  
        self.align = align  
        self.method = method  

    def __repr__(self):
        return (f"LocalVar({self.name!r}, {self.ctype.__name__}, "
                f"offset={self.offset:#x}, size={self.size})")

class MethodRegistry:
    def __init__(self):
        self.methods = {}

    def register(self, m):
        self.methods[m.name] = m

    def get(self, name):
        if name not in self.methods:
            raise KeyError(
                f"Метод '{name}' не зарегистрирован. "
                f"Сначала start_method/end_method."
            )
        return self.methods[name]

    def __contains__(self, name):
        return name in self.methods

    def clear(self):
        self.methods.clear()

INT_REGS   = ('rcx', 'rdx', 'r8', 'r9')
FLOAT_REGS = ('xmm0', 'xmm1', 'xmm2', 'xmm3')

STACK_FIRST_OFF = 0x28

def distribute_args(arg_types, has_sret=False):
    """Распределить аргументы по Microsoft x64 ABI.

    Единый счётчик позиций 0..3 → RCX/RDX/R8/R9 или XMM0..3.
    Позиция ≥ 4 → стек.
    """
    stack_off = STACK_FIRST_OFF
    result = []
    pos = 1 if has_sret else 0

    for t in arg_types:
        if _is_struct_type(t):
            regs = _struct_classify(t)
            for i, r in enumerate(regs):
                is_first = (i == 0)
                if pos < 4:
                    reg = FLOAT_REGS[pos] if r['is_float'] else INT_REGS[pos]
                    result.append(MethodArg(
                        reg, t, r['is_float'],
                        struct_cls=t,
                        struct_off=r['off'],
                        struct_size=r['size'],
                        struct_is_first=is_first,
                        is_struct_pointer=r['is_pointer'],
                    ))
                else:
                    result.append(MethodArg(
                        'stack', t, r['is_float'], stack_off,
                        struct_cls=t,
                        struct_off=r['off'],
                        struct_size=r['size'],
                        struct_is_first=is_first,
                        is_struct_pointer=r['is_pointer'],
                    ))
                    stack_off += 8
                pos += 1
        elif _is_float_type(t):
            if pos < 4:
                result.append(MethodArg(FLOAT_REGS[pos], t, True))
            else:
                result.append(MethodArg('stack', t, True, stack_off))
                stack_off += 8
            pos += 1
        else:
            if pos < 4:
                result.append(MethodArg(INT_REGS[pos], t, False))
            else:
                result.append(MethodArg('stack', t, False, stack_off))
                stack_off += 8
            pos += 1

    return result

REG_NUM = {
    'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3,
    'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
    'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
    'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15,
}

XMM_NUM = {
    'xmm0': 0, 'xmm1': 1, 'xmm2': 2, 'xmm3': 3,
    'xmm4': 4, 'xmm5': 5, 'xmm6': 6, 'xmm7': 7,
    'xmm8': 8, 'xmm9': 9, 'xmm10': 10, 'xmm11': 11,
    'xmm12': 12, 'xmm13': 13, 'xmm14': 14, 'xmm15': 15,
}

def _rex(w=0, r=0, x=0, b=0):
    return 0x40 | (w << 3) | (r << 2) | (x << 1) | b

CALLEE_SAVED_SIZE = 64   
RBP_SAVED_SIZE    = 8    
FRAME_BASE        = CALLEE_SAVED_SIZE + RBP_SAVED_SIZE  

PROLOGUE_HEAD = (
    b'\x55'                          
    b'\x48\x89\xE5'                  
)

PROLOGUE_CALLEE_SAVED = (
    b'\x53'                          
    b'\x56'                          
    b'\x57'                          
    b'\x41\x54'                      
    b'\x41\x55'                      
    b'\x41\x56'                      
    b'\x41\x57'                      
)

SUB_RSP_PLACEHOLDER = b'\x48\x81\xEC\x00\x00\x00\x00'

ADD_RSP_PLACEHOLDER = b'\x48\x81\xC4\x00\x00\x00\x00'

EPILOGUE_TAIL = (
    b'\x41\x5F'            
    b'\x41\x5E'            
    b'\x41\x5D'            
    b'\x41\x5C'            
    b'\x5F'                
    b'\x5E'                
    b'\x5B'                
    b'\x5D'                
    b'\xC3'                
)

def emit_mov_reg_imm64(ctx, reg, value):
    """mov r64, imm64."""
    n = REG_NUM[reg]
    rex = _rex(w=1, b=(n >> 3) & 1)
    opcode = 0xB8 + (n & 0x07)
    ctx.emit(bytes([rex, opcode]) + struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

def emit_mov_reg_reg(ctx, dst, src):
    """mov r64, r64."""
    d = REG_NUM[dst]
    s = REG_NUM[src]
    rex = _rex(w=1, r=(s >> 3) & 1, b=(d >> 3) & 1)
    modrm = 0xC0 | ((s & 0x07) << 3) | (d & 0x07)
    ctx.emit(bytes([rex, 0x89, modrm]))

def emit_mov_reg_mem_rsp(ctx, dst, off):
    """mov r64, [rsp + disp32]."""
    d = REG_NUM[dst]
    rex = _rex(w=1, r=(d >> 3) & 1)
    modrm = 0x84 | ((d & 0x07) << 3)   
    sib = 0x24                          
    ctx.emit(bytes([rex, 0x8B, modrm, sib]) + struct.pack("<i", off))

def emit_mov_mem_rsp_reg(ctx, off, src):
    """mov [rsp + disp32], r64."""
    s = REG_NUM[src]
    rex = _rex(w=1, r=(s >> 3) & 1)
    modrm = 0x84 | ((s & 0x07) << 3)
    sib = 0x24
    ctx.emit(bytes([rex, 0x89, modrm, sib]) + struct.pack("<i", off))

def emit_mov_mem_rsp_imm32(ctx, off, value):
    """mov dword [rsp + disp32], imm32."""
    modrm = 0x84
    sib = 0x24
    ctx.emit(bytes([0xC7, modrm, sib]) + struct.pack("<i", off)
             + struct.pack("<I", value & 0xFFFFFFFF))

def emit_mov_reg_mem_rip(ctx, reg, mem_rva):
    """mov r64, [rip + disp32]."""
    n = REG_NUM[reg]
    rex = _rex(w=1, r=(n >> 3) & 1)
    modrm = 0x05 | ((n & 0x07) << 3)
    next_rva = ctx.text_rva + len(ctx.code) + 7
    disp = mem_rva - next_rva
    ctx.emit(bytes([rex, 0x8B, modrm]) + struct.pack("<i", disp))

def emit_movss_xmm_mem_rip(ctx, xmm, mem_rva):
    """movss xmm, [rip + disp32].

    Без REX, если он пустой (для xmm0-7).
    """
    n = XMM_NUM[xmm]
    rex = _rex(r=(n >> 3) & 1)
    prefix = bytes([0xF3])
    if rex != 0x40:
        prefix += bytes([rex])
    modrm = 0x05 | ((n & 0x07) << 3)
    prefix += bytes([0x0F, 0x10, modrm])
    next_rva = ctx.text_rva + len(ctx.code) + len(prefix) + 4
    disp = mem_rva - next_rva
    ctx.emit(prefix + struct.pack("<i", disp))

def emit_movsd_xmm_mem_rip(ctx, xmm, mem_rva):
    """movsd xmm, [rip + disp32]."""
    n = XMM_NUM[xmm]
    rex = _rex(r=(n >> 3) & 1)
    prefix = bytes([0xF2])
    if rex != 0x40:
        prefix += bytes([rex])
    modrm = 0x05 | ((n & 0x07) << 3)
    prefix += bytes([0x0F, 0x10, modrm])
    next_rva = ctx.text_rva + len(ctx.code) + len(prefix) + 4
    disp = mem_rva - next_rva
    ctx.emit(prefix + struct.pack("<i", disp))

def emit_movss_xmm_xmm(ctx, dst, src):
    """movss xmm, xmm."""
    d = XMM_NUM[dst]
    s = XMM_NUM[src]
    rex = _rex(r=(d >> 3) & 1, b=(s >> 3) & 1)
    prefix = bytes([0xF3])
    if rex != 0x40:
        prefix += bytes([rex])
    modrm = 0xC0 | ((d & 0x07) << 3) | (s & 0x07)
    prefix += bytes([0x0F, 0x10, modrm])
    ctx.emit(prefix)

def emit_lea_rip(ctx, reg, target_rva):
    """lea reg, [rip + disp32]."""
    n = REG_NUM[reg]
    rex = _rex(w=1, r=(n >> 3) & 1)
    modrm = 0x05 | ((n & 0x07) << 3)
    next_rva = ctx.text_rva + len(ctx.code) + 7
    disp = target_rva - next_rva
    ctx.emit(bytes([rex, 0x8D, modrm]) + struct.pack("<i", disp))

def emit_movd_gp_xmm(ctx, gp, xmm):
    """movd gp32, xmm. Для float (4 байта)."""
    g = REG_NUM[gp]
    x = XMM_NUM[xmm]
    rex = _rex(r=(x >> 3) & 1, b=(g >> 3) & 1)
    prefix = bytes([0x66])
    if rex != 0x40:
        prefix += bytes([rex])
    modrm = 0xC0 | ((x & 0x07) << 3) | (g & 0x07)
    ctx.emit(prefix + bytes([0x0F, 0x7E, modrm]))

def emit_movq_gp_xmm(ctx, gp, xmm):
    """movq gp64, xmm. Для double (8 байт)."""
    g = REG_NUM[gp]
    x = XMM_NUM[xmm]
    rex = _rex(w=1, r=(x >> 3) & 1, b=(g >> 3) & 1)
    prefix = bytes([0x66])
    if rex != 0x40:
        prefix += bytes([rex])
    modrm = 0xC0 | ((x & 0x07) << 3) | (g & 0x07)
    ctx.emit(prefix + bytes([0x0F, 0x7E, modrm]))

def _emit_dup_xmm_to_gp(self, gp, xmm, ctype):
    """Продублировать XMM → GP (для varargs)."""
    if ctype is ctypes.c_double:
        emit_movq_gp_xmm(self, gp, xmm)
    else:
        emit_movd_gp_xmm(self, gp, xmm)

def _promote_vararg_type(ctype, value):

    if ctype is ctypes.c_float:
        return ctypes.c_double, float(value)

    if ctype in (ctypes.c_short, ctypes.c_byte, ctypes.c_char,
                    ctypes.c_bool):
        return ctypes.c_int, int(value)

    if ctype in (ctypes.c_ushort, ctypes.c_ubyte):
        return ctypes.c_uint, int(value)

    return ctype, value

def _emit_dup_float_to_gp(self, stack_off, ctype):
    """Продублировать float из стека в GP (для varargs)."""

    self.emit(bytes([0x8B, 0x44, 0x24, stack_off & 0xFF]))

    if ctype is ctypes.c_double:
        self.emit(bytes([0x48, 0x8B, 0x44, 0x24, stack_off & 0xFF]))

class MethodsMixin:
    def _ensure_method_state(self):
        if not hasattr(self, 'method_registry') or self.method_registry is None:
            self.method_registry = MethodRegistry()
        if not hasattr(self, '_current_method'):
            self._current_method = None

    def start_method(self, name, arg_types, ret_type=None, varargs=False):
        self._ensure_method_state()
        if self._current_method is not None:
            raise RuntimeError(...)

        args = distribute_args(arg_types)
        n_fixed = len(arg_types)

        jmp_off = len(self.code)
        self.emit(bytes([0xE9, 0x00, 0x00, 0x00, 0x00]))

        if varargs:
            prologue = (
                b'\x55'  
                b'\x48\x89\xE5'  
                b'\x48\x89\x4D\x10'  
                b'\x48\x89\x55\x18'  
                b'\x4C\x89\x45\x20'  
                b'\x4C\x89\x4D\x28'  
                b'\x53'  
                b'\x56'  
                b'\x57'  
                b'\x41\x54'  
                b'\x41\x55'  
                b'\x41\x56'  
                b'\x41\x57'  
            )
            prologue_codes = _build_varargs_prologue_codes()
        else:
            prologue = PROLOGUE_HEAD + PROLOGUE_CALLEE_SAVED
            prologue_codes = _build_standard_prologue_codes()

        prologue_size = len(prologue)

        self.emit(prologue)

        sub_rsp_off = len(self.code)
        self.emit(SUB_RSP_PLACEHOLDER)
        prologue_size += len(SUB_RSP_PLACEHOLDER)

        body_begin_off = len(self.code)

        existing = self.method_registry.methods.get(name)
        if existing is not None:
            existing.args = args
            existing.ret_type = ret_type
            existing.rva = None
            existing.varargs = varargs
            existing.n_fixed = n_fixed
            existing.prologue_size = prologue_size
            existing.prologue_codes = prologue_codes
            existing.body_begin_rva = self.text_rva + body_begin_off
            existing.seh_builder = None
            existing.seh_scopes = []
            existing.unwind_info = None
            existing.has_seh = False
            existing.locals = []
            existing.local_size = 0
            existing.frame_size = 0
            existing.sub_rsp_off = sub_rsp_off
            existing.add_rsp_off = None
            method = existing
        else:
            method = Method(name, args, ret_type, None,
                            varargs=varargs, n_fixed=n_fixed)
            method.prologue_size = prologue_size
            method.prologue_codes = prologue_codes
            method.body_begin_rva = self.text_rva + body_begin_off
            method.sub_rsp_off = sub_rsp_off
            self.method_registry.register(method)

        self._current_method = {
            'name': name,
            'args': args,
            'ret_type': ret_type,
            'start_off': jmp_off + 5,
            'jmp_off': jmp_off,
            'method': method,
            'varargs': varargs,
            'n_fixed': n_fixed,
            'end_off': None,
        }
        return args

    def end_method(self):
        self._ensure_method_state()
        if self._current_method is None:
            raise RuntimeError("end_method(): нет активного метода")

        m = self._current_method
        method = m['method']

        N = (method.local_size + 15) & ~15
        method.frame_size = N

        if method.sub_rsp_off is not None:
            struct.pack_into("<I", self.code, method.sub_rsp_off + 3, N)

        body_end_off = len(self.code)
        method.body_end_rva = self.text_rva + body_end_off

        add_rsp_off = len(self.code)
        method.add_rsp_off = add_rsp_off
        self.emit(b'\x48\x81\xC4' + struct.pack("<I", N))
        self.emit(EPILOGUE_TAIL)

        method.end_rva = self.text_rva + len(self.code)

        jmp_off = m['jmp_off']
        rel = len(self.code) - (jmp_off + 5)
        self.patch_i32(jmp_off + 1, rel)

        rva = self.text_rva + m['start_off']
        method.rva = rva

        from .seh import UnwindInfo, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER
        sb = m.get('seh_builder')
        method.has_seh = (sb is not None and len(sb.scopes) > 0)
        if method.has_seh:
            method.seh_scopes = sorted(sb.scopes, key=lambda s: s.begin_rva)

        ui = UnwindInfo()
        ui.version = 1
        flags = 0
        if method.seh_scopes:
            for scope in method.seh_scopes:
                if scope.kind == 'except':
                    flags |= UNW_FLAG_EHANDLER
                elif scope.kind == 'finally':
                    flags |= UNW_FLAG_UHANDLER
        ui.flags = flags
        ui.size_of_prolog = method.prologue_size
        ui.codes = list(method.prologue_codes)

        if N > 0:

            code_offset = method.prologue_size - len(SUB_RSP_PLACEHOLDER)

            if N <= 128 and N % 8 == 0:

                ui.codes.append(
                    UnwindCode(code_offset, UWOP_ALLOC_SMALL, (N - 8) // 8)
                )
            elif N // 8 <= 0xFFFF:

                ui.codes.append(
                    UnwindCode(code_offset, UWOP_ALLOC_LARGE, 0,
                               extra_words=[N // 8])
                )
            else:

                ui.codes.append(
                    UnwindCode(code_offset, UWOP_ALLOC_LARGE, 1,
                               extra_words=[N & 0xFFFF, (N >> 16) & 0xFFFF])
                )

        ui.codes.sort(key=lambda c: -c.code_offset)

        has_set_fpreg = any(
            c.unwind_op == UWOP_SET_FPREG for c in ui.codes
        )
        if has_set_fpreg:
            ui.frame_register = 5  
            ui.frame_offset = (64 + N) // 16
            if ui.frame_offset > 15:
                raise NotImplementedError(
                    f"end_method({method.name}): FrameOffset={ui.frame_offset} > 15"
                )
        else:
            ui.frame_register = 0
            ui.frame_offset = 0

        ui.handler_rva = 0
        ui.scope_table = list(method.seh_scopes) if method.has_seh else []
        method.unwind_info = ui

        print(f"[N] {method.name}: local_size={method.local_size} N={N}")

        for fixup_off in method.call_fixups:
            next_rva = self.text_rva + fixup_off + 4
            fix_rel = rva - next_rva
            self.patch_i32(fixup_off, fix_rel)

        self._current_method = None
        self._after_end_method(method)
        return method

    def _after_end_method(self, method):
        """Хук для Context. По умолчанию — пусто."""
        pass

    def _call_varargs(self, method, values):
        n_fixed = method.n_fixed
        if len(values) < n_fixed:
            raise ValueError(
                f"call_method('{method.name}'): нужно минимум {n_fixed} "
                f"фиксированных аргументов, получено {len(values)}"
            )

        fixed_values = list(values[:n_fixed])
        raw_extra = list(values[n_fixed:])

        extra_values = []
        for i, v in enumerate(raw_extra):
            if not (isinstance(v, tuple) and len(v) == 2):
                raise ValueError(
                    f"call_method('{method.name}'): varargs-аргумент #{i} "
                    f"должен быть (значение, ctype), получено {v!r}"
                )
            val, ctype = v
            ctype, val = _promote_vararg_type(ctype, val)
            extra_values.append((ctype, val))

        all_args = []
        pos = 0

        for i, arg in enumerate(method.args):
            val = fixed_values[i]
            all_args.append({
                'loc': arg.loc,
                'ctype': arg.ctype,
                'is_float': arg.is_float,
                'value': val,
                'stack_off': arg.stack_off,
                'struct_cls': arg.struct_cls,
                'struct_off': arg.struct_off,
                'struct_size': arg.struct_size,
                'struct_is_first': arg.struct_is_first,
                'is_struct_pointer': arg.is_struct_pointer,
            })
            if arg.loc != 'stack':
                pos += 1
            else:
                pos = 4
        pos = sum(1 for a in all_args if a['loc'] != 'stack')

        stack_off = STACK_FIRST_OFF
        for a in all_args:
            if a['loc'] == 'stack':
                stack_off = max(stack_off, a['stack_off'] + 8)

        for ctype, val in extra_values:
            is_float = ctype in (ctypes.c_float, ctypes.c_double)
            if pos < 4:
                loc = FLOAT_REGS[pos] if is_float else INT_REGS[pos]
                all_args.append({
                    'loc': loc,
                    'ctype': ctype,
                    'is_float': is_float,
                    'value': val,
                    'stack_off': None,
                    'struct_cls': None,
                })
            else:
                all_args.append({
                    'loc': 'stack',
                    'ctype': ctype,
                    'is_float': is_float,
                    'value': val,
                    'stack_off': stack_off,
                    'struct_cls': None,
                })
                stack_off += 8
            pos += 1

        n_stack = sum(1 for a in all_args if a['loc'] == 'stack')
        frame_size = 0x20 + n_stack * 8
        frame_size = (frame_size + 0x0F) & ~0x0F

        if frame_size <= 0x7F:
            self.emit(bytes([0x48, 0x83, 0xEC, frame_size & 0xFF]))
        else:
            self.emit(bytes([0x48, 0x81, 0xEC]) + struct.pack("<I", frame_size))

        cur_stack = 0x20
        n_float_in_xmm = 0

        for a in all_args:
            loc = a['loc']
            ctype = a['ctype']
            is_float = a['is_float']
            val = a['value']

            if loc == 'stack':
                if is_float:

                    self._emit_store_float_to_stack(cur_stack, ctype, val)

                else:
                    self._emit_store_int_to_stack(cur_stack, ctype, val)
                cur_stack += 8
            elif is_float:
                self._emit_load_float_arg(loc, ctype, val)

                gp = INT_REGS[XMM_NUM[loc]]
                if ctype is ctypes.c_double:
                    emit_movq_gp_xmm(self, gp, loc)
                else:
                    emit_movd_gp_xmm(self, gp, loc)
                n_float_in_xmm += 1
            else:
                if a.get('struct_cls') is not None:
                    self._emit_load_struct_arg_from_dict(a, val)
                else:
                    self._emit_load_int_arg(loc, ctype, val)

        if n_float_in_xmm > 4:
            n_float_in_xmm = 4
        self.emit(bytes([0xB0, n_float_in_xmm & 0xFF]))  

        if method.rva is None:
            fixup_off = len(self.code) + 1
            self.emit(bytes([0xE8, 0x00, 0x00, 0x00, 0x00]))
            method.call_fixups.append(fixup_off)
        else:
            self.call_rva(method.rva)

        if frame_size <= 0x7F:
            self.emit(bytes([0x48, 0x83, 0xC4, frame_size & 0xFF]))
        else:
            self.emit(bytes([0x48, 0x81, 0xC4]) + struct.pack("<I", frame_size))

    def _emit_load_struct_arg_from_dict(self, a, val):
        arg = MethodArg(
            a['loc'], a['struct_cls'], a['is_float'],
            stack_off=a['stack_off'],
            struct_cls=a['struct_cls'],
            struct_off=a['struct_off'],
            struct_size=a['struct_size'],
            struct_is_first=a['struct_is_first'],
            is_struct_pointer=a['is_struct_pointer'],
        )
        self._emit_load_struct_arg(arg, val)

    def call_method(self, name, values):
        """Вызвать метод по имени с аргументами."""
        self._ensure_method_state()
        method = self.method_registry.get(name)
        if method.varargs:
            return self._call_varargs(method, values)

        sret_kind = None
        if method.ret_struct is not None:
            sret_kind = _struct_return_kind(method.ret_struct)
        has_sret = (sret_kind == ('sret',))

        logical = 0
        for i, a in enumerate(method.args):
            if has_sret and i == 0:
                continue  
            if a.struct_cls is not None and not a.struct_is_first:
                continue  
            logical += 1

        if len(values) != logical:
            raise ValueError(
                f"call_method('{name}'): ожидалось {logical} "
                f"аргументов, получено {len(values)}"
            )

        n_stack = sum(1 for a in method.args if a.loc == 'stack')
        frame_size = 0x20 + n_stack * 8
        frame_size = (frame_size + 0x0F) & ~0x0F

        if frame_size <= 0x7F:
            self.emit(bytes([0x48, 0x83, 0xEC, frame_size & 0xFF]))
        else:
            self.emit(bytes([0x48, 0x81, 0xEC]) + struct.pack("<I", frame_size))

        stack_off = 0x20
        val_idx = 0

        for i, arg in enumerate(method.args):

            if has_sret and i == 0:
                ret_slot_name = "_ret_" + method.name
                ret_rva = self.rva_of(ret_slot_name)
                emit_lea_rip(self, arg.loc, ret_rva)
                continue

            if arg.struct_cls is not None and not arg.struct_is_first:
                val = values[val_idx - 1]
            else:
                val = values[val_idx]
                val_idx += 1

            if arg.struct_cls is not None:
                self._emit_load_struct_arg(arg, val)
            elif arg.loc == 'stack':
                if arg.is_float:
                    self._emit_store_float_to_stack(stack_off, arg.ctype, val)
                else:
                    self._emit_store_int_to_stack(stack_off, arg.ctype, val)
                stack_off += 8
            elif arg.is_float:
                self._emit_load_float_arg(arg.loc, arg.ctype, val)
            else:
                self._emit_load_int_arg(arg.loc, arg.ctype, val)

        if method.rva is None:
            fixup_off = len(self.code) + 1
            self.emit(bytes([0xE8, 0x00, 0x00, 0x00, 0x00]))
            method.call_fixups.append(fixup_off)
        else:
            self.call_rva(method.rva)

        if method.ret_struct is not None:
            self._save_struct_return(method)

        if frame_size <= 0x7F:
            self.emit(bytes([0x48, 0x83, 0xC4, frame_size & 0xFF]))
        else:
            self.emit(bytes([0x48, 0x81, 0xC4]) + struct.pack("<I", frame_size))

    def _save_struct_return(self, method):
        kind = _struct_return_kind(method.ret_struct)
        slot_rva = self.rva_of("_ret_" + method.name)
        if kind == ('sret',):
            return
        if kind == ('rax',):
            self.mov_mem_reg(slot_rva, 0)

    def _emit_load_struct_arg(self, arg, val):
        if isinstance(val, str):
            base_rva = self.rva_of(val)
        elif isinstance(val, Rva):
            base_rva = val.rva
        elif isinstance(val, Mem):
            if arg.is_struct_pointer:
                emit_mov_reg_mem_rip(self, arg.loc, val.rva)
                return
            else:
                raise ValueError(
                    f"_emit_load_struct_arg: Mem не подходит "
                    f"для by-value структуры"
                )
        else:
            raise ValueError(
                f"_emit_load_struct_arg: ожидался str/Rva/Mem, "
                f"получено {val!r}"
            )

        if arg.is_struct_pointer:
            emit_lea_rip(self, arg.loc, base_rva)
            return

        field_rva = base_rva + arg.struct_off
        sz = arg.struct_size

        if arg.is_float:
            if sz <= 4:
                emit_movss_xmm_mem_rip(self, arg.loc, field_rva)
            elif sz <= 8:
                emit_movsd_xmm_mem_rip(self, arg.loc, field_rva)
            else:
                raise NotImplementedError(
                    f"_emit_load_struct_arg: float-часть {sz} байт "
                    f"не поддерживается"
                )
        else:
            if sz <= 8:
                emit_mov_reg_mem_rip(self, arg.loc, field_rva)
            else:
                raise NotImplementedError(
                    f"_emit_load_struct_arg: int-часть {sz} байт "
                    f"не поддерживается"
                )

    def _emit_load_int_arg(self, reg, ctype, val):
        if isinstance(val, int):
            emit_mov_reg_imm64(self, reg, val & 0xFFFFFFFFFFFFFFFF)
        elif isinstance(val, Mem):
            emit_mov_reg_mem_rip(self, reg, val.rva)
        elif isinstance(val, Rva):
            emit_lea_rip(self, reg, val.rva)
        elif isinstance(val, str):
            emit_mov_reg_mem_rip(self, reg, self.rva_of(val))
        elif isinstance(val, MethodArg):
            val.emit_load(self, reg)
        else:
            raise ValueError(
                f"call_method: неизвестное значение {val!r} "
                f"для int-аргумента"
            )

    def _emit_load_float_arg(self, xmm, ctype, val):
        if isinstance(val, str):
            mem_rva = self.rva_of(val)
            if ctype is ctypes.c_double:
                emit_movsd_xmm_mem_rip(self, xmm, mem_rva)
            else:
                emit_movss_xmm_mem_rip(self, xmm, mem_rva)

        elif isinstance(val, (int, float)) and not isinstance(val, bool):

            if ctype is ctypes.c_double:
                bits = struct.unpack("<Q", struct.pack("<d", float(val)))[0]

                emit_mov_reg_imm64(self, 'rax', bits)

                n = XMM_NUM[xmm]
                rex = _rex(w=1, r=(n >> 3) & 1)
                modrm = 0xC0 | ((n & 0x07) << 3) | 0  
                self.emit(bytes([0x66, rex, 0x0F, 0x6E, modrm]))
            else:
                bits = struct.unpack("<I", struct.pack("<f", float(val)))[0]

                self.emit(bytes([0xB8]) + struct.pack("<I", bits))

                n = XMM_NUM[xmm]
                rex = _rex(r=(n >> 3) & 1)
                modrm = 0xC0 | ((n & 0x07) << 3) | 0  
                if rex != 0x40:
                    self.emit(bytes([0x66, rex, 0x0F, 0x6E, modrm]))
                else:
                    self.emit(bytes([0x66, 0x0F, 0x6E, modrm]))

        elif isinstance(val, MethodArg):
            if not val.is_float:
                raise ValueError(
                    f"float-аргумент ожидает float-значение, "
                    f"получен int-аргумент"
                )
            val.emit_load_float(self, xmm)

        else:
            raise ValueError(
                f"float-аргумент: неизвестное значение {val!r}"
            )

    def _emit_store_int_to_stack(self, off, ctype, val):
        if isinstance(val, int):
            emit_mov_mem_rsp_imm32(self, off, val)
        elif isinstance(val, Mem):
            emit_mov_reg_mem_rip(self, 'rax', val.rva)
            emit_mov_mem_rsp_reg(self, off, 'rax')
        elif isinstance(val, Rva):
            emit_lea_rip(self, 'rax', val.rva)
            emit_mov_mem_rsp_reg(self, off, 'rax')
        elif isinstance(val, str):
            emit_mov_reg_mem_rip(self, 'rax', self.rva_of(val))
            emit_mov_mem_rsp_reg(self, off, 'rax')
        elif isinstance(val, MethodArg):
            val.emit_load(self, 'rax')
            emit_mov_mem_rsp_reg(self, off, 'rax')
        else:
            raise ValueError(
                f"стековый int-аргумент: неизвестное значение {val!r}"
            )

    def _emit_store_float_to_stack(self, off, ctype, val):
        if isinstance(val, str):

            emit_mov_reg_mem_rip(self, 'rax', self.rva_of(val))
            emit_mov_mem_rsp_reg(self, off, 'rax')

        elif isinstance(val, (int, float)) and not isinstance(val, bool):

            if ctype is ctypes.c_double:
                bits = struct.unpack("<Q", struct.pack("<d", float(val)))[0]

                emit_mov_reg_imm64(self, 'rax', bits)

                emit_mov_mem_rsp_reg(self, off, 'rax')
            else:
                bits = struct.unpack("<I", struct.pack("<f", float(val)))[0]

                self.emit(bytes([0xC7, 0x44, 0x24, off & 0xFF])
                          + struct.pack("<I", bits))

        elif isinstance(val, MethodArg) and val.is_float:

            val.emit_load_float(self, 'xmm0')

            self.emit(bytes([0x66, 0x0F, 0x7E, 0xC0]))
            emit_mov_mem_rsp_reg(self, off, 'rax')

        else:
            raise ValueError(
                f"стековый float-аргумент: неизвестное значение {val!r}"
            )

def _build_standard_prologue_codes():
    return [
        UnwindCode(0,  UWOP_PUSH_NONVOL, 5),    
        UnwindCode(1,  UWOP_SET_FPREG, 0),      
        UnwindCode(4,  UWOP_PUSH_NONVOL, 3),    
        UnwindCode(5,  UWOP_PUSH_NONVOL, 6),    
        UnwindCode(6,  UWOP_PUSH_NONVOL, 7),    
        UnwindCode(7,  UWOP_PUSH_NONVOL, 12),   
        UnwindCode(9,  UWOP_PUSH_NONVOL, 13),   
        UnwindCode(11, UWOP_PUSH_NONVOL, 14),   
        UnwindCode(13, UWOP_PUSH_NONVOL, 15),   
    ]

def _build_varargs_prologue_codes():
    """UNWIND_CODE для varargs-пролога MBPRBF (64 байта стека).

    Пролог (24 байта):
      offset  0: push rbp              (1 байт)
      offset  1: mov rbp, rsp          (3 байта)
      offset  4: mov [rbp+0x10], rcx   (4 байта)
      offset  8: mov [rbp+0x18], rdx   (4 байта)
      offset 12: mov [rbp+0x20], r8    (4 байта)
      offset 16: mov [rbp+0x28], r9    (4 байта)
      offset 20: push rbx              (1 байт)
      offset 21: push rsi              (1 байт)
      offset 22: push rdi              (1 байт)
      offset 23: push r12              (2 байта)
      offset 25: push r13              (2 байта)
      offset 27: push r14              (2 байта)
      offset 29: push r15              (2 байта)
    """
    from .seh import UnwindCode, UWOP_PUSH_NONVOL
    return [
        UnwindCode(29, UWOP_PUSH_NONVOL, 15),   
        UnwindCode(27, UWOP_PUSH_NONVOL, 14),   
        UnwindCode(25, UWOP_PUSH_NONVOL, 13),   
        UnwindCode(23, UWOP_PUSH_NONVOL, 12),   
        UnwindCode(22, UWOP_PUSH_NONVOL, 7),    
        UnwindCode(21, UWOP_PUSH_NONVOL, 6),    
        UnwindCode(20, UWOP_PUSH_NONVOL, 3),    
        UnwindCode(1,  UWOP_PUSH_NONVOL, 5),    
    ]
