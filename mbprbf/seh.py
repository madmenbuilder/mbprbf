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


"""seh.py - SEH для MBPRBF (Windows x64).

Сбор scope-таблиц, UNWIND_INFO, генерация .pdata/.xdata.
Использует системный __C_specific_handler из ntdll.dll.
"""

import struct

UNW_FLAG_NHANDLER = 0
UNW_FLAG_EHANDLER = 1
UNW_FLAG_UHANDLER = 2
UNW_FLAG_CHAININFO = 4

UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3
UWOP_SAVE_NONVOL = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_SAVE_XMM128 = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME = 10

ExceptionContinueExecution = 0
ExceptionContinueSearch = 1
ExceptionNestedException = 2
ExceptionCollidedUnwind = 3

EXCEPTION_EXECUTE_HANDLER = 1
EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_CONTINUE_EXECUTION = -1

REG_RCX = 1
REG_RDX = 2
REG_RBX = 3
REG_RSP = 4
REG_RBP = 5
REG_RSI = 6
REG_RDI = 7
REG_R8 = 8
REG_R9 = 9
REG_R10 = 10
REG_R11 = 11
REG_R12 = 12
REG_R13 = 13
REG_R14 = 14
REG_R15 = 15

class ScopeRecord:
    __slots__ = ('begin_rva', 'end_rva', 'handler_rva',
                 'jump_rva', 'kind')

    def __init__(self, begin_rva, end_rva, handler_rva,
                 jump_rva, kind='except'):
        self.begin_rva = begin_rva
        self.end_rva = end_rva
        self.handler_rva = handler_rva
        self.jump_rva = jump_rva
        self.kind = kind  

    def pack(self):
        """SCOPE_RECORD: 4 DWORD (16 байт)."""
        return (struct.pack("<I", self.begin_rva)
                + struct.pack("<I", self.end_rva)
                + struct.pack("<I", self.handler_rva)
                + struct.pack("<I", self.jump_rva))

    def __repr__(self):
        return (f"Scope({self.kind}: "
                f"begin={self.begin_rva:#x} end={self.end_rva:#x} "
                f"handler={self.handler_rva:#x} jump={self.jump_rva:#x})")

class UnwindCode:
    __slots__ = ('code_offset', 'unwind_op', 'op_info', 'extra_words')

    def __init__(self, code_offset, unwind_op, op_info, extra_words=None):
        self.code_offset = code_offset
        self.unwind_op = unwind_op
        self.op_info = op_info
        self.extra_words = extra_words or []

    def pack(self):
        blob = bytes([self.code_offset & 0xFF,
                      (self.unwind_op & 0x0F) | ((self.op_info & 0x0F) << 4)])
        for w in self.extra_words:
            blob += struct.pack("<H", w & 0xFFFF)
        return blob

    def __len__(self):
        return 1 + len(self.extra_words)

    def __repr__(self):
        return (f"UnwindCode(off={self.code_offset} "
                f"op={self.unwind_op} info={self.op_info})")

class SehBuilder:
    """Строит scope-таблицу и unwind-коды для метода."""

    def __init__(self, method):
        self.method = method
        self.stack = []  
        self.scopes = []  
        self.unwind_codes = []  

    def open_try(self, begin_rva):
        block = {
            'kind': 'try',
            'begin_rva': begin_rva,
            'end_rva': None,
        }
        self.stack.append(block)
        return block

    def close_try(self, end_rva):
        if not self.stack or self.stack[-1]['kind'] != 'try':
            raise RuntimeError("close_try: нет открытого __try")
        self.stack[-1]['end_rva'] = end_rva

    def open_except(self, begin_rva, filter_rva):
        if not self.stack or self.stack[-1]['kind'] != 'try':
            raise RuntimeError("open_except: __try не открыт")
        if self.stack[-1]['end_rva'] is None:
            raise RuntimeError("open_except: __try не закрыт")
        try_block = self.stack[-1]
        block = {
            'kind': 'except',
            'begin_rva': begin_rva,
            'end_rva': None,
            'try_block': try_block,
            'filter_rva': filter_rva,
        }
        self.stack.append(block)
        return block

    def close_except(self, end_rva):
        if not self.stack or self.stack[-1]['kind'] != 'except':
            raise RuntimeError("close_except: нет открытого __except")
        block = self.stack.pop()
        block['end_rva'] = end_rva
        try_block = block['try_block']

        scope = ScopeRecord(
            begin_rva=try_block['begin_rva'],
            end_rva=try_block['end_rva'],
            handler_rva=block['filter_rva'],
            jump_rva=block['begin_rva'],
            kind='except',
        )
        self.scopes.append(scope)

        self.stack.pop()
        return scope

    def open_finally(self, begin_rva):
        if not self.stack or self.stack[-1]['kind'] != 'try':
            raise RuntimeError("open_finally: __try не открыт")
        if self.stack[-1]['end_rva'] is None:
            raise RuntimeError("open_finally: __try не закрыт")
        try_block = self.stack[-1]
        block = {
            'kind': 'finally',
            'begin_rva': begin_rva,
            'end_rva': None,
            'try_block': try_block,
        }
        self.stack.append(block)
        return block

    def close_finally(self, end_rva, handler_rva=None):
        if not self.stack or self.stack[-1]['kind'] != 'finally':
            raise RuntimeError("close_finally: нет открытого __finally")
        block = self.stack.pop()
        block['end_rva'] = end_rva
        try_block = block['try_block']

        scope = ScopeRecord(
            begin_rva=try_block['begin_rva'],
            end_rva=try_block['end_rva'],
            handler_rva=(handler_rva if handler_rva is not None
                         else block['begin_rva']),
            jump_rva=0,
            kind='finally',
        )
        self.scopes.append(scope)
        self.stack.pop()
        return scope

    def add_unwind_push_nonvol(self, code_offset, reg_num):
        """push <reg> — 1 байт."""
        self.unwind_codes.append(UnwindCode(
            code_offset, UWOP_PUSH_NONVOL, reg_num))
        return 1

    def add_unwind_alloc_small(self, code_offset, size):
        """sub rsp, size (size = 8 + op_info*8), op_info 0..15."""
        if size % 8 != 0:
            raise ValueError("alloc_small: size должен быть кратен 8")
        if size < 8 or size > 128:
            raise ValueError("alloc_small: size должен быть 8..128")
        op_info = (size - 8) // 8
        self.unwind_codes.append(UnwindCode(
            code_offset, UWOP_ALLOC_SMALL, op_info))
        return 1

    def add_unwind_set_fpreg(self, code_offset):
        """mov rbp, rsp (frame pointer, offset 0)."""
        self.unwind_codes.append(UnwindCode(
            code_offset, UWOP_SET_FPREG, 0))
        return 1

    def build_unwind_codes_for_prologue(self, prologue_desc):
        """prologue_desc: список (kind, reg_or_size).

        kind:
          'push' — push reg (reg = номер)
          'setfp' — mov rbp, rsp
          'alloc' — sub rsp, N
        """
        code_offset = 0
        for kind, arg in prologue_desc:
            if kind == 'push':
                code_offset += self.add_unwind_push_nonvol(
                    code_offset, arg)
            elif kind == 'setfp':
                code_offset += self.add_unwind_set_fpreg(code_offset)
            elif kind == 'alloc':
                code_offset += self.add_unwind_alloc_small(
                    code_offset, arg)
            else:
                raise ValueError(f"unknown prologue kind {kind!r}")

class UnwindInfo:
    """UNWIND_INFO + (опционально) handler + scope table."""

    def __init__(self):
        self.version = 1
        self.flags = 0
        self.size_of_prolog = 0
        self.codes = []  
        self.frame_register = 0
        self.frame_offset = 0
        self.handler_rva = 0  
        self.scope_table = []  

    def set_handler(self, handler_rva, has_termination=False):
        self.flags |= UNW_FLAG_EHANDLER
        if has_termination:
            self.flags |= UNW_FLAG_UHANDLER
        self.handler_rva = handler_rva

    def pack(self):
        """Собрать UNWIND_INFO + handler + scope table."""

        b0 = (self.version & 0x07) | ((self.flags & 0x1F) << 3)
        b1 = self.size_of_prolog & 0xFF
        count_words = sum(len(c) for c in self.codes)
        b2 = count_words & 0xFF
        b3 = (self.frame_register & 0x0F) | ((self.frame_offset & 0x0F) << 4)

        blob = bytearray()
        blob += bytes([b0, b1, b2, b3])

        for code in self.codes:
            blob += code.pack()

        if count_words % 2 == 1:
            blob += b'\x00\x00'

        if self.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            blob += struct.pack("<I", self.handler_rva)

        if self.scope_table:
            blob += struct.pack("<I", len(self.scope_table))
            for scope in self.scope_table:
                blob += scope.pack()

            pad = (4 - len(blob) % 4) % 4
            blob += b'\x00' * pad

        return bytes(blob)

    def __repr__(self):
        return (f"UnwindInfo(flags={self.flags:#x} "
                f"codes={len(self.codes)} "
                f"scopes={len(self.scope_table)})")

class RuntimeFunction:
    __slots__ = ('begin_rva', 'end_rva', 'unwind_info_rva')

    def __init__(self, begin_rva, end_rva, unwind_info_rva):
        self.begin_rva = begin_rva
        self.end_rva = end_rva
        self.unwind_info_rva = unwind_info_rva

    def pack(self):
        """RUNTIME_FUNCTION: 3 DWORD (12 байт)."""
        return (struct.pack("<I", self.begin_rva)
                + struct.pack("<I", self.end_rva)
                + struct.pack("<I", self.unwind_info_rva))

    def __repr__(self):
        return (f"RuntimeFunction(begin={self.begin_rva:#x} "
                f"end={self.end_rva:#x} "
                f"unwind={self.unwind_info_rva:#x})")
