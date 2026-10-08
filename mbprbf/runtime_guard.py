
"""runtime_guard.py - VEH-based runtime exception handling для MBPRBF.
"""
import ctypes
import struct

from .methods import MethodArg

EXC_NAMES = {
    0xC0000005: "AccessViolationException",
    0x80000003: "BreakpointException",
    0x80000004: "SingleStepException",
    0xC000001D: "InvalidOpcodeException",
    0xC0000025: "NoncontinuableException",
    0xC000008C: "OutOfBoundsException",
    0xC000008D: "FloatDenormalOperandException",
    0xC000008E: "FloatDivideByZeroException",
    0xC000008F: "FloatInexactResultException",
    0xC0000090: "FloatInvalidOperationException",
    0xC0000091: "FloatOverflowException",
    0xC0000092: "FloatStackCheckException",
    0xC0000093: "FloatUnderflowException",
    0xC0000094: "IntegerDivideByZeroException",
    0xC0000095: "IntegerOverflowException",
    0xC0000096: "PrivilegedInstructionException",
    0xC0000017: "OutOfMemoryError",
    0xC00000FD: "StackOverflowException",
    0xC0000135: "DllNotFoundException",
    0xC0000142: "DllInitFailedException",
    0xC0000139: "EntryPointNotFoundException",
    0x80000002: "DataMisalignedException",
}

_SKIP_IN_TABLE = {0xC0000005}

def _arg_rcx(ctype=ctypes.c_void_p):
    return MethodArg('rcx', ctype, False)

def _arg_rdx(ctype=ctypes.c_uint64):
    return MethodArg('rdx', ctype, False)

def _arg_r8(ctype=ctypes.c_uint64):
    return MethodArg('r8', ctype, False)

def _arg_r9(ctype=ctypes.c_uint64):
    return MethodArg('r9', ctype, False)

def gen_csh_wrapper(ctx):
    from .methods import Method
    from .seh import UnwindInfo

    jmp_off = len(ctx.code)
    ctx.emit(bytes([0xFF, 0x25, 0, 0, 0, 0]))

    method = Method('_csh_wrapper', [], None, ctx.text_rva + jmp_off)
    method.end_rva = ctx.text_rva + len(ctx.code)
    method.body_begin_rva = method.rva
    method.body_end_rva = method.end_rva
    method.prologue_size = 0
    method.prologue_codes = []
    method.has_seh = False
    method.seh_scopes = []

    ui = UnwindInfo()
    ui.version = 1
    ui.flags = 0
    ui.size_of_prolog = 0
    ui.codes = []
    ui.frame_register = 0
    ui.frame_offset = 0
    ui.handler_rva = 0
    ui.scope_table = []
    method.unwind_info = ui

    ctx.method_registry.register(method)

    iat_rva = ctx.iat["__C_specific_handler"]
    next_rva = ctx.text_rva + jmp_off + 6
    struct.pack_into("<i", ctx.code, jmp_off + 2, iat_rva - next_rva)

    return method.rva

def gen_runtime_guard(ctx):
    csh_rva = gen_csh_wrapper(ctx)
    return csh_rva
