
"""mb_array.py - ядро массивов MBPRBF.

Смешанные и однородные, статические и динамические массивы.
Runtime: heap, таблица offsets (uint32), таблица types (uint32).

Раскладка слота Array в .data (0x60 = 96 байт):
    +0x00  uint64_t  ptr                — указатель на данные (heap)
    +0x08  uint64_t  length             — количество элементов
    +0x10  uint64_t  capacity           — ёмкость данных в байтах
    +0x18  uint64_t  used_bytes         — занято байт (после выравнивания)
    +0x20  uint64_t  types_ptr          — uint32[] коды типов
    +0x28  uint64_t  offsets_ptr        — uint32[] offsets
    +0x30  uint64_t  offsets_capacity   — ёмкость types/offsets (элементов)
    +0x38  uint32_t  elem_size          — для однородных
    +0x3C  uint32_t  flags              — битовые флаги
    +0x40  uint64_t  reserved[4]        — запас (32 байта)
"""

import ctypes
import struct

ARR_SLOT_SIZE = 0x60

ARR_PTR_OFF              = 0x00
ARR_LENGTH_OFF           = 0x08
ARR_CAPACITY_OFF         = 0x10
ARR_USED_BYTES_OFF       = 0x18
ARR_TYPES_PTR_OFF        = 0x20
ARR_OFFSETS_PTR_OFF      = 0x28
ARR_OFFSETS_CAPACITY_OFF = 0x30
ARR_ELEM_SIZE_OFF        = 0x38
ARR_FLAGS_OFF            = 0x3C

FLAG_DYNAMIC     = 0x01
FLAG_HOMOGENEOUS = 0x02
FLAG_INITIALIZED = 0x04

T_ERROR   = 0
T_INT8    = 1
T_INT16   = 2
T_INT32   = 3
T_INT64   = 4
T_FLOAT   = 5
T_DOUBLE  = 6
T_CHAR_P  = 7

_SIZE_TABLE = {
    T_ERROR: 0, T_INT8: 1, T_INT16: 2, T_INT32: 4,
    T_INT64: 8, T_FLOAT: 4, T_DOUBLE: 8, T_CHAR_P: 8,
}
_ALIGN_TABLE = {
    T_ERROR: 1, T_INT8: 1, T_INT16: 2, T_INT32: 4,
    T_INT64: 8, T_FLOAT: 4, T_DOUBLE: 8, T_CHAR_P: 8,
}

def type_to_code(t):
    if t in (ctypes.c_int8, ctypes.c_byte, ctypes.c_bool,
             ctypes.c_uint8, ctypes.c_ubyte):
        return T_INT8
    if t in (ctypes.c_int16, ctypes.c_short,
             ctypes.c_uint16, ctypes.c_ushort):
        return T_INT16
    if t in (ctypes.c_int32, ctypes.c_int, ctypes.c_long,
             ctypes.c_uint32, ctypes.c_uint, ctypes.c_ulong):
        return T_INT32
    if t in (ctypes.c_int64, ctypes.c_longlong,
             ctypes.c_uint64, ctypes.c_ulonglong):
        return T_INT64
    if t is ctypes.c_float:
        return T_FLOAT
    if t is ctypes.c_double:
        return T_DOUBLE
    if t in (ctypes.c_char_p, ctypes.c_void_p):
        return T_CHAR_P
    raise TypeError(f"array: неизвестный ctypes-тип {t!r}")

def code_to_size(code):
    return _SIZE_TABLE[code]

def code_to_align(code):
    return _ALIGN_TABLE[code]

def code_is_float(code):
    return code in (T_FLOAT, T_DOUBLE)

def align_up(v, a):
    return (v + a - 1) & ~(a - 1)

def type_of_value(v):
    if isinstance(v, bool):
        return ctypes.c_int32
    if isinstance(v, int):
        return ctypes.c_int32
    if isinstance(v, float):
        return ctypes.c_float
    if isinstance(v, str):
        return ctypes.c_char_p
    if isinstance(v, (bytes, bytearray)):
        return ctypes.c_char_p
    raise TypeError(f"array: не могу определить тип для {v!r}")

class Array:
    __slots__ = (
        'name', 'slot_rva', 'values', 'types', 'type_codes',
        'length', 'is_homogeneous', 'is_dynamic', 'is_static',
        'str_keys', 'offsets', 'capacity', 'used_bytes',
        'offsets_capacity', 'elem_size',
    )

    def __init__(self, name, values, types):
        self.name = name
        self.slot_rva = None
        self.values = list(values)
        self.types = list(types)
        self.type_codes = [type_to_code(t) for t in types]
        self.length = len(values)
        self.is_dynamic = True
        self.is_static = False

        self.is_homogeneous = (
            all(t is self.types[0] for t in self.types) if self.types else True
        )

        self.offsets = []
        cur = 0
        max_align = 1
        for code in self.type_codes:
            a = code_to_align(code)
            s = code_to_size(code)
            max_align = max(max_align, a)
            cur = align_up(cur, a)
            self.offsets.append(cur)
            cur += s
        cur = align_up(cur, max_align)
        self.capacity = cur
        self.used_bytes = cur
        self.offsets_capacity = self.length

        if self.is_homogeneous:
            self.elem_size = code_to_size(self.type_codes[0]) if self.type_codes else 0
        else:
            self.elem_size = 0

        self.str_keys = {}

    def forbid_dynamic(self, method_name):
        """Проверить, что метод разрешён для этого типа массива."""
        if self.is_static:
            raise TypeError(
                f"array '{self.name}': метод '{method_name}' запрещён для "
                f"статического массива (размер известен на сборке)"
            )

    def __repr__(self):
        kind = "homogeneous" if self.is_homogeneous else "mixed"
        return f"Array({self.name!r}, len={self.length}, {kind})"
