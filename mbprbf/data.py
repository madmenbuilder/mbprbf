
"""data.py - раскладка и сборка секции .data, глобальный реестр данных."""

import struct

from .pe_builder import align_up
from .consts import TEXT_BUF_SIZE, WC_SIZE
import ctypes

from .array_validator import reset_tracking

DATA_OFF_MSG        = 0x050   
DATA_OFF_HINST      = 0x080   
DATA_OFF_HEAP       = 0x090   
DATA_OFF_FREE_START = 0x0A0   

DATA_ALLOC = {}
DATA_ORDER = []
STRINGS    = {}
WSTRINGS = {}

def reset_data():
    DATA_ALLOC.clear()
    DATA_ORDER.clear()
    STRINGS.clear()
    WSTRINGS.clear()
    from .arrays import reset_arrays
    reset_arrays()
    reset_tracking()

def data_alloc(name, size, init=0, type="int"):
    if name in DATA_ALLOC:
        raise ValueError(f"data_alloc: '{name}' уже занят")
    DATA_ALLOC[name] = {"off": None, "size": size, "init": init, "type": type}
    DATA_ORDER.append(name)
    return name

def data_alloc_struct(name, struct_name):
    """Зарегистрировать в .data место под WinAPI-структуру."""
    from .structs import WINAPI_STRUCTS
    if struct_name not in WINAPI_STRUCTS:
        raise KeyError(f"data_alloc_struct: {struct_name!r} нет в WINAPI_STRUCTS")
    spec = WINAPI_STRUCTS[struct_name]
    data_alloc(name, spec["size"], 0, type="struct")
    DATA_ALLOC[name]["struct_name"] = struct_name
    return name

def data_alloc_ffi_struct(name, struct_cls, init=None):
    if name in DATA_ALLOC:
        raise ValueError(f"data_alloc_ffi_struct: '{name}' уже занят")

    size = ctypes.sizeof(struct_cls)
    init_bytes = bytes(struct_cls()) if init is None else bytes(init)

    DATA_ALLOC[name] = {
        "off": None,
        "size": size,
        "init": init_bytes,
        "type": "bytes",
    }
    DATA_ORDER.append(name)
    return name

def add_string(name, s):
    if name in STRINGS:
        raise ValueError(f"add_string: '{name}' уже занят")
    STRINGS[name] = s
    return name

def add_wstring(name, s):
    """Зарегистрировать wide-строку (UTF-16LE) в .rdata."""
    if name in WSTRINGS:
        raise ValueError(f"add_wstring: '{name}' уже занят")
    WSTRINGS[name] = s
    return name

def data_alloc_points(name, points):
    """Зарегистрировать POINT-массив в .data.

    points — список (x, y), каждая точка = 8 байт (2 × int32).
    """
    if name in DATA_ALLOC:
        raise ValueError(f"data_alloc_points: '{name}' уже занят")
    size = len(points) * 8
    DATA_ALLOC[name] = {
        "off": None,
        "size": size,
        "init": 0,
        "type": "points",
        "points": list(points),
    }
    DATA_ORDER.append(name)
    return name

def layout_data(widgets, windows, data_alloc, data_order):
    """Распределить смещения в .data.

    Возвращает (widget_offsets, text_buf_off, data_size).
    """
    cursor = DATA_OFF_FREE_START

    for win in windows:
        cursor = align_up(cursor, 8)
        win.wc_off = cursor
        cursor += WC_SIZE

    for win in windows:
        win.hwnd_off = cursor
        cursor += 8

    widget_offsets = {}
    for w in widgets:
        widget_offsets[w.name] = cursor
        cursor += 8

    cursor = align_up(cursor, 8)

    for name in data_order:
        cursor = align_up(cursor, 8)
        data_alloc[name]["off"] = cursor
        cursor += data_alloc[name]["size"]

    cursor = align_up(cursor, 16)
    text_buf_off = cursor
    cursor += TEXT_BUF_SIZE
    cursor = align_up(cursor, 16)

    errors = []
    for name in data_order:
        info = data_alloc[name]
        off = info["off"]
        size = info["size"]
        end = off + size
        if off % 8 != 0:
            errors.append(f"{name}: off={off:#x} не выровнен на 8")
        if end > cursor:
            errors.append(f"{name}: end={end:#x} > cursor={cursor:#x}")
    if text_buf_off + TEXT_BUF_SIZE > cursor:
        errors.append(
            f"text_buf: {text_buf_off:#x}+{TEXT_BUF_SIZE:#x}="
            f"{text_buf_off+TEXT_BUF_SIZE:#x} > cursor={cursor:#x}"
        )
    if errors:
        raise ValueError("layout_data: выход за пределы .data:\n  "
                         + "\n  ".join(errors))

    return widget_offsets, text_buf_off, cursor

def build_data(data_size, data_alloc, data_order):
    d = bytearray(data_size)
    for name in data_order:
        info = data_alloc[name]
        off = info["off"]
        size = info["size"]
        init = info["init"]
        typ = info.get("type", "int")

        if typ == "points":
            pts = info["points"]
            for i, (x, y) in enumerate(pts):
                struct.pack_into("<i", d, off + i * 8 + 0, x)
                struct.pack_into("<i", d, off + i * 8 + 4, y)
        elif typ == "bytes":
            blob = info["init"]
            d[off:off + len(blob)] = blob
        elif typ == "float":
            if size == 4:
                struct.pack_into("<I", d, off, init & 0xFFFFFFFF)
            elif size == 8:
                struct.pack_into("<Q", d, off, init & 0xFFFFFFFFFFFFFFFF)
        else:
            if size == 4:
                struct.pack_into("<I", d, off, init & 0xFFFFFFFF)
            elif size == 8:
                struct.pack_into("<Q", d, off, init & 0xFFFFFFFFFFFFFFFF)
            else:
                struct.pack_into("<I", d, off, init & 0xFFFFFFFF)
    return bytes(d)
