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


"""structs.py - WinAPI-структуры (ctypes) и их сборка."""
import ctypes
from ctypes import wintypes

from .consts import (
    CS_HREDRAW, CS_VREDRAW, COLOR_WINDOW,
    OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST, OFN_HIDEREADONLY, OFN_EXPLORER,
)

class OPENFILENAMEA(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("lStructSize",       wintypes.DWORD),
        ("hwndOwner",         wintypes.HWND),
        ("hInstance",         wintypes.HINSTANCE),
        ("lpstrFilter",       wintypes.LPCSTR),
        ("lpstrCustomFilter", wintypes.LPSTR),
        ("nMaxCustFilter",    wintypes.DWORD),
        ("nFilterIndex",      wintypes.DWORD),
        ("lpstrFile",         wintypes.LPSTR),
        ("nMaxFile",          wintypes.DWORD),
        ("lpstrFileTitle",    wintypes.LPSTR),
        ("nMaxFileTitle",     wintypes.DWORD),
        ("lpstrInitialDir",   wintypes.LPCSTR),
        ("lpstrTitle",        wintypes.LPCSTR),
        ("Flags",             wintypes.DWORD),
        ("nFileOffset",       wintypes.WORD),
        ("nFileExtension",    wintypes.WORD),
        ("lpstrDefExt",       wintypes.LPCSTR),
        ("lCustData",         wintypes.LPARAM),
        ("lpfnHook",          ctypes.c_void_p),
        ("lpTemplateName",    wintypes.LPCSTR),
        ("pvReserved",        ctypes.c_void_p),
        ("dwReserved",        wintypes.DWORD),
        ("FlagsEx",           wintypes.DWORD),
    ]

assert ctypes.sizeof(OPENFILENAMEA) == 0x98, ctypes.sizeof(OPENFILENAMEA)
OPENFILENAMEA_SIZE = 0x98

class WNDCLASSEXA(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("cbSize",        wintypes.UINT),
        ("style",         wintypes.UINT),
        ("lpfnWndProc",   ctypes.c_void_p),
        ("cbClsExtra",    ctypes.c_int),
        ("cbWndExtra",    ctypes.c_int),
        ("hInstance",     wintypes.HINSTANCE),
        ("hIcon",         wintypes.HICON),
        ("hCursor",       wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName",  wintypes.LPCSTR),
        ("lpszClassName", wintypes.LPCSTR),
        ("hIconSm",       wintypes.HICON),
    ]

assert ctypes.sizeof(WNDCLASSEXA) == 0x50, ctypes.sizeof(WNDCLASSEXA)
WNDCLASSEXA_SIZE = 0x50

WINAPI_STRUCTS = {
    "OPENFILENAMEA": {
        "cls": OPENFILENAMEA,
        "size": OPENFILENAMEA_SIZE,
        "rva_fields": (
            "lpstrFilter", "lpstrCustomFilter",
            "lpstrFile", "lpstrFileTitle",
            "lpstrInitialDir", "lpstrTitle",
            "lpstrDefExt", "lpTemplateName",
        ),
        "defaults": {
            "lStructSize":  OPENFILENAMEA_SIZE,
            "nFilterIndex": 1,
            "Flags":        (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST
                             | OFN_HIDEREADONLY | OFN_EXPLORER),
        },
    },
    "WNDCLASSEXA": {
        "cls": WNDCLASSEXA,
        "size": WNDCLASSEXA_SIZE,
        "rva_fields": ("lpfnWndProc", "lpszMenuName", "lpszClassName"),
        "defaults": {
            "cbSize":        WNDCLASSEXA_SIZE,
            "style":         CS_HREDRAW | CS_VREDRAW,
            "hbrBackground": COLOR_WINDOW + 1,
        },
    },
}

SERVICE_STRUCTS = {
    "wndclassex": "WNDCLASSEXA",
}

def build_winapi_struct(cls, values, image_base, rva_fields=()):
    s = cls()
    rva_set = set(rva_fields)
    for name, value in values.items():
        if not hasattr(s, name):
            raise KeyError(f"build_winapi_struct: поле {name!r} "
                           f"отсутствует в {cls.__name__}")
        if name in rva_set and value:
            value = image_base + value
        setattr(s, name, value)
    return bytes(s)

def build_struct(name, image_base, **overrides):
    spec = WINAPI_STRUCTS[name]
    values = dict(spec["defaults"])
    values.update(overrides)
    return build_winapi_struct(spec["cls"], values, image_base,
                                rva_fields=spec["rva_fields"])

def resolve_struct_override(val, string_rvas, data_rva_final, data_alloc, windows):
    if not isinstance(val, tuple) or not val:
        return val
    tag = val[0]
    if tag == "@str":
        return string_rvas.get(val[1], 0)
    if tag == "@data":
        return data_rva_final + data_alloc[val[1]]["off"]
    if tag == "@size":
        return data_alloc[val[1]]["size"]
    if tag == "@rva":
        ref_win = next((w for w in windows if w.cls_name == val[1]), None)
        if ref_win is None:
            raise ValueError(f"@rva: окно {val[1]!r} не найдено")
        return getattr(ref_win, val[2])
    raise ValueError(f"resolve_struct_override: неизвестный тег {tag!r}")
