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

import ctypes

class FFIStruct(ctypes.Structure):
    """Базовая структура для FFI."""

    @classmethod
    def size(cls):
        return ctypes.sizeof(cls)

    @classmethod
    def field_offsets(cls):
        """Список (name, offset, size, ctype) для всех полей."""
        result = []
        for name, ftype in cls._fields_:
            field = getattr(cls, name)
            result.append((name, field.offset, field.size, ftype))
        return result

    @classmethod
    def is_by_pointer(cls):
        """True, если структура передаётся по указателю.

        По Microsoft x64 ABI: структура передаётся по указателю,
        если её размер >8 байт или если она нерегулярна (3/5/6/7 байт
        из-за упаковки, но ctypes уже сам выравнивает — так что
        достаточно size > 8).
        """
        return ctypes.sizeof(cls) > 8
