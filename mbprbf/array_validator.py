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


"""array_validator.py - валидация массивов на этапе сборки.

Обёртка над memory_tracker для проверки границ и трекинга массивов.
"""

from .exceptions import OutOfBoundsException
from . import memory_tracker as mt

from .mb_array import (ARR_PTR_OFF, ARR_TYPES_PTR_OFF, ARR_OFFSETS_PTR_OFF)

def reset_tracking():
    mt.reset_tracking()

def ensure_alive(ctx, arr):
    """Проверить, что все три блока массива не освобождены.

    Ключи — heap@RVA, те же, что создаёт heap_alloc_at_rva.
    """
    slot_rva = ctx.rva_of(arr.name)
    mt.ensure_alive(f"heap@{slot_rva + ARR_PTR_OFF:#x}")
    mt.ensure_alive(f"heap@{slot_rva + ARR_TYPES_PTR_OFF:#x}")
    mt.ensure_alive(f"heap@{slot_rva + ARR_OFFSETS_PTR_OFF:#x}")

def check_bounds_static(arr, index, location):
    """Проверка границ для статических массивов."""
    if not getattr(arr, "is_static", False):
        return
    if not isinstance(index, int):
        return
    if index < 0 or index >= arr.length:
        raise OutOfBoundsException(
            f"array '{arr.name}': статический массив, "
            f"индекс {index} вне [0, {arr.length}) ({location})"
        )
