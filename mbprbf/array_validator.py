
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
