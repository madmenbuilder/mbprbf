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


"""memory_tracker.py - трекинг выделений памяти на этапе сборки.

Отслеживает ВСЕ выделения/освобождения памяти в MBPRBF:
    - heap_alloc / heap_alloc_at_rva
    - heap_realloc / heap_realloc_at_rva
    - heap_free / heap_free_at_rva
    - array_alloc (неявный через emit_array_alloc)
    - array_free

Используется для MemoryException на этапе сборки:
    - утечка (выделили, но не освободили)
    - double free
    - invalid free (free неизвестного указателя)
    - realloc неизвестного указателя
"""

from .exceptions import MemoryException
import inspect
import os

_ALLOCATIONS = {}

_RUNTIME_BASENAMES = {
    "memory_tracker.py",
    "contexts.py",
    "array_validator.py",
    "arrays.py",
    "array_runtime.py",
    "mb_array.py",
    "methods.py",
    "structs.py",
    "data.py",
    "pe_builder.py",
    "console_builder.py",
    "gui_builder.py",
    "imports.py",
    "consts.py",
    "exceptions.py",
}

def reset_tracking():
    _ALLOCATIONS.clear()

def _caller_location(skip_internal=True):
    """Вернуть 'file.py:LINE in func' первого не-внутреннего кадра."""
    frame = inspect.currentframe()
    try:
        frame = frame.f_back
        while frame is not None:
            basename = os.path.basename(frame.f_code.co_filename)
            if not skip_internal or basename not in _RUNTIME_BASENAMES:
                return f"{basename}:{frame.f_lineno} in {frame.f_code.co_name}"
            frame = frame.f_back
        return "<unknown>"
    finally:
        del frame

def track_alloc(name, kind, location=None):
    if location is None:
        location = _caller_location()
    if name in _ALLOCATIONS:
        raise MemoryException(
            f"memory: double alloc — '{name}' уже выделен ранее "
            f"({_ALLOCATIONS[name]['location']}), повторное выделение в {location}"
        )
    _ALLOCATIONS[name] = {
        "kind": kind,
        "location": location,
        "freed_at": None,
    }

def track_free(name, location=None):
    """Зарегистрировать освобождение. Бросает MemoryException при ошибках."""
    if location is None:
        location = _caller_location()
    entry = _ALLOCATIONS.get(name)
    if entry is None:
        raise MemoryException(
            f"memory: invalid free — '{name}' не отслеживается "
            f"(освобождение в {location})"
        )
    if entry["freed_at"] is not None:
        raise MemoryException(
            f"memory: double free — '{name}' уже освобождён в "
            f"{entry['freed_at']}, повторно в {location}"
        )
    entry["freed_at"] = location

def ensure_alive(name, location=None):
    """Проверить, что объект памяти не освобождён. MemoryException при use after free."""
    if location is None:
        location = _caller_location()
    entry = _ALLOCATIONS.get(name)
    if entry is None:
        return  
    if entry["freed_at"] is not None:
        raise MemoryException(
            f"memory: use after free — '{name}' освобождён в "
            f"{entry['freed_at']}, обращение в {location}"
        )

def track_realloc(name, location=None):
    """Зарегистрировать realloc. Бросает MemoryException при realloc неизвестного.

    После успешного realloc запись остаётся активной (freed_at = None).
    """

    if location is None:
        location = _caller_location()

    entry = _ALLOCATIONS.get(name)
    if entry is None:

        raise MemoryException(
            f"memory: realloc для '{name}', который не отслеживается "
            f"(realloc в {location})"
        )
    if entry["freed_at"] is not None:
        raise MemoryException(
            f"memory: realloc после free — '{name}' освобождён в "
            f"{entry['freed_at']}, realloc в {location}"
        )

def check_all_freed():
    """Проверить утечки. MemoryException, если есть не освобождённые."""
    leaks = [
        (name, entry)
        for name, entry in _ALLOCATIONS.items()
        if entry["freed_at"] is None
    ]
    if leaks:
        lines = "\n".join(
            f"  - {name} ({entry['kind']}) выделен в {entry['location']}"
            for name, entry in leaks
        )
        raise MemoryException(
            f"memory: утечка памяти — не освобождены:\n{lines}\n"
            f"Вызовите heap_free / array_free для каждого выделения."
        )

def get_all():
    """Для отладки — все текущие записи."""
    return dict(_ALLOCATIONS)
