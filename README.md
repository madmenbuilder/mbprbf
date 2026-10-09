# MBPRBF

**MBPRBF** (*Madmen Builder for Programs on Raw Bytes Framework*) —
фреймворк для описания логики Windows-приложения **на Python** и получения
нативного PE-файла (`.exe`) под **Windows x64**, без компилятора C/C++ и
без рантайм-зависимостей.

Сборщик сам генерирует машинный код x86-64, собирает секции PE
(`.text`, `.rdata`, `.data`, `.rsrc`, `.pdata`, `.xdata`, `.reloc`),
таблицы импорта, ресурсы (иконки, манифест, версия), SEH-таблицы и
корректный PE-заголовок.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Platform: Windows x64](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)]()
[![PyPI](https://img.shields.io/pypi/v/mbprbf.svg)](https://pypi.org/project/mbprbf/)

```
Python-описание (GUI / Console / GDI)  ───►  Нативный .exe (x64)
                                             без Python, без DLL-рантайма
```

## Содержание

- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Быстрый старт](#быстрый-старт)
  - [Консоль](#консоль)
  - [GUI](#gui)
  - [GDI](#gdi)
- [Массивы](#массивы)
- [Методы и WinAPI](#методы-и-winapi)
- [FFI и структуры](#ffi-и-структуры)
- [SEH](#seh)
- [Трекер памяти](#трекер-памяти)
- [Модули](#модули)
- [Ограничения](#ограничения)

## License

MBPRBF is licensed under the **GNU General Public License v3.0 or later**
(GPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.

Copyright (C) 2026 Madmen3733.

## Author

**Madmen3733** — [github.com/madmenmadmen](https://github.com/madmenmadmen)

## Links

- **GitHub**: https://github.com/madmenmadmen/mbprbf
- **PyPI**: https://pypi.org/project/mbprbf/
- **Issues**: https://github.com/madmenmadmen/mbprbf/issues

## Возможности

- **Три типа приложений**:
  - консольные (`IMAGE_SUBSYSTEM_WINDOWS_CUI`),
  - GUI (`IMAGE_SUBSYSTEM_WINDOWS_GUI`),
  - GDI (рисование поверх окна).
- **Прямая эмиссия машинного кода x86-64**.
- **Система методов** по Microsoft x64 ABI: `RCX/RDX/R8/R9` + `XMM0–XMM3`,
  счётчики int/float, forward references для рекурсии,
  корректное выравнивание `RSP`, varargs.
- **Массивы MBPRBF** — смешанные/однородные, статические/динамические.
- **Структуры WinAPI** на `ctypes` с релокацией RVA-полей.
- **FFI** — экспорт C-функций из DLL с автопроверкой экспортов.
- **SEH x64** — `try_` / `except_` / `finally_`, `.pdata` / `.xdata`.
- **Трекер памяти** на этапе сборки.
- **Ресурсы PE** — иконки, манифест, `VS_VERSIONINFO`.
- **GDI-изображения** — PNG → DIB → `CreateDIBSection`, спрайты с маской.

## Архитектура

```
Пользовательский код (build_console / build_gui / build_gdi)
        │
        ├── console_builder.py
        ├── gui_builder.py
        └── gdi_builder.py
                │
                ▼
        Контексты (contexts.py)
        Context → GUIContext / ConsoleContext / GDIContext
                │
        ┌───────┼───────────┐
        ▼       ▼           ▼
   asm_helper  methods    seh
                │
                ▼
        PE-сборщик (pe_builder.py)
```

## Быстрый старт

> Фасады `gui.py` / `gdi.py` реэкспортируют
> `Window`, `Button`, `add_string`, `build_gui` / `build_gdi` через
> `from ... import *`, поэтому тянуть их напрямую из `widgets.py`,
> `data.py`, `gui_builder.py` не обязательно.

### Консоль

```python
from console_builder import build_console
from data import add_string

add_string("_hello", "Hello, MBPRBF!\r\n")

def main(ctx):
    ctx.write_str("_hello")

build_console("hello.exe", main)
```

Альтернатива — `add_string` реэкспортируется самим `console_builder.py`:

```python
from console_builder import build_console, add_string
```

### GUI

```python
from gui import (
    Window, Button,
    build_gui, add_string,
)

add_string("_title", "Demo")
add_string("_msg", "Clicked!")

def on_click(ctx):
    ctx.message_box_str("_msg", "_title", 0)

win = Window("Demo", 400, 300)

btn = Button(
    name="btn1",
    text="Click me",
    id_val=1001,
    x=20, y=20, w=120, h=32,
    on_click=on_click,
    parent=win,
)

build_gui("demo.exe", [win], [btn], timers=[])
```

### GDI

```python
from gdi import (
    Window, Rect, Circle, Text,
    build_gdi, add_string, rgb,
)

add_string("_title", "GDI Demo")

win = Window("GDI Demo", 640, 480, double_buffer=True)

shapes = [
    Rect(20, 20, 200, 100, fill=rgb(200, 30, 30), border=0),
    Circle(320, 240, 80, fill=rgb(30, 120, 200), border=0),
    Text(20, 400, "Hello, GDI", color=0x000000, size=24),
]

build_gdi("gdi_demo.exe", [win], [], shapes, timers=[])
```

## Массивы

Слот `Array` в `.data` — 96 байт:

| Смещение | Размер | Поле               | Описание                         |
|----------|--------|--------------------|----------------------------------|
| `+0x00`  | 8      | `ptr`              | указатель на данные (heap)       |
| `+0x08`  | 8      | `length`           | количество элементов             |
| `+0x10`  | 8      | `capacity`         | ёмкость данных, байт             |
| `+0x18`  | 8      | `used_bytes`       | занято байт (после выравнивания) |
| `+0x20`  | 8      | `types_ptr`        | `uint32[]` коды типов            |
| `+0x28`  | 8      | `offsets_ptr`      | `uint32[]` смещения              |
| `+0x30`  | 8      | `offsets_capacity` | ёмкость `types`/`offsets`        |
| `+0x38`  | 4      | `elem_size`        | размер для однородных            |
| `+0x3C`  | 4      | `flags`            | битовые флаги                    |

Создание — `arrays.array(...)`. Runtime-операции — методы `ctx`
(они сами вызовут `ensure_runtime` с нужным набором зависимостей):

```python
import ctypes
from arrays import array, array_get, array_set, array_len, array_free

a = array([1, 2, 3])                       # динамический int32
b = array([1.5, 2.5], types=[ctypes.c_float])
c = array(size=10)                          # статический, int32
d = array(size=10, type=ctypes.c_float)     # статический, float32

# read/write — статика/динамика
array_get(ctx, a, 1)                        # или ctx.array_get(a, 1)
array_set(ctx, a, 1, 42)
array_len(ctx, a)

# runtime-операции — только для динамических
ctx.array_append(a, 4)
ctx.array_insert(a, 1, 99)
ctx.array_remove(a, 0)
ctx.array_resize(a, 8)

array_free(ctx, a)
```

## Методы и WinAPI

```python
import ctypes

ctx.start_method("add", [ctypes.c_int32, ctypes.c_int32],
                 ret_type=ctypes.c_int32)
# ... эмиссия тела ...
ctx.end_method()

ctx.call_method("add", (5, 7))
ctx.call_iat("MessageBoxA")
```

## FFI и структуры

`ffi_export_method` возвращает `Method` и регистрирует его под именем
`"_" + alias` (или `"_" + name`, если alias не задан). Именно это имя
нужно передавать в `call_method`.

```python
import ctypes

ctx.ffi_export_method(
    "GetTickCount", "kernel32.dll",
    args=[], ret=ctypes.c_uint32, alias="GetTickCount",
)
ctx.call_method("_GetTickCount", [])
```

Структуры:

```python
from data import data_alloc_struct
data_alloc_struct("_ofn", "OPENFILENAMEA")
```

## SEH

```python
with ctx.try_():
    # ...
    with ctx.except_(EXCEPTION_EXECUTE_HANDLER):
        pass

with ctx.try_():
    pass
    with ctx.finally_(lambda c: c.call_iat("CloseHandle")):
        pass
```

## Трекер памяти

`memory_tracker.py` ловит на этапе сборки:

- двойную аллокацию,
- double free,
- use-after-free,
- утечки (`check_all_freed()`).

## Модули

| Файл                 | Назначение                                              |
|----------------------|---------------------------------------------------------|
| `asm_helper.py`      | эмиттеры инструкций, `call_iat`, `call_rva`, ветвления  |
| `methods.py`         | ABI, прологи/эпилоги, `start_method` / `call_method`    |
| `contexts.py`        | `Context`, `GUIContext`, `ConsoleContext`, `GDIContext` |
| `console_builder.py` | сборка `.exe` для CUI                                   |
| `gui_builder.py`     | сборка `.exe` для GUI + `.rsrc`                         |
| `gdi_builder.py`     | надстройка над GUI для GDI                              |
| `widgets.py`         | виджеты, `Window`, `Timer`                              |
| `gdi_objects.py`     | фигуры, `rgb`, вращение                                 |
| `structs.py`         | WinAPI-структуры                                        |
| `data.py`            | `.data`: `DATA_ALLOC`, строки, структуры                |
| `mb_array.py`        | ядро массивов                                           |
| `arrays.py`          | регистрация, init, get/set/len/free                     |
| `array_runtime.py`   | append / insert / remove / resize                       |
| `array_validator.py` | валидация и трекинг                                     |
| `memory_tracker.py`  | трекер аллокаций                                        |
| `seh.py`             | `.pdata` / `.xdata`, `UnwindInfo`, scope-таблицы        |
| `runtime_guard.py`   | SEH-guard и `__C_specific_handler` wrapper              |
| `pe_builder.py`      | PE-заголовок, секции, `.rsrc`, `.reloc`                 |
| `imports.py`         | `IMPORT_DLL`, `CORE_IMPORTS`, `CONSOLE_CORE_IMPORTS`    |
| `consts.py`          | WinAPI-константы                                        |

## Ограничения

- Только Windows x64, MS ABI.
- Нет встроенного аллокатора регистров — промежуточные значения живут на стеке.
- Стек методов фиксируется на этапе `end_method`.
- Плавающая точка — только через `XMM` или x87-эмиттеры, без выражений.