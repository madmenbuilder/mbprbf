#!/usr/bin/env python3
"""gui.py - тонкий фасад над новыми модулями MBRBF.

Реэкспортирует всё, что нужно генераторам gen_*.py:
  - виджеты и Window/Timer из widgets.py
  - build_gui из gui_builder.py
  - data_alloc/add_string/reset_data/data_alloc_struct из data.py
  - все WinAPI-константы из consts.py
"""

# ---- константы ----
from .consts import *  # noqa: F401,F403

# ---- виджеты и Window/Timer ----
from .widgets import *

# ---- данные ----
from .data import *

# ---- структуры ----
from .structs import *

# ---- импорты WinAPI ----
from .imports import *

# ---- контексты ----
from .contexts import *

# ---- сборка ----
from .gui_builder import *
