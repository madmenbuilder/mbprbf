#!/usr/bin/env python3
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
