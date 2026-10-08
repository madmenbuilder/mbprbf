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

"""gdi.py - фасад GDI для генераторов."""

from .consts import *  # noqa

from .widgets import (  # noqa
    Widget, Label, Button, TextArea, CheckBox, RadioButton,
    GroupBox, ListBox, ComboBox, ProgressBar, TrackBar,
    Timer, Window,
)

from .gdi_objects import (  # noqa
    Shape, Point, Line, Rect, Square, Ellipse, Circle, Polygon, Text, Image,
    rgb,
)

from .data import (  # noqa
    DATA_ALLOC, DATA_ORDER, STRINGS,
    reset_data, data_alloc, data_alloc_struct, add_string,
)

from .structs import (  # noqa
    OPENFILENAMEA, WNDCLASSEXA, WINAPI_STRUCTS, build_struct,
)

from .imports import IMPORT_DLL, CORE_IMPORTS  # noqa

from .contexts import Context, GUIContext, GDIContext  # noqa

from .gdi_builder import build_gdi  # noqa
