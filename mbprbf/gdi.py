#!/usr/bin/env python3
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
