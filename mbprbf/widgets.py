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

"""widgets.py - классы виджетов и Window/Timer для MBRBF."""

from .consts import (
    WS_CHILD, WS_VISIBLE, WS_BORDER, WS_VSCROLL, WS_GROUP,
    ES_LEFT, ES_AUTOHSCROLL, ES_READONLY,
    BS_PUSHBUTTON, BS_AUTOCHECKBOX, BS_AUTORADIOBUTTON, BS_GROUPBOX,
    SS_LEFT, SS_SUNKEN,
    LBS_NOTIFY, LBS_HASSTRINGS,
    CBS_DROPDOWNLIST,
    TBS_HORZ, TBS_AUTOTICKS,
    STYLE_TEXTAREA, STYLE_BUTTON, STYLE_LABEL,
)


class Widget:
    def __init__(self, name, id_val, x, y, w, h, style, parent=None):
        self.name = name
        self.id_val = id_val
        self.x, self.y, self.w, self.h = x, y, w, h
        self.style = style
        self.parent = parent
        self.cls_rva = None
        self.text_rva = None
        self.data_off = None


class Label(Widget):
    def __init__(self, name, text, id_val, x, y, w, h,
                 style=STYLE_LABEL, parent=None):
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "STATIC"
        self.text = text


class Button(Widget):
    def __init__(self, name, text, id_val, x, y, w, h,
                 style=STYLE_BUTTON, on_click=None, parent=None):
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "BUTTON"
        self.text = text
        self.on_click = on_click


class TextArea(Widget):
    def __init__(self, name, text, id_val, x, y, w, h,
                 style=STYLE_TEXTAREA, readonly=False, parent=None):
        if readonly:
            style = style | ES_READONLY
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "EDIT"
        self.text = text
        self.readonly = readonly


class CheckBox(Widget):
    def __init__(self, name, text, id_val, x, y, w, h,
                 style=None, on_click=None, parent=None):
        if style is None:
            style = WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "BUTTON"
        self.text = text
        self.on_click = on_click


class RadioButton(Widget):
    def __init__(self, name, text, id_val, x, y, w, h,
                 group_start=False, on_click=None, parent=None):
        style = WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON
        if group_start:
            style |= WS_GROUP
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "BUTTON"
        self.text = text
        self.on_click = on_click


class GroupBox(Widget):
    def __init__(self, name, text, id_val, x, y, w, h,
                 style=None, parent=None):
        if style is None:
            style = WS_CHILD | WS_VISIBLE | BS_GROUPBOX
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "BUTTON"
        self.text = text


class ListBox(Widget):
    def __init__(self, name, id_val, x, y, w, h,
                 style=None, parent=None):
        if style is None:
            style = (WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL
                     | LBS_NOTIFY | LBS_HASSTRINGS)
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "LISTBOX"
        self.text = ""


class ComboBox(Widget):
    def __init__(self, name, id_val, x, y, w, h,
                 style=None, parent=None):
        if style is None:
            style = WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "COMBOBOX"
        self.text = ""


class ProgressBar(Widget):
    def __init__(self, name, id_val, x, y, w, h,
                 style=None, parent=None):
        if style is None:
            style = WS_CHILD | WS_VISIBLE
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "msctls_progress32"
        self.text = ""


class TrackBar(Widget):
    def __init__(self, name, id_val, x, y, w, h,
                 style=None, parent=None):
        if style is None:
            style = WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_AUTOTICKS
        super().__init__(name, id_val, x, y, w, h, style, parent)
        self.cls_name = "msctls_trackbar32"
        self.text = ""


class Timer:
    def __init__(self, id_val, ms, on_tick=None, parent=None, autostart=True):
        self.id_val = id_val
        self.ms = ms
        self.on_tick = on_tick
        self.parent = parent
        self.autostart = autostart


class Window:
    def __init__(self, title, w, h,
                 cls_name=None,
                 style=0x00CF0000,
                 on_resize=None,
                 on_destroy=None,
                 on_paint=None,
                 on_create=None,
                 erase_bg=True,
                 ex_style=0,
                 double_buffer=False,
                 visible=True,
                 is_main=True,
                 icon=None):
        self.title = title
        self.w, self.h = w, h
        self.cls_name = cls_name or ("MyGuiClass_" + str(id(self) & 0xFFFF))
        self.style = style
        self.on_resize = on_resize
        self.on_destroy = on_destroy
        self.on_paint = on_paint
        self.visible = visible
        self.is_main = is_main
        self.icon = icon
        self.erase_bg = erase_bg
        self.ex_style = ex_style
        self.icon_res_id = None
        self.cls_rva = None
        self.title_rva = None
        self.hwnd_off = None
        self.wc_off = None
        self.wndproc_rva = None
        self.create_rva = None
        self.icon_rva = None
        self.double_buffer = double_buffer
        self.on_create = on_create