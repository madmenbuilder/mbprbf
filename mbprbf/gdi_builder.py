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

"""gdi_builder.py - сборка GDI-приложений."""

from .gui_builder import build_gui as _build_gui
from .gdi_objects import (Polygon as PolygonShape,
                          Image as ImageShape)
from . import data as _data
import struct

def _png_to_dib_blob(source, w=None, h=None, shape=None):
    from PIL import Image
    import io

    if isinstance(source, (bytes, bytearray)):
        img = Image.open(io.BytesIO(source))
    else:
        img = Image.open(source)
    img = img.convert("RGBA")

    if w is not None and h is not None:
        img = img.resize((w, h), Image.LANCZOS)
        W, H = w, h
    else:
        W, H = img.size

    # упаковка BGRA (без premultiply, без shape)
    buf = bytearray(8 + W * H * 4)
    struct.pack_into("<I", buf, 0, W)
    struct.pack_into("<I", buf, 4, H)

    px = img.load()
    off = 8
    for y in range(H):
        for x in range(W):
            r, g, b, a = px[x, y]
            buf[off + 0] = b
            buf[off + 1] = g
            buf[off + 2] = r
            buf[off + 3] = 255    # alpha не важна
            off += 4

    return bytes(buf)

def f2i(v):
    """float32 → uint32 биты (для data_alloc с type='float')."""
    return struct.unpack("<I", struct.pack("<f", v))[0]

def build_gdi(out_path, windows, widgets, shapes, timers,
              data_alloc=None, data_order=None, strings=None,
              imports=None, extra_strings=None,
              version=None, icon=None,
              text_rva=0x1000):
    if data_alloc is None: data_alloc = _data.DATA_ALLOC
    if data_order is None: data_order = _data.DATA_ORDER
    if strings    is None: strings    = _data.STRINGS

    # ------------------------------------------------------------------
    # 1) Text-строки
    # ------------------------------------------------------------------
    if "_face_Arial" not in strings:
        _data.add_string("_face_Arial", "Arial")
    if "_dyn_text_len" not in data_alloc:
        _data.data_alloc("_dyn_text_len", 4, 0)
    if "_rot_k" not in data_alloc:
        data_alloc("_rot_k", 4, init=f2i(3.14159265 / 180.0), type="float")
    if "_rot_cos" not in data_alloc:
        data_alloc("_rot_cos", 4, init=f2i(1.0), type="float")
    if "_rot_sin" not in data_alloc:
        data_alloc("_rot_sin", 4, init=f2i(0.0), type="float")

    for s in shapes:
        txt = getattr(s, "text", None)
        if txt:
            key = "_text_" + txt
            if key not in strings:
                _data.add_string(key, txt)
        face = getattr(s, "face", None)
        if face:
            fkey = "_face_" + face
            if fkey not in strings:
                _data.add_string(fkey, face)

    for s in shapes:
        if getattr(s, "fmt_name", None) is not None:
            buf = s.buf_name
            if buf not in data_alloc:
                _data.data_alloc(buf, 128, b"\x00" * 128, type="bytes")

    # ------------------------------------------------------------------
    # 2) POINT-массивы для Polygon (верхнеуровневых)
    # ------------------------------------------------------------------
    for s in shapes:
        if isinstance(s, PolygonShape):
            name = s.data_name
            if name not in data_alloc:
                _data.data_alloc_points(name, s.points)

    import hashlib

    extra_resources = []
    next_res_id = 1000
    need_res_slots = False
    _res_cache = {}  # sha256(blob) → res_id

    for s in shapes:
        if not isinstance(s, ImageShape):
            continue

        # --- слоты per-Image ---
        for key in (s.himg_key, s.hsrc_dc_key, s.hsrc_bmp_old_key):
            if key not in data_alloc:
                _data.data_alloc(key, 8, 0, type="int")
        for key in (s.img_w_key, s.img_h_key):
            if key not in data_alloc:
                _data.data_alloc(key, 4, 0, type="int")
        uid = s.uid
        for suffix in ("mask_dc", "mask_bmp", "mask_old",
                       "mask_inv_dc", "mask_inv_bmp", "mask_inv_old",
                       "spr_dc", "spr_bmp", "spr_old"):
            key = f"_img_{suffix}_{uid}"
            if key not in data_alloc:
                _data.data_alloc(key, 8, 0, type="int")

        # --- POINT-массивы для Polygon-формы внутри Image ---
        shp = s.shape
        if isinstance(shp, PolygonShape):
            if shp.data_name not in data_alloc:
                _data.data_alloc_points(shp.data_name, shp.points)

        if getattr(s, "embed", False):
            dib_blob = _png_to_dib_blob(
                s.source,
                w=s.w, h=s.h
            )
            digest = hashlib.sha256(dib_blob).digest()
            if digest in _res_cache:
                s.res_id = _res_cache[digest]
            else:
                s.res_id = next_res_id
                _res_cache[digest] = next_res_id
                extra_resources.append((10, next_res_id, 0x0409, dib_blob))
                next_res_id += 1
            need_res_slots = True

    # --- общие слоты ресурсов ---
    if need_res_slots:
        for key, size in [
            ("_res_hrsrc",  8),
            ("_res_size",   8),
            ("_res_ptr",    8),
            ("_res_stream", 8),
        ]:
            if key not in data_alloc:
                _data.data_alloc(key, size, 0, type="int")
    for key, size in (
        ("_img_src_dc", 8),
        ("_img_src_old", 8),
    ):
        if key not in data_alloc:
            _data.data_alloc(key, size, 0, type="int")

    # ------------------------------------------------------------------
    # 4) Привязка фигур к окнам
    # ------------------------------------------------------------------
    for win in windows:
        win.gdi_shapes = list(shapes)

    # ------------------------------------------------------------------
    # 5) Сборка
    # ------------------------------------------------------------------
    return _build_gui(out_path, windows, widgets, timers,
                      data_alloc=data_alloc, data_order=data_order,
                      strings=strings, imports=imports,
                      extra_strings=extra_strings,
                      version=version, icon=icon,
                      text_rva=text_rva,
                      extra_resources=extra_resources)