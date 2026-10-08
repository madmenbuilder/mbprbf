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


"""gdi_objects.py - фигуры для GDI-рисования.

Каждый Shape умеет emit(ctx) — эмитить код отрисовки в GDIContext.

Вращение: если shape.rotation != 0, вокруг shape.pivot (или центра)
ставится XFORM через SetWorldTransform, рисуется фигура,
затем ставится identity.

Цвет: (r,g,b) или int 0xRRGGBB.
"""

import struct
import math

def rgb(r, g, b):
    """RGB → COLORREF (0x00BBGGRR)."""
    if not (0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255):
        raise ValueError(f"rgb({r},{g},{b}): значения 0..255")
    return (b << 16) | (g << 8) | r

def _colorref(color):
    """(r,g,b) или int 0xRRGGBB → COLORREF int."""
    if color is None:
        return None
    if isinstance(color, tuple):
        if len(color) == 3:
            return rgb(*color)
        raise ValueError(f"цвет: ожидался (r,g,b), получено {color!r}")
    if isinstance(color, int):
        r = (color >> 16) & 0xFF
        g = (color >> 8) & 0xFF
        b = color & 0xFF
        return rgb(r, g, b)
    raise ValueError(f"цвет: неизвестный формат {color!r}")

from .contexts import Context

def _i32(v):
    return Context.i32(v)

def _i16(v):
    return Context.i16(v)

def _i8(v):
    return Context.i8(v)

def _f32_bits(x):
    """float → int32-битовое представление (для eM11 и т.п.)."""
    return struct.unpack("<i", struct.pack("<f", float(x)))[0] & 0xFFFFFFFF

def _is_dynamic(v):
    """True, если v — имя слота в .data (динамика)."""
    return isinstance(v, str)

def _resolve_name(v):
    """Разобрать 'name' или 'name+offset' → (name, offset).

    Возвращает (name, offset) или None, если v — не строка.
    """
    if not isinstance(v, str):
        return None
    if '+' in v:
        name, off_s = v.rsplit('+', 1)
        try:
            return (name.strip(), int(off_s.strip(), 0))
        except ValueError:
            return (v, 0)
    return (v, 0)

def _emit_i32(ctx, reg, v):
    if isinstance(v, str):
        name, off = _resolve_name(v)
        rva = ctx.rva_of(name) + off
        if reg == 'eax':
            ctx.mov_eax_rva(rva)
        elif reg == 'ecx':
            ctx.mov_ecx_rva(rva)
        elif reg == 'edx':
            ctx.mov_edx_rva(rva)
        elif reg == 'r8d':
            ctx.mov_r8d_rva(rva)
        elif reg == 'r9d':
            ctx.emit(bytes([0x45, 0x8B, 0x0D])
                     + struct.pack("<i", rva - (ctx.rva_now() + 7)))
        else:
            raise ValueError(f"_emit_i32: reg={reg}")
    else:
        v_u = v & 0xFFFFFFFF
        if reg == 'eax':
            ctx.emit(bytes([0xB8]) + struct.pack("<I", v_u))
        elif reg == 'ecx':
            ctx.emit(bytes([0xB9]) + struct.pack("<I", v_u))
        elif reg == 'edx':
            ctx.emit(bytes([0xBA]) + struct.pack("<I", v_u))
        elif reg == 'r8d':
            ctx.emit(bytes([0x41, 0xB8]) + struct.pack("<I", v_u))
        elif reg == 'r9d':
            ctx.emit(bytes([0x41, 0xB9]) + struct.pack("<I", v_u))
        else:
            raise ValueError(f"_emit_i32: reg={reg}")

def _emit_add_i32(ctx, reg, v):
    """add reg32, v.

    v: int (imm) или str (имя слота).
    reg: 'eax', 'ecx', 'edx', 'r8d', 'r9d'.
    """
    if _is_dynamic(v):
        name, off = _resolve_name(v)
        rva = ctx.rva_of(name) + off
        if reg == 'eax':
            ctx.add_eax_rva(rva)
        elif reg == 'ecx':
            ctx.emit(bytes([0x03, 0x0D])
                     + struct.pack("<i", rva - (ctx.rva_now() + 6)))
        elif reg == 'edx':
            ctx.emit(bytes([0x03, 0x15])
                     + struct.pack("<i", rva - (ctx.rva_now() + 6)))
        elif reg == 'r8d':
            ctx.emit(bytes([0x44, 0x03, 0x05])
                     + struct.pack("<i", rva - (ctx.rva_now() + 7)))
        elif reg == 'r9d':
            ctx.emit(bytes([0x44, 0x03, 0x0D])
                     + struct.pack("<i", rva - (ctx.rva_now() + 7)))
        else:
            raise ValueError(f"_emit_add_i32: reg={reg}")
    else:
        v_u = v & 0xFFFFFFFF
        if reg == 'eax':
            ctx.add_eax_imm32(v_u)
        elif reg == 'ecx':
            ctx.add_ecx_imm32(v_u)
        elif reg == 'edx':
            ctx.emit(bytes([0x81, 0xC2]) + struct.pack("<I", v_u))
        elif reg == 'r8d':
            ctx.emit(bytes([0x41, 0x81, 0xC0]) + struct.pack("<I", v_u))
        elif reg == 'r9d':
            ctx.emit(bytes([0x41, 0x81, 0xC1]) + struct.pack("<I", v_u))
        else:
            raise ValueError(f"_emit_add_i32: reg={reg}")

def _emit_sub_i32(ctx, reg, v):
    """sub reg32, v."""
    if _is_dynamic(v):
        name, off = _resolve_name(v)
        rva = ctx.rva_of(name) + off
        if reg == 'eax':
            ctx.sub_eax_rva(rva)
        elif reg == 'ecx':
            ctx.emit(bytes([0x2B, 0x0D])
                     + struct.pack("<i", rva - (ctx.rva_now() + 6)))
        elif reg == 'edx':
            ctx.emit(bytes([0x2B, 0x15])
                     + struct.pack("<i", rva - (ctx.rva_now() + 6)))
        elif reg == 'r8d':
            ctx.emit(bytes([0x44, 0x2B, 0x05])
                     + struct.pack("<i", rva - (ctx.rva_now() + 7)))
        elif reg == 'r9d':
            ctx.emit(bytes([0x44, 0x2B, 0x0D])
                     + struct.pack("<i", rva - (ctx.rva_now() + 7)))
        else:
            raise ValueError(f"_emit_sub_i32: reg={reg}")
    else:
        v_u = v & 0xFFFFFFFF
        if reg == 'eax':
            ctx.sub_eax_imm32(v_u)
        elif reg == 'ecx':
            ctx.sub_ecx_imm32(v_u)
        elif reg == 'edx':
            ctx.emit(bytes([0x81, 0xEA]) + struct.pack("<I", v_u))
        elif reg == 'r8d':
            ctx.emit(bytes([0x41, 0x81, 0xE8]) + struct.pack("<I", v_u))
        elif reg == 'r9d':
            ctx.emit(bytes([0x41, 0x81, 0xE9]) + struct.pack("<I", v_u))
        else:
            raise ValueError(f"_emit_sub_i32: reg={reg}")

class Shape:
    """Базовая фигура.

    rotation    - статичный угол в градусах (по часовой), или 0
    pivot       - (x, y) центр вращения для статичного; None = центр фигуры

    spin_angle_name - имя слота в .data (float32, градусы), для
                      ДИНАМИЧЕСКОГО вращения. Если задан — перебивает
                      статичный rotation.
    spin_pivot      - (x, y) центр для динамического вращения. None = центр.
    """

    def __init__(self, rotation=0.0, pivot=None,
                 spin_angle_name=None, spin_pivot=None):
        self.rotation = rotation
        self.pivot = pivot
        self.spin_angle_name = spin_angle_name
        self.spin_pivot = spin_pivot

    def emit(self, ctx):
        raise NotImplementedError

    def emit_mask(self, ctx):
        """Нарисовать фигуру чёрным на mask_dc (1bpp).

        ctx.target_rva уже указывает на mask_dc.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}: emit_mask не реализован"
        )

    def _is_dynamic(self):
        return self.spin_angle_name is not None

    def _rotation_xform(self, default_pivot):
        if self.rotation == 0.0:
            return None
        angle = math.radians(self.rotation)
        c = math.cos(angle)
        s = math.sin(angle)
        px, py = self.pivot if self.pivot is not None else default_pivot
        if isinstance(px, str) or isinstance(py, str):
            raise ValueError(
                f"{self.__class__.__name__}: static rotation с динамическим "
                f"pivot не поддерживается — используйте spin_angle_name"
            )
        edx = px - c * px + s * py
        edy = py - s * px - c * py
        return (c, s, edx, edy)

    def _push_rotation(self, ctx):
        if self._is_dynamic():
            px, py = (self.spin_pivot if self.spin_pivot is not None
                      else self._default_pivot())
            ctx.push_rotation_dynamic_pivot(
                angle_rva=ctx.rva_of(self.spin_angle_name),
                k_rva=ctx.rva_of("_rot_k"),
                cos_rva=ctx.rva_of("_rot_cos"),
                sin_rva=ctx.rva_of("_rot_sin"),
                px=px, py=py,
            )
            return True

        if self.rotation == 0.0:
            return False

        xform = self._rotation_xform(self._default_pivot())
        if xform is None:
            return False
        c, s, edx, edy = xform
        ctx.push_rotation(c, s, edx, edy)
        return True

    def _pop_rotation(self, ctx, token):
        if not token:
            return
        ctx.pop_rotation()

    def _default_pivot(self):
        return (0, 0)

class Point(Shape):
    """Точка — не рисуется, координата."""
    def __init__(self, x, y):
        super().__init__(0.0, None)
        self.x = x
        self.y = y

class Line(Shape):
    """Линия от (x1,y1) до (x2,y2)."""
    def __init__(self, x1, y1, x2, y2, color=0x000000, width=1,
                 rotation=0.0, pivot=None):
        super().__init__(rotation, pivot)
        self.x1, self.y1 = x1, y1
        self.x2, self.y2 = x2, y2
        self.color = _colorref(color)
        self.width = width

    def _default_pivot(self):
        if isinstance(self.x1, str) or isinstance(self.y1, str) \
           or isinstance(self.x2, str) or isinstance(self.y2, str):
            raise ValueError(
                f"Line: динамический pivot не поддерживается"
            )
        return ((self.x1 + self.x2) / 2, (self.y1 + self.y2) / 2)

    def emit(self, ctx):
        token = self._push_rotation(ctx)

        ctx.set_pen(self.color, self.width)

        ctx.mov_reg_rva(1, ctx.target_rva)
        _emit_i32(ctx, 'edx', self.x1)
        _emit_i32(ctx, 'r8d', self.y1)
        ctx.emit(bytes([0x45, 0x31, 0xC9]))  
        ctx.call_iat("MoveToEx")

        ctx.mov_reg_rva(1, ctx.target_rva)
        _emit_i32(ctx, 'edx', self.x2)
        _emit_i32(ctx, 'r8d', self.y2)
        ctx.call_iat("LineTo")

        ctx.restore_pen()

        self._pop_rotation(ctx, token)

class Rect(Shape):
    """Прямоугольник (x, y, w, h)."""
    def __init__(self, x, y, w, h, fill=None, border=0x000000,
                 border_width=1, rotation=0.0, pivot=None):
        super().__init__(rotation, pivot)
        self.x, self.y = x, y
        self.w, self.h = w, h
        self.fill = _colorref(fill)
        self.border = _colorref(border)
        self.border_width = border_width

    def _default_pivot(self):
        if isinstance(self.x, str) or isinstance(self.y, str):
            if isinstance(self.x, str) and isinstance(self.y, str):
                return (self.x, self.y)   
            raise ValueError(
                f"Rect: смешанные static/dynamic координаты"
            )
        return (self.x + self.w / 2, self.y + self.h / 2)

    def _make_region_static(self, ctx, hrgn_rva, offset):
        ox, oy = offset
        ctx.create_rect_region(
            hrgn_rva,
            self.x + ox, self.y + oy,
            self.x + ox + self.w, self.y + oy + self.h,
        )

    def emit_mask(self, ctx):

        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.emit(bytes([0xBA]) + _i32(self.x))
        ctx.emit(bytes([0x41, 0xB8]) + _i32(self.y))
        ctx.emit(bytes([0x41, 0xB9]) + _i32(self.x + self.w))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + _i32(self.y + self.h))
        ctx.call_iat("Rectangle")

    def polygon_points(self, offset=(0, 0)):
        ox, oy = offset
        x, y, w, h = self.x + ox, self.y + oy, self.w, self.h
        return [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]

    def emit(self, ctx):
        token = self._push_rotation(ctx)

        if self.fill is not None:
            ctx.set_brush(self.fill)
        if self.border is not None:
            ctx.set_pen(self.border, self.border_width)

        ctx.mov_reg_rva(1, ctx.target_rva)
        _emit_i32(ctx, 'edx', self.x)  
        _emit_i32(ctx, 'r8d', self.y)  
        _emit_i32(ctx, 'r9d', self.x)  
        _emit_add_i32(ctx, 'r9d', self.w)  
        _emit_i32(ctx, 'eax', self.y)  
        _emit_add_i32(ctx, 'eax', self.h)  
        ctx.emit(bytes([0x89, 0x44, 0x24, 0x20]))  
        ctx.call_iat("Rectangle")

        if self.border is not None:
            ctx.restore_pen()
        if self.fill is not None:
            ctx.restore_brush()

        self._pop_rotation(ctx, token)

class Square(Rect):
    def __init__(self, x, y, size, fill=None, border=0x000000,
                 border_width=1, rotation=0.0, pivot=None):
        super().__init__(x, y, size, size, fill=fill, border=border,
                         border_width=border_width, rotation=rotation,
                         pivot=pivot)

class Ellipse(Shape):
    """Эллипс (cx, cy, rx, ry)."""
    def __init__(self, cx, cy, rx, ry, fill=None, border=0x000000,
                 border_width=1, rotation=0.0, pivot=None):
        super().__init__(rotation, pivot)
        self.cx, self.cy = cx, cy
        self.rx, self.ry = rx, ry
        self.fill = _colorref(fill)
        self.border = _colorref(border)
        self.border_width = border_width

    def _default_pivot(self):
        if isinstance(self.cx, str) or isinstance(self.cy, str):
            if isinstance(self.cx, str) and isinstance(self.cy, str):
                return (self.cx, self.cy)
            raise ValueError(f"Ellipse: смешанные static/dynamic")
        return (self.cx, self.cy)

    def _make_region_static(self, ctx, hrgn_rva, offset):
        ox, oy = offset
        ctx.create_ellipse_region(
            hrgn_rva,
            self.cx - self.rx + ox, self.cy - self.ry + oy,
            self.cx + self.rx + ox, self.cy + self.ry + oy,
        )

    def emit_mask(self, ctx):
        left = self.cx - self.rx
        top = self.cy - self.ry
        right = self.cx + self.rx
        bottom = self.cy + self.ry
        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.emit(bytes([0xBA]) + _i32(left))
        ctx.emit(bytes([0x41, 0xB8]) + _i32(top))
        ctx.emit(bytes([0x41, 0xB9]) + _i32(right))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + _i32(bottom))
        ctx.call_iat("Ellipse")

    def polygon_points(self, offset=(0, 0), segments=64):
        ox, oy = offset
        cx, cy = self.cx + ox, self.cy + oy
        pts = []
        for i in range(segments):
            a = 2.0 * math.pi * i / segments
            pts.append((
                int(round(cx + self.rx * math.cos(a))),
                int(round(cy + self.ry * math.sin(a))),
            ))
        return pts

    def emit(self, ctx):
        token = self._push_rotation(ctx)

        if self.fill is not None:
            ctx.set_brush(self.fill)
        if self.border is not None:
            ctx.set_pen(self.border, self.border_width)

        _emit_i32(ctx, 'edx', self.cx)
        _emit_sub_i32(ctx, 'edx', self.rx)

        _emit_i32(ctx, 'r8d', self.cy)
        _emit_sub_i32(ctx, 'r8d', self.ry)

        _emit_i32(ctx, 'r9d', self.cx)
        _emit_add_i32(ctx, 'r9d', self.rx)

        _emit_i32(ctx, 'eax', self.cy)
        _emit_add_i32(ctx, 'eax', self.ry)
        ctx.emit(bytes([0x89, 0x44, 0x24, 0x20]))

        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.call_iat("Ellipse")

        if self.border is not None:
            ctx.restore_pen()
        if self.fill is not None:
            ctx.restore_brush()

        self._pop_rotation(ctx, token)

class Circle(Ellipse):
    def __init__(self, cx, cy, r, fill=None, border=0x000000,
                 border_width=1, rotation=0.0, pivot=None):
        super().__init__(cx, cy, r, r, fill=fill, border=border,
                         border_width=border_width, rotation=rotation,
                         pivot=pivot)

class Polygon(Shape):
    """Многоугольник по списку точек [(x1,y1), ...].

    POINT-массив кладётся в .data, имя слота — self.data_name.
    build_gdi регистрирует слот через data_alloc_points.
    """
    def __init__(self, points, fill=None, border=0x000000,
                 border_width=1, rotation=0.0, pivot=None,
                 data_name=None):
        super().__init__(rotation, pivot)
        if len(points) < 3:
            raise ValueError("Polygon: минимум 3 точки")
        self.points = list(points)
        self.fill = _colorref(fill)
        self.border = _colorref(border)
        self.border_width = border_width

        self.data_name = data_name or ("_poly_" + str(id(self) & 0xFFFF))

    def _default_pivot(self):
        xs = [p[0] for p in self.points]
        ys = [p[1] for p in self.points]
        return (sum(xs) / len(xs), sum(ys) / len(ys))

    def emit_mask(self, ctx):
        pts_rva = ctx.rva_of(self.data_name)
        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.lea_rip(2, pts_rva)
        ctx.emit(bytes([0x41, 0xB8]) + _i32(len(self.points)))
        ctx.call_iat("Polygon")

    def _make_region_static(self, ctx, hrgn_rva, offset):
        pts_name = self.data_name + "_off"
        ctx.create_polygon_region(hrgn_rva,
                                  ctx.rva_of(pts_name),
                                  len(self.points))

    def polygon_points(self, offset=(0, 0)):
        ox, oy = offset
        return [(px + ox, py + oy) for px, py in self.points]

    def emit(self, ctx):
        token = self._push_rotation(ctx)

        if self.fill is not None:
            ctx.set_brush(self.fill)
        if self.border is not None:
            ctx.set_pen(self.border, self.border_width)

        pts_rva = ctx.rva_of(self.data_name)
        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.lea_rip(2, pts_rva)
        ctx.emit(bytes([0x41, 0xB8]) + _i32(len(self.points)))
        ctx.call_iat("Polygon")

        if self.border is not None:
            ctx.restore_pen()
        if self.fill is not None:
            ctx.restore_brush()

        self._pop_rotation(ctx, token)

class Image(Shape):
    def __init__(self, x, y, source, shape, w=None, h=None,
                 embed=True, rotation=0.0, pivot=None,
                 spin_angle_name=None, spin_pivot=None):
        super().__init__(rotation, pivot,
                         spin_angle_name=spin_angle_name,
                         spin_pivot=spin_pivot)
        self.x, self.y = x, y
        self.source = source
        self.shape = shape
        self.w = w or 0
        self.h = h or 0
        self.embed = embed
        self.res_id = None

        uid = str(id(self) & 0xFFFF)
        self.uid = uid
        self.himg_key = "_img_himg_" + uid
        self.hsrc_dc_key = "_img_src_dc_" + uid
        self.hsrc_bmp_old_key = "_img_src_old_" + uid
        self.img_w_key = "_img_w_" + uid
        self.img_h_key = "_img_h_" + uid

    def _default_pivot(self):
        return (self.x + self.w / 2, self.y + self.h / 2)

    def emit(self, ctx):
        if self.embed and self.res_id is not None:
            ctx.image_load_dib_from_resource(
                self.res_id, self.himg_key,
                hdc_rva=ctx.hdc_rva,
                img_w_key=self.img_w_key,
                img_h_key=self.img_h_key,
            )

        uid = self.uid
        mask_dc_key = "_img_mask_dc_" + uid
        mask_bmp_key = "_img_mask_bmp_" + uid
        mask_old_key = "_img_mask_old_" + uid
        mask_inv_dc_key = "_img_mask_inv_dc_" + uid
        mask_inv_bmp_key = "_img_mask_inv_bmp_" + uid
        mask_inv_old_key = "_img_mask_inv_old_" + uid
        spr_dc_key = "_img_spr_dc_" + uid
        spr_bmp_key = "_img_spr_bmp_" + uid
        spr_old_key = "_img_spr_old_" + uid

        ctx.image_build_sprite(
            self.shape, self.w, self.h, self.himg_key,
            mask_dc_key, mask_bmp_key, mask_old_key,
            mask_inv_dc_key, mask_inv_bmp_key, mask_inv_old_key,
            spr_dc_key, spr_bmp_key, spr_old_key,
        )

        has_rotation = (self.rotation != 0.0) or self._is_dynamic()
        if has_rotation:
            token = self._push_rotation(ctx)
            ctx.image_draw_sprite(
                spr_dc_key, mask_inv_dc_key,  
                self.w, self.h,
                self.x, self.y, self.w, self.h,
            )
            self._pop_rotation(ctx, token)
        else:
            ctx.image_draw_sprite(
                spr_dc_key, mask_inv_dc_key,
                self.w, self.h,
                self.x, self.y, self.w, self.h,
            )

class Text(Shape):
    """Текст (x, y).

    Два режима:
      1. Статичная строка:  Text(x, y, "hello")
      2. Динамический счёт:  Text(x, y, fmt_name="fmt_d",
                                  value_name="score_p")
         → на каждом кадре: wsprintfA(buf, fmt, [value])
         → TextOutA(hdc, x, y, buf, len)

    x, y: int (imm) или str (имя слота в .data).
    """
    def __init__(self, x, y, text=None, color=0x000000, size=14,
                 weight=400, italic=False, underline=False,
                 face="Arial", rotation=0.0, pivot=None,
                 fmt_name=None, value_name=None, buf_name=None):
        super().__init__(rotation, pivot)
        if text is None and fmt_name is None:
            raise ValueError("Text: нужен text или fmt_name")
        self.x, self.y = x, y
        self.text = text
        self.color = _colorref(color)
        self.size = size
        self.weight = weight
        self.italic = italic
        self.underline = underline
        self.face = face

        self.fmt_name = fmt_name
        self.value_name = value_name
        self.buf_name = buf_name or ("_text_buf_" + str(id(self) & 0xFFFF))

    def _default_pivot(self):
        if isinstance(self.x, str) or isinstance(self.y, str):
            raise ValueError(f"Text: динамический pivot не поддерживается")
        return (self.x, self.y)

    def _ensure_data_slots(self):
        """Регистрация слотов в .data для динамического режима."""
        from .data import data_alloc, DATA_ALLOC
        if self.fmt_name is not None:
            if self.buf_name not in DATA_ALLOC:
                data_alloc(self.buf_name, 128, 0, type="bytes")

    def emit(self, ctx):
        self._ensure_data_slots()

        token = self._push_rotation(ctx)

        if self.fmt_name is not None:
            ctx.lea_rip(1, ctx.rva_of(self.buf_name))
            ctx.lea_rip(2, ctx.string_rvas[self.fmt_name])
            ctx.mov_r8d_mem(self.value_name)
            ctx.emit(bytes([0x31, 0xC0]))
            ctx.call_iat("wsprintfA")

            ctx.store_eax_mem("_dyn_text_len")
            text_rva = ctx.rva_of(self.buf_name)
            text_len_rva = ctx.rva_of("_dyn_text_len")
        else:
            text_rva = ctx.string_rvas["_text_" + self.text]
            text_len_rva = None

        ctx.emit(bytes([0x48, 0x83, 0xEC, 0x60]))
        ctx.emit(bytes([0xB9]) + _i32(self.size))
        ctx.emit(bytes([0x31, 0xD2]))
        ctx.emit(bytes([0x45, 0x31, 0xC0]))
        ctx.emit(bytes([0x45, 0x31, 0xC9]))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x20]) + _i32(self.weight))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x28])
                 + _i32(1 if self.italic else 0))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x30])
                 + _i32(1 if self.underline else 0))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x38]) + _i32(0))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x40]) + _i32(1))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x48]) + _i32(0))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x50]) + _i32(0))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x58]) + _i32(0))
        ctx.emit(bytes([0xC7, 0x44, 0x24, 0x60]) + _i32(0))
        ctx.lea_rip(0, ctx.string_rvas["_face_" + self.face])
        ctx.emit(bytes([0x48, 0x89, 0x44, 0x24, 0x68]))
        ctx.call_iat("CreateFontA")
        ctx.emit(bytes([0x48, 0x83, 0xC4, 0x60]))
        ctx.store_rax_rva(ctx.hfont_rva)

        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.mov_reg_rva(2, ctx.hfont_rva)
        ctx.call_iat("SelectObject")
        ctx.store_rax_rva(ctx.hfont_old_rva)

        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.emit(bytes([0xBA]) + _i32(self.color))
        ctx.call_iat("SetTextColor")

        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.emit(bytes([0xBA]) + _i32(1))
        ctx.call_iat("SetBkMode")

        ctx.mov_reg_rva(1, ctx.target_rva)
        _emit_i32(ctx, 'edx', self.x)         
        _emit_i32(ctx, 'r8d', self.y)         
        ctx.lea_rip(9, text_rva)
        if text_len_rva is not None:
            ctx.mov_eax_rva(text_len_rva)
            ctx.emit(bytes([0x89, 0x44, 0x24, 0x20]))
        else:
            ctx.emit(bytes([0xC7, 0x44, 0x24, 0x20])
                     + _i32(len(self.text.encode("ascii"))))
        ctx.call_iat("TextOutA")

        ctx.mov_reg_rva(1, ctx.target_rva)
        ctx.mov_reg_rva(2, ctx.hfont_old_rva)
        ctx.call_iat("SelectObject")

        ctx.mov_reg_rva(1, ctx.hfont_rva)
        ctx.call_iat("DeleteObject")

        self._pop_rotation(ctx, token)
