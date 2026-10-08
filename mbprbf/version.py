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

# version.py
"""version.py — версия MBPRBF."""

__version__ = "1.0.0"
__version_tuple__ = (1, 0, 0)

# для PE: MajorLinkerVersion / MinorLinkerVersion — по 1 байту
LINKER_MAJOR = __version_tuple__[0] & 0xFF
LINKER_MINOR = __version_tuple__[1] & 0xFF