# version.py
"""version.py — версия MBPRBF."""

__version__ = "1.0.0"
__version_tuple__ = (1, 0, 0)

# для PE: MajorLinkerVersion / MinorLinkerVersion — по 1 байту
LINKER_MAJOR = __version_tuple__[0] & 0xFF
LINKER_MINOR = __version_tuple__[1] & 0xFF