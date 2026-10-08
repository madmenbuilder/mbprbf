import ctypes

class FFIStruct(ctypes.Structure):
    """Базовая структура для FFI."""

    @classmethod
    def size(cls):
        return ctypes.sizeof(cls)

    @classmethod
    def field_offsets(cls):
        """Список (name, offset, size, ctype) для всех полей."""
        result = []
        for name, ftype in cls._fields_:
            field = getattr(cls, name)
            result.append((name, field.offset, field.size, ftype))
        return result

    @classmethod
    def is_by_pointer(cls):
        """True, если структура передаётся по указателю.

        По Microsoft x64 ABI: структура передаётся по указателю,
        если её размер >8 байт или если она нерегулярна (3/5/6/7 байт
        из-за упаковки, но ctypes уже сам выравнивает — так что
        достаточно size > 8).
        """
        return ctypes.sizeof(cls) > 8
