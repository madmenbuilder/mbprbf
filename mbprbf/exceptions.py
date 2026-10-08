#!/usr/bin/env python3
class ProgramException(Exception):
    pass

class MemoryException(ProgramException):
    pass

class OutOfBoundsException(ProgramException):
    pass