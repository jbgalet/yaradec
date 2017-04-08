# Use enum.py from python 3.6
from enum import IntEnum, IntFlag

# Constants extracted from libyara/include/types.h   (github.com/VirusTotal/yara)

UNDEFINED = 0xFFFABADAFABADAFF


def IS_UNDEFINED(X):
    return X == UNDEFINED


_OP_EQ = 0
_OP_NEQ = 1
_OP_LT = 2
_OP_GT = 3
_OP_LE = 4
_OP_GE = 5
_OP_ADD = 6
_OP_SUB = 7
_OP_MUL = 8
_OP_DIV = 9
_OP_MINUS = 10
OP_INT_BEGIN = 100
OP_DBL_BEGIN = 120
OP_STR_BEGIN = 140
OP_READ_INT = 240
OP_INT_END = OP_INT_BEGIN + _OP_MINUS
OP_DBL_END = OP_DBL_BEGIN + _OP_MINUS
OP_STR_END = OP_STR_BEGIN + _OP_GE


class Opcode(IntEnum):
    OP_ERROR = 0
    OP_HALT = 255

    OP_AND = 1
    OP_OR = 2
    OP_NOT = 3
    OP_BITWISE_NOT = 4
    OP_BITWISE_AND = 5
    OP_BITWISE_OR = 6
    OP_BITWISE_XOR = 7
    OP_SHL = 8
    OP_SHR = 9
    OP_MOD = 10
    OP_INT_TO_DBL = 11
    OP_STR_TO_BOOL = 12
    OP_PUSH = 13
    OP_POP = 14
    OP_CALL = 15
    OP_OBJ_LOAD = 16
    OP_OBJ_VALUE = 17
    OP_OBJ_FIELD = 18
    OP_INDEX_ARRAY = 19
    OP_COUNT = 20
    OP_LENGTH = 21
    OP_FOUND = 22
    OP_FOUND_AT = 23
    OP_FOUND_IN = 24
    OP_OFFSET = 25
    OP_OF = 26
    OP_PUSH_RULE = 27
    OP_INIT_RULE = 28
    OP_MATCH_RULE = 29
    OP_INCR_M = 30
    OP_CLEAR_M = 31
    OP_ADD_M = 32
    OP_POP_M = 33
    OP_PUSH_M = 34
    OP_SWAPUNDEF = 35
    OP_JNUNDEF = 36
    OP_JLE = 37
    OP_FILESIZE = 38
    OP_ENTRYPOINT = 39
    OP_CONTAINS = 40
    OP_MATCHES = 41
    OP_IMPORT = 42
    OP_LOOKUP_DICT = 43
    OP_JFALSE = 44
    OP_JTRUE = 45

    OP_INT_EQ = (OP_INT_BEGIN + _OP_EQ)
    OP_INT_NEQ = (OP_INT_BEGIN + _OP_NEQ)
    OP_INT_LT = (OP_INT_BEGIN + _OP_LT)
    OP_INT_GT = (OP_INT_BEGIN + _OP_GT)
    OP_INT_LE = (OP_INT_BEGIN + _OP_LE)
    OP_INT_GE = (OP_INT_BEGIN + _OP_GE)
    OP_INT_ADD = (OP_INT_BEGIN + _OP_ADD)
    OP_INT_SUB = (OP_INT_BEGIN + _OP_SUB)
    OP_INT_MUL = (OP_INT_BEGIN + _OP_MUL)
    OP_INT_DIV = (OP_INT_BEGIN + _OP_DIV)
    OP_INT_MINUS = (OP_INT_BEGIN + _OP_MINUS)

    OP_DBL_EQ = (OP_DBL_BEGIN + _OP_EQ)
    OP_DBL_NEQ = (OP_DBL_BEGIN + _OP_NEQ)
    OP_DBL_LT = (OP_DBL_BEGIN + _OP_LT)
    OP_DBL_GT = (OP_DBL_BEGIN + _OP_GT)
    OP_DBL_LE = (OP_DBL_BEGIN + _OP_LE)
    OP_DBL_GE = (OP_DBL_BEGIN + _OP_GE)
    OP_DBL_ADD = (OP_DBL_BEGIN + _OP_ADD)
    OP_DBL_SUB = (OP_DBL_BEGIN + _OP_SUB)
    OP_DBL_MUL = (OP_DBL_BEGIN + _OP_MUL)
    OP_DBL_DIV = (OP_DBL_BEGIN + _OP_DIV)
    OP_DBL_MINUS = (OP_DBL_BEGIN + _OP_MINUS)

    OP_STR_EQ = (OP_STR_BEGIN + _OP_EQ)
    OP_STR_NEQ = (OP_STR_BEGIN + _OP_NEQ)
    OP_STR_LT = (OP_STR_BEGIN + _OP_LT)
    OP_STR_GT = (OP_STR_BEGIN + _OP_GT)
    OP_STR_LE = (OP_STR_BEGIN + _OP_LE)
    OP_STR_GE = (OP_STR_BEGIN + _OP_GE)

    OP_INT8 = (OP_READ_INT + 0)
    OP_INT16 = (OP_READ_INT + 1)
    OP_INT32 = (OP_READ_INT + 2)
    OP_UINT8 = (OP_READ_INT + 3)
    OP_UINT16 = (OP_READ_INT + 4)
    OP_UINT32 = (OP_READ_INT + 5)
    OP_INT8BE = (OP_READ_INT + 6)
    OP_INT16BE = (OP_READ_INT + 7)
    OP_INT32BE = (OP_READ_INT + 8)
    OP_UINT8BE = (OP_READ_INT + 9)
    OP_UINT16BE = (OP_READ_INT + 10)
    OP_UINT32BE = (OP_READ_INT + 11)


def IS_INT_OP(X):
    return (X) >= Opcode.OP_INT_BEGIN and (X) <= Opcode.OP_INT_END


def IS_DBL_OP(X):
    return (X) >= Opcode.OP_DBL_BEGIN and (X) <= Opcode.OP_DBL_END


def IS_STR_OP(X):
    return (X) >= Opcode.OP_STR_BEGIN and (X) <= Opcode.OP_STR_END


class MetaType(IntEnum):
    NULL = 0
    INTEGER = 1
    STRING = 2
    BOOLEAN = 3


class StrFlag(IntFlag):
    NOFLAG = 0x00
    REFERENCED = 0x01
    HEXADECIMAL = 0x02
    NO_CASE = 0x04
    ASCII = 0x08
    WIDE = 0x10
    REGEXP = 0x20
    FAST_HEX_REGEXP = 0x40
    FULL_WORD = 0x80
    ANONYMOUS = 0x100
    SINGLE_MATCH = 0x200
    LITERAL = 0x400
    FITS_IN_ATOM = 0x800
    NULL = 0x1000
    CHAIN_PART = 0x2000
    CHAIN_TAIL = 0x4000
    FIXED_OFFSET = 0x8000
    GREEDY_REGEXP = 0x10000


class RuleFlag(IntFlag):
    NOFLAG = 0x00
    PRIVATE = 0x01
    GLOBAL = 0x02
    REQUIRE_EXECUTABLE = 0x04
    REQUIRE_FILE = 0x08
    NULL = 0x1000
