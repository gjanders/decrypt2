#!/usr/bin/env python
# coding=utf-8

import ast
import base64
import binascii
import itertools
import string
import tokenize
import zlib
from html import escape as html_escape, unescape as html_unescape
from io import StringIO

g_record: dict = {}  # dict record set by calling function
g_register = {}


class Tokenizer(object):
    def __init__(self, data):
        self.chain = [t for t in tokenize.generate_tokens(StringIO(data).readline)]
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        try:
            res = self.chain[self.index]
            self.index += 1
        except IndexError:
            raise StopIteration
        return res

    def prev(self):
        self.index -= 1
        if self.index < 0:
            raise StopIteration
        return self.chain[self.index]


def numargs(argcount):
    def numargs_decorator(func):
        def func_wrapper(data, args):
            if len(args) == argcount:
                return func(data, args)
            else:
                func_name = func.__name__[3:]
                raise Exception(f"{func_name}() takes exactly {argcount} arguments, {len(args)} given")

        return func_wrapper

    return numargs_decorator


def coerce_to_int(input_parameter, calling_func, accept_null=True):
    if accept_null and isinstance(input_parameter, str):
        if input_parameter.lower() in ("null", "none", "undefined", ""):
            return None

    try:
        return int(input_parameter)
    except:
        or_null_option = " or 'null'" if accept_null else ""
        raise Exception(f"{calling_func}() parameter must be integer {or_null_option}")


@numargs(0)
def fn_ascii(data, args):
    data = data.decode("ascii", "replace") if type(data) == bytes else data
    return "".join(c if c in string.printable[:-5] else "." for c in data)


@numargs(1)
def fn_emit(data, args):
    global g_record
    (field,) = args
    emit = data.decode("utf-8", "replace") if type(data) == bytes else data
    g_record[field] = emit
    return data


@numargs(1)
def fn_decode(data, args):
    (codec,) = args
    if isinstance(data, str):
        data = str.encode(data)    
    try:
        data = data.decode(codec, "replace") #if isinstance(data, bytes) else data
    except LookupError:
        raise Exception(f"the codec '{codec}' is not valid")
    return data

@numargs(1)
def fn_literal_decode(data, args):
    (codec,) = args
    try:
        data_literal = ast.literal_eval("b'"+data+"'")
        data_decoded = data_literal.decode(codec)
    except LookupError:
        raise Exception(f"the codec '{codec}' is not valid")
    return data_decoded

@numargs(0)
def fn_escape(data, args):
    data = data if isinstance(data, bytes) else data.encode("utf8", errors="ignore")
    data = "".join(data.replace(b"\\", b"\\\\").decode("ascii", errors="backslashreplace"))
    tr = {
        0x00: "\\x00",
        0x01: "\\x01",
        0x02: "\\x02",
        0x03: "\\x03",
        0x04: "\\x04",
        0x05: "\\x05",
        0x06: "\\x06",
        0x07: "\\x07",
        0x08: "\\x08",
        0x09: "\\x09",
        0x0A: "\\x0a",
        0x0B: "\\x0b",
        0x0C: "\\x0c",
        0x0D: "\\x0d",
        0x0E: "\\x0e",
        0x0F: "\\x0f",
        0x10: "\\x10",
        0x11: "\\x11",
        0x12: "\\x12",
        0x13: "\\x13",
        0x14: "\\x14",
        0x15: "\\x15",
        0x16: "\\x16",
        0x17: "\\x17",
        0x18: "\\x18",
        0x19: "\\x19",
        0x1A: "\\x1a",
        0x1B: "\\x1b",
        0x1C: "\\x1c",
        0x1D: "\\x1d",
        0x1E: "\\x1e",
        0x1F: "\\x1f",
        0x7F: "\\x7f",
    }
    return data.translate(tr)


@numargs(0)
def fn_unescape(data, args):
    data = data if isinstance(data, bytes) else data.encode("latin1", errors="ignore")
    data = data.decode("unicode_escape", errors="ignore")
    try:
        return data.encode("latin1")
    except UnicodeEncodeError:
        return data


@numargs(0)
def fn_htmlescape(data, args):
    data = data.decode("utf-8", "ignore") if type(data) == bytes else data
    return html_escape(data)


@numargs(0)
def fn_htmlunescape(data, args):
    data = data.decode("utf-8", "ignore") if type(data) == bytes else data
    return html_unescape(data)


@numargs(0)
def fn_hex(data, args):
    return binascii.hexlify(data.encode() if type(data) == str else data).decode("ascii")


@numargs(0)
def fn_unhex(data, args):
    return binascii.unhexlify(data)


@numargs(1)
def fn_rotx(data, args):
    (count,) = args
    count = coerce_to_int(count, "rotx", accept_null=False)

    if type(data) != str:
        raise Exception("rotx(): ROT only supports alphabetical characters A-Z")

    left = "abcdefghijklmnopqrstuvwxyz"
    right = left[count:] + left[:count]

    def translate(c):
        i = left.find(c)
        return c if i < 0 else right[i]

    res = []
    for c in data:
        c = translate(c.lower()).upper() if c.isupper() else translate(c)
        res.append(c)
    return "".join(res)


@numargs(1)
def fn_ror(data, args):
    (count,) = args
    count = coerce_to_int(count, "ror", accept_null=False)
    data = [ord(c) for c in data] if type(data) == str else data
    return bytes([_rotate_right(c, count) for c in data])


def _rotate_right(c, shift):
    return (c >> shift % 8) & (2**8 - 1) | ((c & (2**8 - 1)) << (8 - (shift % 8))) & 0xFF


@numargs(1)
def fn_rol(data, args):
    (count,) = args
    count = coerce_to_int(count, "rol", accept_null=False)
    data = [ord(c) for c in data] if type(data) == str else data
    return bytes([_rotate_left(c, count) for c in data])


def _rotate_left(c, shift):
    return (c << shift % 8) & (2**8 - 1) | ((c & (2**8 - 1)) >> (8 - (shift % 8)))


@numargs(0)
def fn_btoa(data, args):
    return base64.b64encode(data.encode() if type(data) == str else data).decode("ascii")


@numargs(0)
def fn_atob(data, args):
    data = data.encode() if type(data) == str else data
    return base64.b64decode(data + "====".encode())  # b64decode ignores extra padding


@numargs(0)
def fn_b32(data, args):
    padding = "=" * (8 - (len(data) % 8)) if len(data) % 8 != 0 else ""
    data = data.encode() if type(data) == str else data
    return base64.b32decode(data + padding.encode())


@numargs(1)
def fn_save(data, args):
    global g_register
    (var,) = args
    g_register[var] = data
    return data


@numargs(1)
def fn_load(data, args):
    global g_register
    (var,) = args
    if var not in g_register:
        raise Exception(f"load(): the variable '{var}' could not be loaded")
    return g_register[var]


@numargs(2)
def fn_substr(data, args):
    start, count = args
    start = coerce_to_int(start, "substr", accept_null=False)
    count = coerce_to_int(count, "substr", accept_null=True)
    if start < 0:
        start = max(len(data) + start, 0)
    if count is None:
        end = None
    elif count < 0:
        end = count
    else:
        end = start + count
    if start > len(data):
        raise Exception("substr(): start offset exceeds length of data")
    return data[start:end]


@numargs(2)
def fn_slice(data, args):
    start, end = args
    start = coerce_to_int(start, "slice", accept_null=True)
    end = coerce_to_int(end, "slice", accept_null=True)
    if isinstance(end, str) and end.lower() in ("null", "none", "undefined", ""):
        end = None
    if isinstance(start, int) and isinstance(end, int) or end is None:
        return data[start:end]
    else:
        raise Exception("slice(): start and end must be integers or 'null'")


@numargs(0)
def fn_rev(data, args):
    return data[::-1]


@numargs(1)
def fn_xor(data, args):
    (key,) = args

    key = [key] if isinstance(key, int) else [ord(c) for c in key]
    for key_int in key:
        if key_int < 0 or key_int > 255:
            raise Exception("xor(): does not accept integers greater than 255 or unicode as a key")

    data = [ord(c) for c in data] if type(data) == str else data
    res = bytearray((((d ^ k) & 0xFF) for d, k in zip(data, itertools.cycle(key))))
    return bytes(res)


@numargs(1)
def fn_rc4(data, args):
    (key,) = args

    data = [ord(c) for c in data] if type(data) == str else data

    if isinstance(key, int):
        raise Exception("rc4(): does not accept an integer as a key")

    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    res = bytearray()

    for c in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        res.append(c ^ S[(S[i] + S[j]) % 256])

    return bytes(res)


@numargs(2)
def fn_tr(data, args):
    trans_from, trans_to = args
    if isinstance(data, bytes):
        trans_from = trans_from if isinstance(trans_from, bytes) else trans_from.encode("utf8")
        trans_to = trans_to if isinstance(trans_to, bytes) else trans_to.encode("utf8")
        trans_chars = bytes.maketrans(trans_from, trans_to)
    else:
        trans_from = trans_from.decode("utf8") if isinstance(trans_from, bytes) else trans_from
        trans_to = trans_to.decode("utf8") if isinstance(trans_to, bytes) else trans_to
        trans_chars = str.maketrans(trans_from, trans_to)
    return data.translate(trans_chars)


@numargs(2)
def fn_find(data, args):
    sub, start = args
    start = coerce_to_int(start, "find", accept_null=True)
    if isinstance(sub, (int, bytes)):
        data = data if isinstance(data, bytes) else data.encode("utf8", errors="ignore")
        return data.find(sub, start)
    else:
        data = data if isinstance(data, str) else data.decode("utf8", errors="ignore")
        return data.find(sub, start)


@numargs(0)
def fn_b32re(data, args):
    data = data.encode() if type(data) == str else data
    return _reverse_endian_decode(data, 5)


@numargs(0)
def fn_b64re(data, args):
    data = data.encode() if type(data) == str else data
    return _reverse_endian_decode(data, 6)


def _reverse_endian_decode(data, bit_width):
    # Reverse endian decoding like SunBurst DGA
    base_dict = {
        5: {k: i for i, k in enumerate(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")},
        6: {k: i for i, k in enumerate(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")},
    }
    decode_dict = base_dict[bit_width]
    bit_stack = 0
    bits_on_stack = 0
    ret_bytes = bytearray()
    for char in data:
        if char not in decode_dict:
            continue
        bit_stack |= decode_dict[char] << bits_on_stack
        bits_on_stack += bit_width
        if bits_on_stack >= 8:
            ret_bytes.append(bit_stack & 0xFF)
            bit_stack >>= 8
            bits_on_stack -= 8
    if bits_on_stack > 0:
        bit_stack <<= 8 - bits_on_stack
        ret_bytes.append(bit_stack & 0xFF)
    return bytes(ret_bytes)


@numargs(0)
def fn_b58(data, args):
    data = data.encode() if type(data) == str else data
    return _base58_decode(data)


def _base58_decode(data, slice_len=2**8, max_len=2**15):
    b58_alpha = bytearray(b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    data_clean = bytearray([b for b in data if b in b58_alpha])
    data_len = len(data_clean)
    if max_len and data_len > max_len:
        raise Exception(f"base58 error: Input data length over soft limit of {max_len}")
    leading_null_count = 0
    for leading_null_count, clean_val in enumerate(data_clean):
        if clean_val != b58_alpha[0]:
            break
    return_int = 0
    b58_factors = [58**x for x in range(slice_len + 1)]
    b58_dict = {v: i for i, v in enumerate(b58_alpha)}
    while data_clean:
        slice_total = 0
        if len(data_clean) < slice_len:
            slice_len = len(data_clean)
        for val in data_clean[:slice_len]:
            slice_total = 58 * slice_total + b58_dict[val]
        return_int = return_int * b58_factors[slice_len] + slice_total
        data_clean = data_clean[slice_len:]
    output_len = int(data_len * 0.7322476243909465)
    return (b"\x00" * leading_null_count) + return_int.to_bytes(output_len << 1, "big").lstrip(b"\x00")


@numargs(1)
def fn_zlib_inflate(data, args):
    (wbits,) = args
    wbits = coerce_to_int(wbits, "zlib_inflate", accept_null=False)
    data = data.encode() if type(data) == str else data
    try:
        return zlib.decompress(data, wbits)
    except zlib.error as exc:
        if not any(
            [
                wbits in range(-15, -7),
                wbits in range(8, 16),
                wbits in range(24, 32),
                wbits in range(40, 48),
            ]
        ):
            raise Exception("zlib_inflate(): invalid wbits value provided")
        raise Exception(f"zlib_inflate(): {exc}")


def get_args(g):
    global g_record
    global g_register

    args = ()
    token_type, token_value, _, _, _ = g.next()
    token_minus = False

    if token_type in [tokenize.NAME, tokenize.ENDMARKER]:
        g.prev()
        return args

    if token_type == tokenize.NEWLINE:
        return args

    if token_value != "(":
        raise Exception("syntax error")

    while True:
        token_type, token_value = g.next()[0:2]

        if token_type == tokenize.OP:
            if token_value == ")":
                break
            if token_value == "-":
                token_minus = True
                continue

        if token_type == tokenize.NUMBER:
            token_value = int(token_value, 0)
            if token_minus:
                token_value = -token_value
        elif token_minus:
            raise Exception(f"Cannot negate '{token_value}' with '-' operator")
        elif token_type == tokenize.STRING:
            token_value = token_value[1:-1]
            token_value = token_value.encode("latin1").decode("unicode-escape")
        elif token_type == tokenize.NAME:
            if token_value in g_record:
                token_value = g_record[token_value]
            elif token_value in g_register:
                token_value = g_register[token_value]
            else:
                raise Exception(f"the field and register '{token_value}' does not exist")
        else:
            raise Exception(f"syntax error parsing {tokenize.tok_name[token_type]} with value: {token_value}")

        token_minus = False
        args = args + (token_value,)

    return args


def parse_statement(s):
    # always emit the decrypted value even if not requested
    if s.find("emit(") == -1:
        s = s + " emit('decrypted') "

    try:
        g = Tokenizer(s)
    except:
        raise Exception("syntax error")

    for toknum, tokval, _, _, _ in g:
        cmd = None

        if toknum in [tokenize.ENDMARKER, tokenize.NEWLINE]:
            break

        if toknum == tokenize.NAME and cmd is None:
            cmd = tokval
        else:
            raise Exception("syntax error")

        if cmd in ("atob", "b64"):
            yield fn_atob, get_args(g)

        elif cmd == "btoa":
            yield fn_btoa, get_args(g)

        elif cmd == "hex":
            yield fn_hex, get_args(g)

        elif cmd == "unhex":
            yield fn_unhex, get_args(g)

        elif cmd == "rol":
            yield fn_rol, get_args(g)

        elif cmd == "ror":
            yield fn_ror, get_args(g)

        elif cmd == "rotx":
            yield fn_rotx, get_args(g)

        elif cmd == "xor":
            yield fn_xor, get_args(g)

        elif cmd == "rc4":
            yield fn_rc4, get_args(g)

        elif cmd == "emit":
            yield fn_emit, get_args(g)

        elif cmd == "load":
            yield fn_load, get_args(g)

        elif cmd == "save":
            yield fn_save, get_args(g)

        elif cmd == "substr":
            yield fn_substr, get_args(g)

        elif cmd == "slice":
            yield fn_slice, get_args(g)

        elif cmd == "rev":
            yield fn_rev, get_args(g)

        elif cmd == "b32":
            yield fn_b32, get_args(g)

        elif cmd == "ascii":
            yield fn_ascii, get_args(g)

        elif cmd == "decode":
            yield fn_decode, get_args(g)

        elif cmd == "litdecode":
            yield fn_literal_decode, get_args(g)

        elif cmd == "escape":
            yield fn_escape, get_args(g)

        elif cmd == "unescape":
            yield fn_unescape, get_args(g)

        elif cmd == "htmlescape":
            yield fn_htmlescape, get_args(g)

        elif cmd == "htmlunescape":
            yield fn_htmlunescape, get_args(g)

        elif cmd == "tr":
            yield fn_tr, get_args(g)

        elif cmd == "find":
            yield fn_find, get_args(g)

        elif cmd == "b32re":
            yield fn_b32re, get_args(g)

        elif cmd == "b64re":
            yield fn_b64re, get_args(g)

        elif cmd == "b58":
            yield fn_b58, get_args(g)

        elif cmd == "zlib_inflate":
            yield fn_zlib_inflate, get_args(g)

        else:
            raise Exception(f"'{cmd}' is not a recognized command")
