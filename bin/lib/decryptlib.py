import tokenize
import base64
import binascii
import itertools
import string
import sys

g_record = None  # dict record set by calling function
g_register = {}

PY2 = sys.version_info[0] == 2

if PY2:
    import StringIO
    from HTMLParser import HTMLParser
    html_unescape = HTMLParser().unescape
    def html_escape(s): raise Exception("Not implemented for Python 2")
else:
    import io as StringIO
    from html import escape as html_escape, unescape as html_unescape


class Tokenizer(object):
    def __init__(self, data):
        self.chain = [t for t in tokenize.generate_tokens(StringIO.StringIO(data).readline)]
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
                raise Exception('%s() takes exactly %d arguments, %d given' % (func.__name__[3:], argcount, len(args)))
        return func_wrapper
    return numargs_decorator

@numargs(0)
def FN_ascii(data, args):
    data = data.decode('ascii', 'replace') if type(data) == bytes else data
    return "".join(c if c in string.printable[:-5] else "." for c in data)

@numargs(1)
def FN_emit(data, args):
    global g_record
    field, = args
    emit = data.decode("utf-8", "replace") if type(data) == bytes else data
    g_record[field] = emit
    return data

@numargs(1)
def FN_decode(data, args):
    codec, = args
    try:
        data = data.decode(codec, 'replace') if isinstance(data, bytes) else data
    except LookupError:
        raise Exception("the codec '%s' is not valid" % codec)
    return data

@numargs(0)
def FN_escape(data, args):
    data = data if isinstance(data, bytes) else data.encode("utf8", errors="ignore")
    data = "".join(data.replace(b"\\", b"\\\\").decode("ascii", errors="backslashreplace"))
    tr = {0x00: u'\\x00', 0x01: u'\\x01', 0x02: u'\\x02', 0x03: u'\\x03',
          0x04: u'\\x04', 0x05: u'\\x05', 0x06: u'\\x06', 0x07: u'\\x07',
          0x08: u'\\x08', 0x09: u'\\x09', 0x0a: u'\\x0a', 0x0b: u'\\x0b', 
          0x0c: u'\\x0c', 0x0d: u'\\x0d', 0x0e: u'\\x0e', 0x0f: u'\\x0f', 
          0x10: u'\\x10', 0x11: u'\\x11', 0x12: u'\\x12', 0x13: u'\\x13', 
          0x14: u'\\x14', 0x15: u'\\x15', 0x16: u'\\x16', 0x17: u'\\x17', 
          0x18: u'\\x18', 0x19: u'\\x19', 0x1a: u'\\x1a', 0x1b: u'\\x1b',
          0x1c: u'\\x1c', 0x1d: u'\\x1d', 0x1e: u'\\x1e', 0x1f: u'\\x1f',
          0x7f: u'\\x7f'}
    return data.translate(tr)

@numargs(0)
def FN_unescape(data, args):
    data = data if isinstance(data, bytes) else data.encode("latin1", errors="ignore")
    data = data.decode("unicode_escape", errors="ignore")
    try:
        return data.encode("latin1")
    except UnicodeEncodeError:
        return data

@numargs(0)
def FN_htmlescape(data, args):
    data = data.decode("utf-8", "ignore") if type(data) == bytes else data
    return html_escape(data)

@numargs(0)
def FN_htmlunescape(data, args):
    data = data.decode("utf-8", "ignore") if type(data) == bytes else data
    return html_unescape(data)

@numargs(0)
def FN_hex(data, args):
    if PY2:
        return binascii.hexlify(data)
    return binascii.hexlify(data.encode() if type(data) == str else data).decode("ascii")

@numargs(0)
def FN_unhex(data, args):
    return binascii.unhexlify(data)

@numargs(1)
def FN_rotx(data, args):
    count, = args

    if type(data) != str:
        raise Exception("rotx(): ROT only supports alphabetical characters A-Z")

    left = 'abcdefghijklmnopqrstuvwxyz'
    right = left[count:] + left[:count]
    def translate(c):
        i = left.find(c)
        return c if i < 0 else right[i]
    res = []
    for c in data:
        c = translate(c.lower()).upper() if c.isupper() else translate(c)
        res.append(c)
    return ''.join(res)

@numargs(1)
def FN_ror(data, args):
    count, = args
    fn = lambda c, shift: (c >> shift % 8) & (2**8 - 1) | ((c & (2**8 - 1)) << (8 - (shift % 8))) & 0xff
    res = bytearray()
    data = [ord(c) for c in data] if type(data) == str else data
    for c in data:
        res.append(fn(c, count))
    return bytes(res)

@numargs(1)
def FN_rol(data, args):
    count, = args
    fn = lambda c, shift: (c << shift % 8) & (2**8 - 1) | ((c & (2**8 - 1)) >> (8 - (shift % 8)))
    res = bytearray()
    data = [ord(c) for c in data] if type(data) == str else data
    for c in data:
        res.append(fn(c, count))

    return bytes(res)

@numargs(0)
def FN_btoa(data, args):
    if PY2:
        return base64.b64encode(data)
    return base64.b64encode(data.encode() if type(data) == str else data).decode("ascii")

@numargs(0)
def FN_atob(data, args):
    data = data.encode() if type(data) == str else data
    return base64.b64decode(data + '===='.encode())  # b64decode ignores extra padding

@numargs(0)
def FN_b32(data, args):
    padding = "=" * (8 - (len(data) % 8)) if len(data) % 8 != 0 else ""
    data = data.encode() if type(data) == str else data
    return base64.b32decode(data + padding.encode())

@numargs(1)
def FN_save(data, args):
    global g_register
    var, = args
    g_register[var] = data
    return data

@numargs(1)
def FN_load(data, args):
    global g_register
    var, = args
    if var not in g_register:
        raise Exception("load(): the variable '%s' could not be loaded" % var)
    return g_register[var]

@numargs(2)
def FN_substr(data, args):
    start, count = args
    if type(start) == int and type(count) == int:
        if start <= 0:
            start = max(len(data) + start, 0)
        end = start + count
        if start > len(data):
            raise Exception("substr(): start offset exceeds length of data")
        return data[start:end]
    else:
        raise Exception("substr(): ranges must be integers")

@numargs(0)
def FN_rev(data, args):
    return data[::-1]

@numargs(1)
def FN_xor(data, args):
    key, = args
    if PY2 and isinstance(key, unicode):
        key = str(key)

    key = [key] if isinstance(key, int) else [ord(c) for c in key]
    for key_int in key:
        if key_int > 255:
            raise Exception("xor(): does not accept integers greater than 255 or unicode as a key")

    data = [ord(c) for c in data] if type(data) == str else data
    res = bytearray((((d ^ k) & 0xff) for d, k in zip(data, itertools.cycle(key))))
    return bytes(res)

@numargs(1)
def FN_rc4(data, args):
    key, = args

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
def FN_tr(data, args):
    trans_from, trans_to = args
    if PY2:
        data = data if isinstance(data, str) else data.encode('utf8')
        trans_chars = string.maketrans(trans_from, trans_to)
    else:
        if isinstance(data, bytes):
            trans_from = trans_from if isinstance(trans_from, bytes) else trans_from.encode('utf8')
            trans_to = trans_to if isinstance(trans_to, bytes) else trans_to.encode('utf8')
            trans_chars = bytes.maketrans(trans_from, trans_to)
        else:
            trans_from = trans_from.decode('utf8') if isinstance(trans_from, bytes) else trans_from
            trans_to = trans_to.decode('utf8') if isinstance(trans_to, bytes) else trans_to
            trans_chars = str.maketrans(trans_from, trans_to)
    return data.translate(trans_chars)

@numargs(2)
def FN_find(data, args):
    sub, start = args
    if not isinstance(start, int):
        raise Exception('find(): start must be integer')
    if isinstance(sub, int) and sub not in range(256):
        raise Exception('find(): subsequence must be integer between 0 and 255')
    if isinstance(sub, (int, bytes)):
        data = data if isinstance(data, bytes) else data.encode('utf8', errors='ignore')
        return data.find(sub, start)
    else:
        data = data if isinstance(data, str) else data.decode('utf8', errors='ignore')
        return data.find(sub, start)

def getargs(g):
    global g_record
    global g_register

    args = ()
    toknum, tokval, _, _, _ = g.next()

    if toknum in [tokenize.NAME, tokenize.ENDMARKER]:
        g.prev()
        return args

    if toknum == tokenize.NEWLINE:
        return args

    if tokval != "(":
        raise Exception("syntax error")

    while True:
        toknum, tokval = g.next()[0:2]

        if tokval == ")":
            break

        if tokval == ",":
            continue

        if toknum == tokenize.STRING:
            tokval = tokval[1:-1]
            tokval = tokval.encode("latin1").decode("unicode-escape")
            if PY2:
                tokval = tokval.encode("latin1")
        elif toknum == tokenize.NAME:
            if tokval in g_record:
                tokval = g_record[tokval]
            elif tokval in g_register:
                tokval = g_register[tokval]
            else:
                raise Exception("the field and register '%s' does not exist" % tokval)
        elif toknum == tokenize.NUMBER:
            tokval = int(tokval, 0)
        else:
            raise Exception("syntax error")

        args = args + (tokval,)

    return args

def parsestmt(s):
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
            yield FN_atob, getargs(g)

        elif cmd == "btoa":
            yield FN_btoa, getargs(g)

        elif cmd == "hex":
            yield FN_hex, getargs(g)

        elif cmd == "unhex":
            yield FN_unhex, getargs(g)

        elif cmd == "rol":
            yield FN_rol, getargs(g)

        elif cmd == "ror":
            yield FN_ror, getargs(g)

        elif cmd == "rotx":
            yield FN_rotx, getargs(g)

        elif cmd == "xor":
            yield FN_xor, getargs(g)

        elif cmd == "rc4":
            yield FN_rc4, getargs(g)

        elif cmd == "emit":
            yield FN_emit, getargs(g)

        elif cmd == "load":
            yield FN_load, getargs(g)

        elif cmd == "save":
            yield FN_save, getargs(g)

        elif cmd == "substr":
            yield FN_substr, getargs(g)

        elif cmd == "rev":
            yield FN_rev, getargs(g)

        elif cmd == "b32":
            yield FN_b32, getargs(g)

        elif cmd == "ascii":
            yield FN_ascii, getargs(g)

        elif cmd == "decode":
            yield FN_decode, getargs(g)

        elif cmd == "escape":
            yield FN_escape, getargs(g)

        elif cmd == "unescape":
            yield FN_unescape, getargs(g)

        elif cmd == "htmlescape":
            yield FN_htmlescape, getargs(g)

        elif cmd == "htmlunescape":
            yield FN_htmlunescape, getargs(g)

        elif cmd == "tr":
            yield FN_tr, getargs(g)

        elif cmd == "find":
            yield FN_find, getargs(g)

        else:
            raise Exception("'%s' is not a recognized command" % cmd)
