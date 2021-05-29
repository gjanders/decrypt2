try:
    import StringIO
except:
    import io as StringIO

import tokenize
import base64
import binascii
import re
import string
import sys

g_record = None
g_register = {}

PY2 = sys.version_info[0] == 2

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
    res = []
    data = [ord(c) for c in data] if type(data) == str else data
    for c in data:
        res.append(fn(c, count))
    if PY2:
        return ''.join([chr(c) for c in res])
    return bytes(res)

@numargs(1)
def FN_rol(data, args):
    count, = args
    fn = lambda c, shift: (c << shift % 8) & (2**8 - 1) | ((c & (2**8 - 1)) >> (8 - (shift % 8)))
    res = []
    data = [ord(c) for c in data] if type(data) == str else data
    for c in data:
        res.append(fn(c, count))
    if PY2:
        return ''.join([chr(c) for c in res])
    return bytes(res)

@numargs(0)
def FN_btoa(data, args):
    if PY2:
        return base64.b64encode(data)
    return base64.b64encode(data.encode() if type(data) == str else data).decode("ascii") 

@numargs(0)
def FN_atob(data, args):
    padding = "=" * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ""
    data = data.encode() if type(data) == str else data
    return base64.b64decode(data + padding.encode())

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
        end = start + count
        if start > len(data):
            raise Exception("substr(): start offset exceeds length of data")
        if end > len(data):
            end = len(data) - start + 1
        return data[start:end]
    else:
        raise Exception("substr(): ranges must be integers")

@numargs(1)
def FN_xor(data, args):
    key, = args
    if PY2:
        if type(key) == unicode:
            key = str(key)
    
    if type(key) != int:
        if len(key) < len(data):
            key = key * (int(len(data) / len(key)) + 1)
        key = key[:len(data)]
        key = [ord(c) for c in key] if type(key) == str else key
        #fn = lambda a, b: ''.join([chr(ord(d) ^ ord(k)) for d, k in zip(a, b)])
    else:
        key = [key] * len(data)
        #fn = lambda a, b: ''.join([chr((ord(d) ^ k) & 0xff) for d, k in zip(a, b)])

    data = [ord(c) for c in data] if type(data) == str else data
    res = [((d ^ k) & 0xff) for d, k in zip(data, key)]

    if PY2:
        return ''.join([chr(c) for c in res])
   
    return bytes(res) 

@numargs(1)
def FN_rc4(data, args):
    key, = args

    data = [ord(c) for c in data] if type(data) == str else data

    if type(key) == int:
        raise Exception("rc4(): does not accept an integer as a key")

    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i] , S[j] = S[j] , S[i]

    i = j = 0
    res = []

    for c in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i] , S[j] = S[j] , S[i]
        res.append(c ^ S[(S[i] + S[j]) % 256])

    if PY2:
        return ''.join([chr(c) for c in res])

    return bytes(res)


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
    try:
        g = Tokenizer(s)
    except:
        raise Exception("syntax error") 
    for toknum, tokval, _, _, _ in g:
        cmd = None

        if toknum in [tokenize.ENDMARKER, tokenize.NEWLINE]:
            break

        if toknum == tokenize.NAME and cmd == None:
            cmd = tokval
        else:
            raise Exception("syntax error")

        if cmd in ["atob","b64"]:
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

        elif cmd == "b32":
            yield FN_b32, getargs(g)

        elif cmd == "ascii":
            yield FN_ascii, getargs(g)

        else:
            raise Exception("'%s' is not a recognized command" % cmd)

