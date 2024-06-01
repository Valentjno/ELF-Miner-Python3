import sys
PY3 = sys.version_info[0] == 3

if PY3:
    import io
    StringIO = io.StringIO
    BytesIO = io.BytesIO

    def bytes2str(b): return b.decode('latin-1')
    def str2bytes(s): return s.encode('latin-1')
    def int2byte(i): return bytes((i,))
    def byte2int(b): return b

    def iterbytes(b):
        """Return an iterator over the elements of a bytes object.

        For example, for b'abc' yields b'a', b'b' and then b'c'.
        """
        for i in range(len(b)):
            yield b[i:i+1]

    ifilter = filter

    maxint = sys.maxsize
else:
    import io
    StringIO = io.BytesIO
    BytesIO = io.BytesIO

    def bytes2str(b): return b
    def str2bytes(s): return s
    int2byte = chr
    byte2int = ord

    def iterbytes(b):
        return iter(b)

    from itertools import filterfalse

    ifilter = filterfalse

    maxint = sys.maxsize

def iterkeys(d):
    """Return an iterator over the keys of a dictionary."""
    return getattr(d, 'keys' if PY3 else 'iterkeys')()

def itervalues(d):
    """Return an iterator over the values of a dictionary."""
    return getattr(d, 'values' if PY3 else 'itervalues')()

def iteritems(d):
    """Return an iterator over the items of a dictionary."""
    return getattr(d, 'items' if PY3 else 'iteritems')()
