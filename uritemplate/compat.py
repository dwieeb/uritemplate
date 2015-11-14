"""

uritemplate.compat
==================

This module contains compatibility for Python 2.

The code pertaining to urllib has been backported from Python 3.5 with minor
changes.

"""

import collections


_ALWAYS_SAFE = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                         b'abcdefghijklmnopqrstuvwxyz'
                         b'0123456789'
                         b'_.-')
_ALWAYS_SAFE_BYTES = bytearray(_ALWAYS_SAFE)
_safe_quoters = {}


class Quoter(collections.defaultdict):
    """A mapping from bytes (in range(0,256)) to strings.
    String values are percent-encoded byte values, unless the key < 128, and
    in the "safe" set (either the specified safe set, or default set).
    """
    # Keeps a cache internally, using defaultdict, for efficiency (lookups
    # of cached keys don't call Python code at all).
    def __init__(self, safe):
        """safe: bytearray object."""
        self.safe = _ALWAYS_SAFE + safe

    def __repr__(self):
        # Without this, will just display as a defaultdict
        return "<%s %r>" % (self.__class__.__name__, dict(self))

    def __missing__(self, b):
        # Handle a cache miss. Store quoted string in cache and return.
        res = chr(b) if chr(b) in self.safe else "%{0:02X}".format(b)
        self[b] = res
        return res


def quote(string, safe='/', encoding=None, errors=None):
    """quote('abc def') -> 'abc%20def'

    Each part of a URL, e.g. the path info, the query, etc., has a
    different set of reserved characters that must be quoted.

    RFC 2396 Uniform Resource Identifiers (URI): Generic Syntax lists
    the following reserved characters.
    reserved    = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" |
                  "$" | ","

    Each of these characters is reserved in some component of a URL,
    but not necessarily in all of them.

    By default, the quote function is intended for quoting the path
    section of a URL.  Thus, it will not encode '/'.  This character
    is reserved, but in typical usage the quote function is being
    called on a path where the existing slash characters are used as
    reserved characters.

    string and safe may be either str or bytearray objects. encoding and errors
    must not be specified if string is a bytearray object.

    The optional encoding and errors parameters specify how to deal with
    non-ASCII characters, as accepted by the str.encode method.

    By default, encoding='utf-8' (characters are encoded with UTF-8), and
    errors='strict' (unsupported characters raise a UnicodeEncodeError).
    """
    if isinstance(string, (unicode, str)):
        if not string:
            return string
        if encoding is None:
            encoding = 'utf-8'
        if errors is None:
            errors = 'strict'
        s = string.encode(encoding, errors)
        string = bytearray()
        string.extend(s)
    else:
        if encoding is not None:
            raise TypeError("quote() doesn't support 'encoding' for bytearray")
        if errors is not None:
            raise TypeError("quote() doesn't support 'errors' for bytearray")
    return quote_from_bytes(string, safe)


def quote_from_bytes(bs, safe='/'):
    """Like quote(), but accepts a bytearray object rather than a str, and does
    not perform string-to-bytes encoding.  It always returns an ASCII string.
    quote_from_bytes(b'abc def\x3f') -> 'abc%20def%3f'
    """
    if not isinstance(bs, bytearray):
        raise TypeError("quote_from_bytes() expected bytearray")
    if not bs:
        return ''
    if isinstance(safe, str):
        # Normalize 'safe' by converting to bytes and removing non-ASCII chars
        safe = safe.encode('ascii', 'ignore')
    else:
        safe = bytearray([c for c in safe if c < 128])
    if not bs.rstrip(_ALWAYS_SAFE_BYTES + safe):
        return bs.decode()
    try:
        quoter = _safe_quoters[safe]
    except KeyError:
        _safe_quoters[safe] = quoter = Quoter(safe).__getitem__
    return ''.join([quoter(char) for char in bs])
