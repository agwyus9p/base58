'''Base58 encoding

Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
'''

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.

from __future__ import annotations

from hashlib import sha256
from itertools import product

# typing is only needed by type checkers; importing it at runtime is costly
TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import List, Mapping, Optional, Tuple, Union

__version__ = '2.1.1'

# 58 character alphabet used
BITCOIN_ALPHABET = \
    b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
RIPPLE_ALPHABET = b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
XRP_ALPHABET = RIPPLE_ALPHABET

# Retro compatibility
alphabet = BITCOIN_ALPHABET


def scrub_input(v: Union[str, bytes]) -> bytes:
    if isinstance(v, str):
        v = v.encode('ascii')

    return v


def _cached(func):
    # Small memoiser for the alphabet tables. functools.lru_cache would
    # import functools (and collections with it) when base58 is imported.
    cache = {}

    def wrapper(*args):
        try:
            return cache[args]
        except KeyError:
            if len(cache) >= 128:
                cache.clear()
            result = cache[args] = func(*args)
            return result

    wrapper.cache = cache
    return wrapper


@_cached
def _get_base58_encode_pairs(alphabet: bytes) -> List[bytes]:
    # pairs[hi * base + lo] is the two character encoding of digits hi, lo
    return list(map(bytes, product(alphabet, repeat=2)))


@_cached
def _get_base58_encode_tables(
    alphabet: bytes
) -> Tuple[List[bytes], int, int, bytes]:
    # Everything b58encode needs per alphabet: the digit pair table, the
    # pair base (base**2), the divisor (base**4) and the zero character
    sq = len(alphabet) ** 2
    return _get_base58_encode_pairs(alphabet), sq, sq * sq, alphabet[0:1]


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    base = len(alphabet)
    # Peel off four digits per big-integer division: base**4 fits in one
    # internal int digit, so each divmod costs the same as one by base.
    # The four digits split evenly into two digit pairs, so each group
    # needs only one more small divmod and two table lookups.
    # The last group is zero padded; the padding is stripped at the end.
    sq = base * base
    big = sq * sq
    pairs = _get_base58_encode_pairs(alphabet)
    parts = []
    while i:
        i, rem = divmod(i, big)
        hi, lo = divmod(rem, sq)
        parts += pairs[lo], pairs[hi]
    parts.reverse()
    return b''.join(parts).lstrip(alphabet[0:1])


def b58encode(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58
    """
    if isinstance(v, str):
        v = v.encode('ascii')

    origlen = len(v)
    v = v.lstrip(b'\0')
    newlen = len(v)

    i = int.from_bytes(v, 'big')  # first byte is most significant

    # Same digit loop as b58encode_int with default_one=False, inlined to
    # save a call per encode
    tables = _get_base58_encode_tables.cache.get((alphabet,))
    if tables is None:
        tables = _get_base58_encode_tables(alphabet)
    pairs, sq, big, zero = tables
    parts = []
    while i:
        # Two groups of four digits per pass; a group past the top of i
        # is all zero digits, which the lstrip below removes
        i, rem = divmod(i, big)
        i, rem2 = divmod(i, big)
        # rem is a small int: two operators are cheaper than a divmod call
        parts += (pairs[rem % sq], pairs[rem // sq],
                  pairs[rem2 % sq], pairs[rem2 // sq])
    parts.reverse()
    return zero * (origlen - newlen) + b''.join(parts).lstrip(zero)


@_cached
def _get_base58_decode_map(alphabet: bytes,
                           autofix: bool) -> Mapping[int, int]:
    invmap = {char: index for index, char in enumerate(alphabet)}

    if autofix:
        groups = [b'0Oo', b'Il1']
        for group in groups:
            pivots = [c for c in group if c in invmap]
            if len(pivots) == 1:
                for alternative in group:
                    invmap[alternative] = invmap[pivots[0]]

    return invmap


@_cached
def _get_base58_decode_table(alphabet: bytes,
                             autofix: bool) -> Tuple[bytes, Optional[bytes]]:
    # Valid characters and a bytes.translate table mapping each character
    # to its digit value and every invalid character to 255 (None if some
    # digit value does not fit below 255)
    invmap = _get_base58_decode_map(alphabet, autofix)
    if max(invmap.values(), default=0) >= 255:
        return bytes(invmap), None
    return bytes(invmap), bytes(invmap.get(c, 255) for c in range(256))


@_cached
def _get_base58_decode_steps(base: int,
                             steps: int) -> List[Tuple[int, int, int]]:
    # (shift, mask, factor) for merging byte lanes of 2**steps bytes;
    # step j joins lanes of h = 2**j bytes into lanes of 2 * h bytes.
    # A lane holds hi * 256**h + lo and should become hi * base**h + lo,
    # so subtracting hi * (256**h - base**h) merges it in place.
    out = []
    for j in range(steps):
        h = 1 << j
        lanes = (b'\0' * h + b'\xff' * h) * ((1 << steps) // (2 * h))
        out.append((8 * h, int.from_bytes(lanes, 'big'),
                    (1 << 8 * h) - base ** h))
    return out


def b58decode_int(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    if b' ' not in alphabet:
        v = v.rstrip()
    v = scrub_input(v)

    valid, table = _get_base58_decode_table(alphabet, autofix)
    if table is None:
        invalid = v.translate(None, valid)
        if invalid:
            raise ValueError("Invalid character {!r}".format(chr(invalid[0])))
        map = _get_base58_decode_map(alphabet, autofix)
        digits = [map[char] for char in v]
    else:
        # Invalid characters translate to 255, which no digit uses
        digits = v.translate(table)
        if 255 in digits:
            bad = v[digits.index(255)]
            raise ValueError("Invalid character {!r}".format(chr(bad)))
        # Every digit sits in its own byte of one big integer. Each step
        # merges neighbouring lanes, hi * base**h + lo, for all lanes at
        # once; base < 256 so the merged value always fits its lane.
        decimal = int.from_bytes(digits, 'big')
        steps = (len(digits) - 1).bit_length()
        for shift, mask, factor in _get_base58_decode_steps(len(alphabet),
                                                            steps):
            decimal -= (decimal >> shift & mask) * factor
        return decimal

    decimal = 0
    base = len(alphabet)
    # Accumulate five digits in a small int, then fold them into the
    # big integer with a single multiply-add.
    head = len(digits) % 5
    for d in digits[:head]:
        decimal = decimal * base + d
    big = base ** 5
    # zip over one shared iterator yields consecutive groups of five
    rest = iter(digits[head:])
    for a, b, c, d, e in zip(rest, rest, rest, rest, rest):
        decimal = decimal * big + ((((a * base + b) * base + c) * base + d)
                                   * base + e)
    return decimal


def b58decode(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    """
    Decode a Base58 encoded string
    """
    v = v.rstrip()
    if isinstance(v, str):
        v = v.encode('ascii')

    origlen = len(v)
    v = v.lstrip(alphabet[0:1])
    newlen = len(v)

    # Same lane merging as b58decode_int, inlined to save a call per decode
    tables = _get_base58_decode_table.cache.get((alphabet, autofix))
    if tables is None:
        tables = _get_base58_decode_table(alphabet, autofix)
    table = tables[1]
    if table is None:
        acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)
    else:
        digits = v.translate(table)
        if 255 in digits:
            bad = v[digits.index(255)]
            raise ValueError("Invalid character {!r}".format(chr(bad)))
        acc = int.from_bytes(digits, 'big')
        key = (len(alphabet), (len(digits) - 1).bit_length())
        steps = _get_base58_decode_steps.cache.get(key)
        if steps is None:
            steps = _get_base58_decode_steps(*key)
        for shift, mask, factor in steps:
            acc -= (acc >> shift & mask) * factor

    return acc.to_bytes(origlen - newlen + (acc.bit_length() + 7) // 8, 'big')


def b58encode_check(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58 with a 4 character checksum
    """
    v = scrub_input(v)

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4], alphabet=alphabet)


def b58decode_check(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    '''Decode and verify the checksum of a Base58 encoded string'''

    result = b58decode(v, alphabet=alphabet, autofix=autofix)
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result
