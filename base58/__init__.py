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
    # pairs[hi * base + lo] is the two character encoding of digits hi, lo.
    # All pairs are laid out in one string, each followed by a byte that is
    # not in the alphabet, so a single split cuts out every pair at once.
    base = len(alphabet)
    unused = set(range(256)).difference(alphabet)
    if not base or not unused:
        return list(map(bytes, product(alphabet, repeat=2)))
    sep = bytes((min(unused),))
    count = base * base
    buf = bytearray(3 * count)
    buf[0::3] = b''.join([alphabet[d:d + 1] * base for d in range(base)])
    buf[1::3] = alphabet * base
    buf[2::3] = sep * count
    return bytes(buf[:-1]).split(sep)


@_cached
def _get_base58_encode_tables(
    alphabet: bytes
) -> Tuple[List[bytes], int, int, int, bytes]:
    # Everything b58encode needs per alphabet: the digit pair table, the
    # pair base (base**2), the divisor (base**4), base**12 and the zero
    # character
    sq = len(alphabet) ** 2
    big = sq * sq
    return (_get_base58_encode_pairs(alphabet), sq, big, big ** 3,
            alphabet[0:1])


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
    pairs, sq, big, big3, zero = tables
    parts = []
    while i >= big3:
        # Four groups of four digits per pass while at least four remain
        i, rem = divmod(i, big)
        i, rem2 = divmod(i, big)
        i, rem3 = divmod(i, big)
        i, rem4 = divmod(i, big)
        # rem is a small int: two operators are cheaper than a divmod call
        parts += (pairs[rem % sq], pairs[rem // sq],
                  pairs[rem2 % sq], pairs[rem2 // sq],
                  pairs[rem3 % sq], pairs[rem3 // sq],
                  pairs[rem4 % sq], pairs[rem4 // sq])
    if i >= big:
        # Now base**4 <= i < base**12: two or three groups remain, take
        # them without a loop. Zero digits at the top of the last group
        # are removed by the lstrip below.
        i, rem = divmod(i, big)
        rem3, rem2 = divmod(i, big)
        parts += (pairs[rem % sq], pairs[rem // sq],
                  pairs[rem2 % sq], pairs[rem2 // sq],
                  pairs[rem3 % sq], pairs[rem3 // sq])
    elif i:
        parts += pairs[i % sq], pairs[i // sq]
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


@_cached
def _get_base58_decode_merge(base: int,
                             steps: int) -> Tuple[list, int, int]:
    # The merge steps split into all but the last, plus the shift and
    # factor of the last step. The last step joins the two halves of the
    # whole value, so its high half needs no mask.
    if not steps:
        return [], 0, 0
    out = _get_base58_decode_steps(base, steps)
    shift, _, factor = out[-1]
    return out[:-1], shift, factor


@_cached
def _get_base58_decode_plan(alphabet: bytes, autofix: bool):
    # The translate table and the merge plans for inputs of up to 2**11
    # digits, indexed by (len(digits) - 1).bit_length()
    table = _get_base58_decode_table(alphabet, autofix)[1]
    if table is None:
        return None, []
    base = len(alphabet)
    return table, [_get_base58_decode_merge(base, s) for s in range(12)]


_decode_plans = _get_base58_decode_plan.cache


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
    plan = _decode_plans.get((alphabet, autofix))
    if plan is None:
        plan = _get_base58_decode_plan(alphabet, autofix)
    table, merges = plan
    if table is None:
        acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)
    else:
        digits = v.translate(table)
        if 255 in digits:
            bad = v[digits.index(255)]
            raise ValueError("Invalid character {!r}".format(chr(bad)))
        acc = int.from_bytes(digits, 'big')
        bits = (len(digits) - 1).bit_length()
        if bits < 12:
            steps, last_shift, last_factor = merges[bits]
        else:
            steps, last_shift, last_factor = _get_base58_decode_merge(
                len(alphabet), bits)
        for shift, mask, factor in steps:
            acc -= (acc >> shift & mask) * factor
        acc -= (acc >> last_shift) * last_factor

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
