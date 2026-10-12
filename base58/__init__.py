'''Base58 encoding

Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
'''

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.

from hashlib import sha256

# typing is only needed by type checkers; importing it at runtime is costly,
# so annotations using its names are written as strings
TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Mapping, Optional, Tuple, Union

__version__ = '2.1.1'

# 58 character alphabet used
BITCOIN_ALPHABET = \
    b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
RIPPLE_ALPHABET = b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
XRP_ALPHABET = RIPPLE_ALPHABET

# Retro compatibility
alphabet = BITCOIN_ALPHABET


def scrub_input(v: 'Union[str, bytes]') -> bytes:
    if isinstance(v, str):
        v = v.encode('ascii')

    return v


# Encode tables by alphabet, so an encode call needs no tuple key
_encode_tables = {}


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    # The big-endian bytes of i have no leading zero bytes, so b58encode
    # adds no zero characters for them
    return b58encode(i.to_bytes((i.bit_length() + 7) // 8, 'big'), alphabet)


def b58encode(
    v: 'Union[str, bytes]', alphabet: bytes = BITCOIN_ALPHABET
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

    # Peel off four digits per big-integer division: base**4 fits in one
    # internal int digit, so each divmod costs the same as one by base.
    # The four digits split evenly into two digit pairs, each a table lookup.
    tables = _encode_tables.get(alphabet)
    if tables is None:
        # The digit pair table, the pair base (base**2), the divisor
        # (base**4), base**12 and the zero character
        if len(_encode_tables) >= 128:
            _encode_tables.clear()
        base = len(alphabet)
        sq = base * base
        big = sq * sq
        # pairs[hi * base + lo] is the two character encoding of digits
        # hi, lo. All pairs are laid out in one string, each followed by a
        # byte that is not in the alphabet, so one split cuts out every pair.
        unused = set(range(256)).difference(alphabet)
        if not base or not unused:
            pairs = [bytes((hi, lo)) for hi in alphabet for lo in alphabet]
        else:
            sep = bytes((min(unused),))
            buf = bytearray(3 * sq)
            buf[0::3] = b''.join(
                [alphabet[d:d + 1] * base for d in range(base)])
            buf[1::3] = alphabet * base
            buf[2::3] = sep * sq
            pairs = bytes(buf[:-1]).split(sep)
        tables = _encode_tables[alphabet] = (
            pairs, sq, big, big ** 3, alphabet[0:1])
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


def _get_base58_decode_table(
    alphabet: bytes, autofix: bool
) -> 'Tuple[Mapping[int, int], Optional[bytes]]':
    # The digit value of each character and a bytes.translate table mapping
    # each character to its digit value and every invalid character to 255
    # (None if some digit value does not fit below 255)
    invmap = {char: index for index, char in enumerate(alphabet)}

    if autofix:
        for group in (b'0Oo', b'Il1'):
            pivots = [c for c in group if c in invmap]
            if len(pivots) == 1:
                for alternative in group:
                    invmap[alternative] = invmap[pivots[0]]

    if max(invmap.values(), default=0) >= 255:
        return invmap, None
    return invmap, bytes(invmap.get(c, 255) for c in range(256))


def _get_base58_decode_merge(base: int,
                             steps: int) -> 'Tuple[list, int, int]':
    # (shift, mask, factor) for merging byte lanes of 2**steps bytes;
    # step j joins lanes of h = 2**j bytes into lanes of 2 * h bytes.
    # A lane holds hi * 256**h + lo and should become hi * base**h + lo,
    # so subtracting hi * (256**h - base**h) merges it in place.
    # The last step joins the two halves of the whole value, so its high
    # half needs no mask: it is returned apart as its shift and factor.
    out = []
    for j in range(steps - 1):
        h = 1 << j
        lanes = (b'\0' * h + b'\xff' * h) * ((1 << steps) // (2 * h))
        out.append((8 * h, int.from_bytes(lanes, 'big'),
                    (1 << 8 * h) - base ** h))
    if not steps:
        return out, 0, 0
    h = 1 << steps - 1
    return out, 8 * h, (1 << 8 * h) - base ** h


# Decode plans by alphabet, one dict for each autofix setting, so a decode
# call needs no tuple key
_decode_plans = {}
_decode_plans_autofix = {}


def b58decode_int(
    v: 'Union[str, bytes]', alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    if b' ' not in alphabet:
        v = v.rstrip()
        if len(alphabet) < 256:
            # Digit values fit a translate table; b58decode strips nothing
            # more here and merges digits faster
            return int.from_bytes(
                b58decode(v, alphabet, autofix=autofix), 'big')
    v = scrub_input(v)
    invmap = _get_base58_decode_table(alphabet, autofix)[0]

    invalid = v.translate(None, bytes(invmap))
    if invalid:
        raise ValueError("Invalid character {!r}".format(chr(invalid[0])))
    decimal = 0
    base = len(alphabet)
    for char in v:
        decimal = decimal * base + invmap[char]
    return decimal


def b58decode(
    v: 'Union[str, bytes]', alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    """
    Decode a Base58 encoded string
    """
    v = v.rstrip()
    if isinstance(v, str):
        v = v.encode('ascii')

    plans = _decode_plans_autofix if autofix else _decode_plans
    plan = plans.get(alphabet)
    if plan is None:
        if len(plans) >= 128:
            plans.clear()
        # The zero character, the translate table and slots for the merge
        # plans, indexed by (len(digits) - 1).bit_length() (below 64 for
        # any length) and filled in on first use
        plan = plans[alphabet] = (
            alphabet[0:1], _get_base58_decode_table(alphabet, autofix)[1],
            [None] * 64)
    zero, table, merges = plan

    origlen = len(v)
    v = v.lstrip(zero)
    newlen = len(v)
    if table is None:
        acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)
    else:
        digits = v.translate(table)
        if 255 in digits:
            bad = v[digits.index(255)]
            raise ValueError("Invalid character {!r}".format(chr(bad)))
        acc = int.from_bytes(digits, 'big')
        bits = (len(digits) - 1).bit_length()
        merge = merges[bits]
        if merge is None:
            merge = merges[bits] = _get_base58_decode_merge(
                len(alphabet), bits)
        steps, last_shift, last_factor = merge
        for shift, mask, factor in steps:
            acc -= (acc >> shift & mask) * factor
        acc -= (acc >> last_shift) * last_factor

    return acc.to_bytes(origlen - newlen + (acc.bit_length() + 7) // 8, 'big')


def b58encode_check(
    v: 'Union[str, bytes]', alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58 with a 4 character checksum
    """
    if isinstance(v, str):
        v = v.encode('ascii')

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4], alphabet)


def b58decode_check(
    v: 'Union[str, bytes]', alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    '''Decode and verify the checksum of a Base58 encoded string'''

    result = b58decode(v, alphabet, autofix=autofix)
    payload = result[:-4]
    digest = sha256(sha256(payload).digest()).digest()

    # Results shorter than four bytes can never end with the four byte check
    if not result.endswith(digest[:4]):
        raise ValueError("Invalid checksum")

    return payload
