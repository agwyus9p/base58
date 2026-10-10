'''Base58 encoding

Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
'''

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.

from functools import lru_cache
from hashlib import sha256
from itertools import product
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


@lru_cache()
def _get_base58_encode_pairs(alphabet: bytes) -> List[bytes]:
    # pairs[hi * base + lo] is the two character encoding of digits hi, lo
    return list(map(bytes, product(alphabet, repeat=2)))


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    base = len(alphabet)
    # Peel off five digits per big-integer division: base**5 still fits in
    # one internal int digit, so each divmod costs the same as one by base.
    # The five digits are emitted as one single digit and two digit pairs.
    # The last group is zero padded; the padding is stripped at the end.
    big = base ** 5
    sq = base * base
    pairs = _get_base58_encode_pairs(alphabet)
    parts = []
    while i:
        i, rem = divmod(i, big)
        rem, lo = divmod(rem, sq)
        top, mid = divmod(rem, sq)
        parts += pairs[lo], pairs[mid], alphabet[top:top + 1]
    parts.reverse()
    return b''.join(parts).lstrip(alphabet[0:1])


def b58encode(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58
    """
    v = scrub_input(v)

    origlen = len(v)
    v = v.lstrip(b'\0')
    newlen = len(v)

    acc = int.from_bytes(v, byteorder='big')  # first byte is most significant

    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
    return alphabet[0:1] * (origlen - newlen) + result


@lru_cache()
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


@lru_cache()
def _get_base58_decode_table(alphabet: bytes,
                             autofix: bool) -> Tuple[bytes, Optional[bytes]]:
    # Valid characters and a bytes.translate table mapping each character
    # to its digit value (None if some digit value does not fit in a byte)
    invmap = _get_base58_decode_map(alphabet, autofix=autofix)
    if max(invmap.values(), default=0) > 255:
        return bytes(invmap), None
    return bytes(invmap), bytes(invmap.get(c, 0) for c in range(256))


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

    valid, table = _get_base58_decode_table(alphabet, autofix=autofix)
    invalid = v.translate(None, valid)
    if invalid:
        raise ValueError("Invalid character {!r}".format(chr(invalid[0])))
    if table is None:
        map = _get_base58_decode_map(alphabet, autofix=autofix)
        digits = [map[char] for char in v]
    else:
        digits = v.translate(table)

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
    v = scrub_input(v)

    origlen = len(v)
    v = v.lstrip(alphabet[0:1])
    newlen = len(v)

    acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)

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
