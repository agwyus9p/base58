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
from typing import Mapping, Union

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


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    singles, pairs = _get_base58_encode_tables(alphabet)
    base = len(alphabet)
    pair_base = base * base
    # Peel 5 digits per big-int division; 58**5 fits a single 30-bit
    # internal digit, so each remainder is split into a two-digit, a
    # two-digit and a one-digit piece through cached lookup tables.
    chunk_base = pair_base * pair_base * base
    parts = []
    append = parts.append
    while i >= chunk_base:
        i, rem = divmod(i, chunk_base)
        rem, lo = divmod(rem, pair_base)
        top, mid = divmod(rem, pair_base)
        append(pairs[lo])
        append(pairs[mid])
        append(singles[top])
    while i >= pair_base:
        i, lo = divmod(i, pair_base)
        append(pairs[lo])
    if i >= base:
        append(pairs[i])
    elif i:
        append(singles[i])
    parts.reverse()
    return b''.join(parts)


@lru_cache()
def _get_base58_encode_tables(alphabet: bytes):
    singles = [bytes((c,)) for c in alphabet]
    pairs = [bytes((a, b)) for a in alphabet for b in alphabet]
    return singles, pairs


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

    map = _get_base58_decode_map(alphabet, autofix=autofix)

    decimal = 0
    base = len(alphabet)
    try:
        if len(v) < 128:
            for char in v:
                decimal = decimal * base + map[char]
            return decimal
        digits = [map[char] for char in v]
    except KeyError as e:
        raise ValueError(
            "Invalid character {!r}".format(chr(e.args[0]))
        ) from None

    # For long inputs, combine neighbouring values pairwise. Each pass halves
    # the number of values and squares the weight of the left value, so the
    # big multiplications stay balanced instead of growing one digit at a time.
    # The first pass folds five digits at a time; base ** 5 is still small.
    digits[:0] = [0] * (-len(digits) % 5)  # leading zeros do not change value
    groups = iter(digits)
    digits = [(((a * base + b) * base + c) * base + d) * base + e
              for a, b, c, d, e in zip(groups, groups, groups, groups, groups)]
    level_base = base ** 5
    while len(digits) > 1:
        if len(digits) % 2:
            digits.insert(0, 0)  # a leading zero digit does not change value
        pairs = iter(digits)
        digits = [hi * level_base + lo for hi, lo in zip(pairs, pairs)]
        if len(digits) > 1:
            level_base *= level_base
    return digits[0]


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
