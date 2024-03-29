import numpy as np
from collections import Counter
from functools import reduce
import base64
from typing import List

from Crypto.Cipher import AES


def hex_to_bytes(h: str):
    return bytes.fromhex(h)


def xor_block(block1: bytes, block2: bytes):
    if len(block1) != len(block2):
        raise ValueError("blocks need to have same length")
    return bytes([x ^ y for x, y in zip(block1, block2)])


def single_byte_xor(barray: bytes, c: int):
    if c < 0 or c > 255:
        raise ValueError("`c` must be between 0 and 255")
    return bytearray(map(lambda x: x ^ c, barray))


def is_in_interval(c, lo, hi):
    return (c >= lo) and (c < hi)


def is_english_common(c):
    intervals = [(32, 33), (65, 91), (97, 123)]
    for lo, hi in intervals:
        if is_in_interval(c, lo, hi):
            return True
    return False


def get_most_englishy_single_byte_decryption(cipher: bytes):
    res = 0
    message = []
    for i in range(0, 256):
        new_res = 0
        ts = [o ^ i for o in cipher]
        for c in ts:
            if is_english_common(c):
                new_res += 1
        if new_res > res:
            res = new_res
            message = ts
    return bytes(message)


def entropy(b: bytes):
    frequencies = np.array(list(Counter(b).values()))
    frequencies = frequencies / frequencies.sum()
    return (frequencies * (-np.log2(frequencies))).sum()


class RepeatingXOR:
    def __init__(self, key: bytes):
        self._key = key
        self._key_length = len(key)

    def encrypt(self, plaintext: bytes):
        cipher = []
        for i, c in enumerate(plaintext):
            cipher.append(c ^ self._key[i % self._key_length])
        return bytes(cipher)

    def decrypt(self, ciphertext: bytes):
        return self.encrypt(ciphertext)


def hamming_distance(s1: bytes, s2: bytes):
    if len(s1) != len(s2):
        return None

    res = 0
    for i in range(len(s1)):
        res += np.array(list(bin(s1[i] ^ s2[i])[2:])).astype(bool).sum()
    return res


def load_multiline_base64(filepath):
    with open(filepath, "r") as file:
        content = file.readlines()
    content = [line.strip("\n") for line in content]
    content = base64.b64decode("".join(content))
    return content


def pkcs7_pad(s: bytes, block_size: int):
    if not isinstance(s, bytes):
        raise ValueError("Input must be bytes.")
    padding_length = (-len(s)) % block_size
    if padding_length < 0:
        padding_length += block_size
    if padding_length == 0:
        padding_length = block_size
    return s + bytes([padding_length] * padding_length)


class BadPadding(Exception):
    pass


def pkcs7_check_padding(s: bytes, pad: int):
    return len(set(s[-pad:])) == 1


def pkcs7_unpad(s: bytes, block_size: int):
    if not isinstance(s, bytes):
        raise ValueError("Input must be bytes.")
    if block_size < 0 or block_size > 255:
        raise ValueError("Blocks size must be in the range 0 to 255.")

    if len(s) % block_size != 0:
        raise ValueError("Size must be divisible by the block size.")
    pad = s[-1]
    if not pkcs7_check_padding(s, pad=pad):
        raise BadPadding

    return s[:-pad]


class AESECB:
    BLOCK_SIZE = 16

    def __init__(self, key: bytes):
        self._block_cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, plaintext: bytes, pad: bool = True):
        if pad:
            plaintext = pkcs7_pad(plaintext, self.BLOCK_SIZE)
        return self._block_cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, unpad: bool = True):
        plaintext = self._block_cipher.decrypt(ciphertext)
        if unpad:
            padding = plaintext[-1]
            plaintext = plaintext[:-padding]
        return plaintext


class AESCBC:
    def __init__(self, key: bytes):
        self._block_cipher = AESECB(key)

    def block_size(self) -> int:
        return self._block_cipher.BLOCK_SIZE

    def _split_bytes_into_blocks(self, data: bytes) -> List[bytes]:
        block_size = self.block_size()
        num_blocks = len(data) // block_size
        return [data[block_size * i : block_size * (i + 1)] for i in range(num_blocks)]

    @staticmethod
    def _join_blocks_into_bytes(data: List[bytes]) -> bytes:
        return reduce(lambda a, b: a + b, data)

    def encrypt(self, plaintext: bytes, initialization_vector: bytes):
        plaintext = pkcs7_pad(plaintext, self.block_size())
        plaintext_blocks = self._split_bytes_into_blocks(plaintext)
        ciphertext_blocks = []
        for plaintext_block in plaintext_blocks:
            ciphertext = self._block_cipher.encrypt(
                xor_block(plaintext_block, initialization_vector), pad=False
            )
            ciphertext_blocks.append(ciphertext)
            initialization_vector = ciphertext
        return self._join_blocks_into_bytes(ciphertext_blocks), initialization_vector

    def decrypt(self, cipher: bytes, initialization_vector: bytes):
        if len(cipher) % self.block_size() != 0:
            raise ValueError(
                f"Malformed cipher. Its length is not divisible by {AES.block_size}"
            )

        ciphertext_blocks = self._split_bytes_into_blocks(cipher)
        plaintext_blocks = []
        for block in ciphertext_blocks:
            plaintext_blocks.append(
                xor_block(
                    self._block_cipher.decrypt(block, unpad=False),
                    initialization_vector,
                )
            )
            initialization_vector = block
        plaintext = self._join_blocks_into_bytes(plaintext_blocks)
        padding = plaintext[-1]
        if not pkcs7_check_padding(plaintext, padding):
            raise BadPadding
        plaintext = plaintext[:-padding]
        return plaintext


class AESCRT:
    def __init__(self, key: bytes):
        self._block_cipher = AESECB(key)

    def block_size(self) -> int:
        return self._block_cipher.block_size()

    def encrypt(self, plaintext: bytes, nonce: bytes):
        if len(nonce) != 8:
            raise ValueError("An 8-byte nonce is required")
        keystream_number_blocks = (len(plaintext) + 15) // 16
        if (keystream_number_blocks >> 64) > 0:
            raise ValueError("Plaintext is too large")
        counter = bytes([])
        for i in range(keystream_number_blocks):
            counter += nonce + i.to_bytes(8, "little")
        keystream = self._block_cipher.encrypt(counter, pad = False)
        return xor_block(plaintext, keystream[:len(plaintext)])

    def decrypt(self, ciphertext: bytes, nonce: bytes):
        return self.encrypt(ciphertext, nonce)


def sample_random_bytes(size: int):
    from os import urandom

    return urandom(size)
