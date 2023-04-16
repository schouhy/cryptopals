from Crypto.Cipher import AES
from random import randint
from base64 import b64decode

import cryptopals.base as crypto_base


class Oracle:
    def __init__(self):
        key = b"e_N\x92\xae\x1av\xcd\xbap\x1e\xadd\xde\xb9\xf3"
        self._scheme = crypto_base.AESECB(key=key)
        self._suffix = b64decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        )

    def encrypt(self, plaintext: bytes):
        return self._scheme.encrypt(plaintext + self._suffix)


def get_oracle_block_size_and_suffix_length(func):
    m = len(func(b""))
    i = 0
    M = m
    while m == M:
        i += 1
        M = len(func(b"A" * i))
    return M - m, m - i


def find_and_decrypt_suffix(func):
    block_size, suffix_length = get_oracle_block_size_and_suffix_length(func)
    suffix_length_with_padding = len(func(b""))
    assert suffix_length_with_padding % block_size == 0
    decrypted_suffix = b""

    number_of_blocks = suffix_length_with_padding // block_size
    for i in range(number_of_blocks):
        for j in range(block_size - 1, -1, -1):
            block_to_find = func(b"A" * j)[i * block_size : (i + 1) * block_size]
            for c in range(0, 255):
                block_candidate = func(b"A" * j + decrypted_suffix + bytes([c]))[
                    i * block_size : (i + 1) * block_size
                ]
                if block_candidate == block_to_find:
                    decrypted_suffix = decrypted_suffix + bytes([c])
                    break
    return decrypted_suffix[:suffix_length]

