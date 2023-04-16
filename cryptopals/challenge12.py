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


def get_oracle_block_size_and_message_length(func):
    m = len(func(b""))
    i = 0
    M = m
    while m == M:
        i += 1
        M = len(func(b"A" * i))
    return M - m, m - i


def find_and_decrypt_suffix(func):
    block_size, message_length = get_oracle_block_size_and_message_length(func)
    message_length_with_padding = len(func(b""))
    assert message_length_with_padding % block_size == 0
    decrypted_message = b""

    number_of_blocks = message_length_with_padding // block_size
    for i in range(number_of_blocks):
        for j in range(15, -1, -1):
            block_to_find = func(b"A" * j)[i * block_size : (i + 1) * block_size]
            for c in range(0, 255):
                block_candidate = func(b"A" * j + decrypted_message + bytes([c]))[
                    i * block_size : (i + 1) * block_size
                ]
                if block_candidate == block_to_find:
                    decrypted_message = decrypted_message + bytes([c])
                    break
    return decrypted_message[:message_length]
