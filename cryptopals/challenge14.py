
from Crypto.Cipher import AES
from random import randint
from base64 import b64decode

import cryptopals.base as crypto_base
from cryptopals import challenge12


class Oracle:
    def __init__(self):
        key = b"e_N\x92\xae\x1av\xcd\xbap\x1e\xadd\xde\xb9\xf3"
        self._scheme = crypto_base.AESECB(key=key)
        self._suffix = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
        self._prefix = crypto_base.sample_random_bytes(randint(10, 100))

    def encrypt(self, plaintext: bytes):
        return self._scheme.encrypt(self._prefix + plaintext + self._suffix)

def get_block_size(func):
    i = 0
    m = len(func(b""))
    M = m
    while M == m:
        i+=1
        M = len(func(b"A"*i))
    return M - m

def get_prefix_block_number_with_offset(func, complement_length, block_size):
    """
    Computes `len(prefix || [A]*complement_length) // block_size`. 
    To do this we compute 
        func(prefix || [A]*complement_length) and
        func(prefix || [A]*complement_length || random_block)
    and check the number common blocks at the beginning of both strings
    """
    out1 = func(b"A"*complement_length)
    random_block = crypto_base.sample_random_bytes(block_size)
    out2 = func(b"A"*complement_length + random_block)
    for i in range(len(out2)//block_size):
        if out1[i*block_size: (i+1)*block_size] != out2[i*block_size:(i+1)*block_size]:
            break
    return i

def get_prefix_complement_and_block_offset(func):
    """
    Computes `(-len(prefix)) % block_size` (the prefix complement) and the ceiling of `len(prefix) / block_size` (the offset).
    To do this we successively compute `prefix_block_number_with_offset` with increasing complement lengths until a change is
    seen.
    """
    block_size = get_block_size(func)
    prefix_block_number = get_prefix_block_number_with_offset(func, 0, block_size)
    complement = 0
    for i in range(1, block_size):
        new_prefix_block_number = get_prefix_block_number_with_offset(func, i, block_size)
        if prefix_block_number < new_prefix_block_number:
            prefix_block_number = new_prefix_block_number
            complement = i
            break
    return complement, prefix_block_number * block_size

def find_and_decrypt_suffix(func):
    prefix_complement, offset = get_prefix_complement_and_block_offset(func)
    # `new func` is the same as `func` but with the prefix removed
    new_func = lambda x: func(b"A"*prefix_complement + x)[offset:]
    return challenge12.find_and_decrypt_suffix(new_func)

