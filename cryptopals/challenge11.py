import cryptopals.base as crypto_base
from random import randint
from collections import Counter


class Oracle:
    def __init__(self):
        self._last_mode = None

    def encrypt(self, plaintext: bytes):
        prefix = crypto_base.sample_random_bytes(randint(5, 10))
        suffix = crypto_base.sample_random_bytes(randint(5, 10))
        key = crypto_base.sample_random_bytes(16)
        plaintext = prefix + bytes(plaintext) + suffix
        if randint(0, 9) <= 4:
            self._last_mode = "CBC"
            initialization_vector = crypto_base.sample_random_bytes(16)
            scheme = crypto_base.AESCBC(key=key)
            return scheme.encrypt(plaintext, initialization_vector)[0]
        else:
            self._last_mode = "ECB"
            scheme = crypto_base.AESECB(key=key)
            return scheme.encrypt(plaintext)

def detect_oracle_mode(func):
    cipher = func(bytes([0]*64))
    count = max(Counter([cipher[i*16:(i+1)*16] for i in range(len(cipher)//16)]).values())
    if count > 1:
        return "ECB"
    return "CBC"

