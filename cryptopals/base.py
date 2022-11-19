import pandas as pd
import numpy  as np
from collections import Counter
import base64


def hex_to_bytes(h):
    return bytearray.fromhex(h)

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

def entropy(b):
    frequencies = np.array(list(Counter(b).values()))
    frequencies = frequencies / frequencies.sum()
    return (frequencies*(-np.log2(frequencies))).sum()

def ice_encrypt(s):
    ice = [ord(c) for c in "ICE"]
    cipher = []
    for i, c in enumerate(s):
        cipher.append(ord(c) ^ ice[i % 3])
    return bytearray(cipher).hex()

def hamming_distance(s1, s2):
    "input: bytearray"
    if len(s1) != len(s2):
        return None

    res = 0
    for i in range(len(s1)):
        res += np.array(list(bin(s1[i] ^ s2[i])[2:])).astype(bool).sum()
    return res

def get_keysize_candidates_normalized_hamming(s, min_size=2, max_size=40):
    nahd = []
    for keysize in range(min_size, max_size + 1):
        i = 0
        accum = []
        while i + 2*keysize < len(s):
            s1 = s[i: i + keysize]
            s2 = s[i + keysize: i + 2 * keysize]

            accum.append(hamming_distance(s1, s2) / keysize)
            i += keysize

        if len(accum) > 0:
            nahd.append((keysize, sum(accum) / len(accum)))

    return sorted(nahd, key = lambda x: x[1])

def get_keysize_candidates_entropy(s, min_size=2, max_size=40):
    average_entropy = []
    for keysize in range(min_size, max_size + 1):
        m = np.array(([entropy(s[i::keysize]) for i in range(keysize)])).mean()
        average_entropy.append((keysize, m))
    return sorted(average_entropy, key = lambda x: x[1])

def break_repeating_xor(s, keysize):
    cipher_chunks = [s[i : : keysize] for i in range(keysize)]
    text_chunks = [get_most_englishy_single_byte_decryption(chunk, True)[1].decode() for chunk in cipher_chunks]
    return "".join(["".join(t) for t in zip(*text_chunks)])

def load_multiline_base64(filepath):
    with open(filepath, "r") as file:
        cipher = file.readlines()
    cipher = [line.strip("\n") for line in cipher]
    cipher = base64.b64decode("".join(cipher))
    return cipher

def pkcs7_padding(s, block_size: int):
    padding_length = (-len(s)) % block_size
    if padding_length < 0:
        padding_length += block_size
    if padding_length == 0:
        padding_length = block_size
    if isinstance(s, str):
        return s + chr(padding_length)*padding_length
    if isinstance(s, bytearray):
        return s + bytearray([padding_length]*padding_length)
    if isinstance(s, bytes):
        return bytearray(s) + bytearray([padding_length]*padding_length)

def aes_ecb_encrypt(plaintext: bytes, key: bytes):
    from Crypto.Cipher import AES
    aes_ecb = AES.new(key, AES.MODE_ECB)
    return aes_ecb.encrypt(pkcs7_padding(plaintext, 16))

def aes_ecb_decrypt(ciphertext: bytes, key: bytes):
    from Crypto.Cipher import AES
    aes_ecb = AES.new(key, AES.MODE_ECB)
    plaintext = aes_ecb.decrypt(ciphertext)
    padding = plaintext[-1]
    return plaintext[:-padding]

def aes_cbc_encrypt(plaintext: bytes, key: bytes, initialization_vector: bytes):
    from Crypto.Cipher import AES
    from functools import reduce

    aes_ecb = AES.new(key, AES.MODE_ECB)
    if len(plaintext) % AES.block_size != 0:
        plaintext = pkcs7_padding(plaintext, AES.block_size)

    num_blocks = len(plaintext) // AES.block_size
    plaintext_blocks = [plaintext[AES.block_size*i: AES.block_size*(i+1)] for i in range(num_blocks)]
    cipher_blocks = []

    for plaintext_block in plaintext_blocks:
        initialization_vector = aes_ecb.encrypt(xor_block(plaintext_block, initialization_vector))
        cipher_blocks.append(initialization_vector)

    return reduce(lambda a, b: a + b, cipher_blocks)


def aes_cbc_decrypt(cipher: bytes, key: bytes, initialization_vector: bytes):
    from Crypto.Cipher import AES
    from functools import reduce

    aes_ecb = AES.new(key, AES.MODE_ECB)
    if len(cipher) % AES.block_size != 0:
        raise ValueError(f"Malformed cipher. Its length is not divisible by {AES.block_size}")

    num_blocks = len(cipher) // AES.block_size
    cipher_blocks = [cipher[AES.block_size*i: AES.block_size*(i+1)] for i in range(num_blocks)]
    plaintext_blocks = []

    for cipher_block in cipher_blocks:
        plaintext_blocks.append(xor_block(aes_ecb.decrypt(cipher_block), initialization_vector))
        initialization_vector = cipher_block

    return reduce(lambda a, b: a + b, plaintext_blocks)

def sample_random_bytes(size: int):
    from os import urandom
    return urandom(size)

def encryption_oracle_11(plaintext: bytes):
    from Crypto.Cipher import AES
    from random import randint
    prefix = sample_random_bytes(randint(5, 10))
    suffix = sample_random_bytes(randint(5, 10))
    key = sample_random_bytes(16)
    plaintext = prefix + bytearray(plaintext) + suffix
    if randint(0, 9) <= 4:
        iv = sample_random_bytes(16)
        return aes_cbc_encrypt(plaintext, key, iv)
    else:
        aes_ecb = AES.new(key, AES.MODE_ECB)
        if len(plaintext) % AES.block_size != 0:
            plaintext = pkcs7_padding(plaintext, AES.block_size)
        return aes_ecb.encrypt(plaintext)

def detect_encryption_oracle_11(func):
    from collections import Counter

    cipher = func(bytes([0]*64))
    count = max(Counter([cipher[i*16:(i+1)*16] for i in range(len(cipher)//16)]).values())
    if count > 1:
        return "ECB"
    return "CBC"

def encryption_oracle_12(plaintext: bytes):
    from Crypto.Cipher import AES
    from random import randint
    from base64 import b64decode
    key = b"e_N\x92\xae\x1av\xcd\xbap\x1e\xadd\xde\xb9\xf3"
    suffix = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    plaintext = bytearray(plaintext) + suffix

    aes_ecb = AES.new(key, AES.MODE_ECB)
    if len(plaintext) % AES.block_size != 0:
        plaintext = pkcs7_padding(plaintext, AES.block_size)
    return aes_ecb.encrypt(plaintext)

def get_oracle_block_size(oracle):
    m = len(oracle(b""))
    i = 1
    M = len(oracle(b"A"*i))
    while m == M:
        i += 1
        M = len(oracle(b"A"*i))
    return M - m

def decrypt_suffix_encryption_oracle_12():
    block_size = get_oracle_block_size(encryption_oracle_12)
    message_length = len(encryption_oracle_12(b""))
    assert message_length % block_size == 0
    decrypted_message = b""

    number_of_blocks = message_length // block_size
    for i in range(number_of_blocks):
        for j in range(15, -1, -1):
            block_to_find = encryption_oracle_12(b"A"*j)[i*block_size: (i+1)*block_size]
            for c in range(0, 255):
                block_candidate = encryption_oracle_12(b"A"*j + decrypted_message + bytes([c]))[i*block_size: (i+1)*block_size]
                if block_candidate == block_to_find:
                    decrypted_message = decrypted_message + bytes([c])
                    break
    return decrypted_message

class EncryptionOracle13:
    def __init__(self):
        self._key = sample_random_bytes(16)

    @staticmethod
    def parse_dictionary(s: bytes):
        return dict(keyvalue.split("=") for keyvalue in s.decode().split("&"))
    
    @staticmethod
    def profile_for(email: bytes):
        if b"=" in email or b"&" in email:
            raise ValueError("email cannot contain & or =")
        return b"email=" + email + b"&uid=10&role=user"

    def make_profile(self, email):
        return aes_ecb_encrypt(self.profile_for(email), self._key)

    def read_profile(self, ciphertext):
        return self.parse_dictionary(aes_ecb_decrypt(ciphertext, self._key))

def forge_admin_challenge_13(oracle):
    assert get_oracle_block_size(oracle.make_profile) == 16
    # Compute first blocks having "...&user=" block aligned so as to append a block corresponding
    # to the "admin||padding" after it.
    length1 = len(b"email=&uid=10&user=")
    offset = ((length1 + 15) // 16) * 16 - length1
    stem = oracle.make_profile(b"A"*offset)[:-16]
    # Have the oracle encrypt the block "admin||padding" as the second block of a 
    # two block sized email address
    length2 = 16 - len(b"email=")
    admin_block = oracle.make_profile(b"A"*length2 + pkcs7_padding(b"admin", 16))[16:32]
    return stem + admin_block

def solve_challenge_13():
    oracle = EncryptionOracle13()
    forged_profile = forge_admin_challenge_13(oracle)
    return oracle.read_profile(forged_profile)

