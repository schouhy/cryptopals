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

def single_byte_xor(barray, c):
    return bytearray(map(lambda x: x ^ c, barray))

def is_in_interval(c, lo, hi):
    return (c >= lo) and (c < hi)

def is_common(c):
    intervals = [(32, 33), (65, 91), (97, 123)]
    for lo, hi in intervals:
        if is_in_interval(c, lo, hi):
            return True
    return False

def score_most_likely_english(s, ret_message=False):
    res = 0
    message = []
    for i in range(0, 256):
        new_res = 0
        ts = [o ^ i for o in s]
        for c in ts:
            if is_common(c):
                new_res += 1
        if new_res > res:
            res = new_res
            message = ts
    if ret_message:
        return res, message
    return res

def bytearray_entropy(b):
    frequencies = np.array(list(Counter(b).values()))
    frequencies = frequencies / frequencies.sum()
    return (frequencies*(-np.log2(frequencies))).sum()


def entropy(h):
    s = bytearray.fromhex(h)
    return bytearray_entropy(s)

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
        m = np.array(([bytearray_entropy(s[i::keysize]) for i in range(keysize)])).mean()
        average_entropy.append((keysize, m))
    return sorted(average_entropy, key = lambda x: x[1])

def break_repeating_xor(s, keysize):
    cipher_chunks = [s[i : : keysize] for i in range(keysize)]
    text_chunks = [bytearray(score_most_likely_english(chunk, True)[1]).decode() for chunk in cipher_chunks]
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
    if isinstance(s, str):
        return s + chr(padding_length)*padding_length
    if isinstance(s, bytearray):
        return s + bytearray([padding_length]*padding_length)

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



