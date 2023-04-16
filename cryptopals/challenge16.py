import cryptopals.base as crypto_base
from collections import namedtuple

from cryptopals import challenge14

AESCBCOutput = namedtuple("AESCBCOutput", ["ciphertext", "initialization_vector"])


class Oracle:
    def __init__(self):
        self._scheme = crypto_base.AESCBC(key=crypto_base.sample_random_bytes(16))

    @staticmethod
    def _make_payload(userdata: bytes) -> AESCBCOutput:
        userdata = userdata.replace(b"&", b'"&"').replace(b";", b'";"')
        return (
            b"comment1=cooking%20MCs;userdata=" +
            userdata +
            b";comment2=%20like%20a%20pound%20of%20bacon"
        )

    def make_payload(self, userdata: bytes):
        initialization_vector = crypto_base.sample_random_bytes(16)
        ciphertext, _ = self._scheme.encrypt(
            self._make_payload(userdata), initialization_vector
        )
        payload = AESCBCOutput(
            ciphertext=ciphertext, initialization_vector=initialization_vector
        )
        return payload

    def is_admin(self, payload: AESCBCOutput):
        plaintext = self._scheme.decrypt(
            payload.ciphertext, payload.initialization_vector
        )
        return b";admin=true;" in plaintext


def forge_admin(encrypt_func, check_func):
    block_size = challenge14.get_block_size(lambda x: encrypt_func(x).ciphertext)

    # Payload is arbitrarily big just to make sure `"A" * block_size`
    # fits entirely in a block
    payload = encrypt_func(b"A" * block_size * 3)
    new_payload = AESCBCOutput(
        ciphertext=bytearray(payload.ciphertext),
        initialization_vector=payload.initialization_vector,
    )

    desired_block = b";admin=true;AAAA"
    bit_difference = crypto_base.xor_block(b"A" * block_size, desired_block)

    is_admin = False
    block_number = 0
    while not is_admin:
        block_slice = slice(block_number * block_size, (block_number + 1) * block_size)
        new_payload.ciphertext[block_slice] = crypto_base.xor_block(
            new_payload.ciphertext[block_slice], bit_difference
        )
        is_admin = check_func(new_payload)
        block_number += 1
    return new_payload

