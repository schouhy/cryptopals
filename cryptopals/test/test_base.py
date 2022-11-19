import pytest

import cryptopals.base as crypto_base


def test_hex_to_bytes_computes_value_correctly():
    assert crypto_base.hex_to_bytes("ffff") == bytes([255, 255])

def test_xor_block_raises_value_error_on_different_lengths():
    with pytest.raises(ValueError) as e_info:
        crypto_base.xor_block(b"aaa", b"aa")

def test_xor_block_computes_value_correctly():
    block1 = crypto_base.hex_to_bytes(hex(int("0110101", 2))[2:])
    block2 = crypto_base.hex_to_bytes(hex(int("1111011", 2))[2:])
    result = crypto_base.hex_to_bytes(hex(int("1001110", 2))[2:])
    assert crypto_base.xor_block(block1, block2) == result

def test_single_byte_xor_raises_value_error_on_bad_input():
    with pytest.raises(ValueError) as e_info:
        crypto_base.single_byte_xor(b"aaaa", -1)
    with pytest.raises(ValueError) as e_info:
        crypto_base.single_byte_xor(b"aaaa", 256)

def test_single_byte_xor_computes_value_correctly():
    c = 170
    block = bytes([219, 92, 12, 144, 14, 61, 137, 32, 114, 65, 230, 90, 191, 203, 91, 12, 211, 199, 102, 193, 230, 220, 220, 163, 195, 39, 148, 193, 149, 91, 196, 122, 242, 253, 225, 175, 178, 218, 225, 213, 194, 76, 107, 123, 236, 62, 243, 41, 226, 149, 208, 152, 108, 128, 58, 119, 89, 49, 127, 84, 150, 97, 66, 199, 217, 9, 203, 142, 170, 189, 137, 67, 73, 53, 123, 137, 161, 246, 59, 1, 169, 195, 56, 197, 171, 59, 84, 208, 114, 148, 242, 138, 50, 234, 251, 56, 187, 65, 62, 73, 195, 83, 119, 234, 236, 103, 34, 130, 179, 219, 112, 147, 217, 98, 241, 252, 74, 216, 154, 102, 60, 92, 154, 81, 20, 227, 74, 83])
    result = bytes([113, 246, 166, 58, 164, 151, 35, 138, 216, 235, 76, 240, 21, 97, 241, 166, 121, 109, 204, 107, 76, 118, 118, 9, 105, 141, 62, 107, 63, 241, 110, 208, 88, 87, 75, 5, 24, 112, 75, 127, 104, 230, 193, 209, 70, 148, 89, 131, 72, 63, 122, 50, 198, 42, 144, 221, 243, 155, 213, 254, 60, 203, 232, 109, 115, 163, 97, 36, 0, 23, 35, 233, 227, 159, 209, 35, 11, 92, 145, 171, 3, 105, 146, 111, 1, 145, 254, 122, 216, 62, 88, 32, 152, 64, 81, 146, 17, 235, 148, 227, 105, 249, 221, 64, 70, 205, 136, 40, 25, 113, 218, 57, 115, 200, 91, 86, 224, 114, 48, 204, 150, 246, 48, 251, 190, 73, 224, 249])
    assert crypto_base.single_byte_xor(block, c) == result

def test_is_english_common():
    letters_lowercase = "abcdefghijklmnopqrstuvwxyz "
    for char in range(256):
        if char in letters_lowercase.encode():
            assert crypto_base.is_english_common(char)
        elif char in letters_lowercase.upper().encode():
            assert crypto_base.is_english_common(char)
        else:
            assert ~crypto_base.is_english_common(char)

def test_entropy_computes_value_correctly():
    distribution = bytes([1,1,1,2])
    assert crypto_base.entropy(distribution) == pytest.approx(0.8112781244591328, 1e-16)
    distribution = bytes([1,1,2,2])
    assert crypto_base.entropy(distribution) == pytest.approx(1, 1e-16)

def test_ice_encrypt_computes_value_correctly():
    plaintext = bytes([0, 20, 30, 40, 50, 60, 255, 235, 215, 185, 101])
    key = bytes([33, 201, 45, 177])
    result = bytes([33, 221, 51, 153, 19, 245, 210, 90, 246,  112, 72])
    scheme = crypto_base.RepeatingXOR(key=key)
    assert scheme.encrypt(plaintext) == result
    assert scheme.decrypt(scheme.encrypt(plaintext)) == plaintext

