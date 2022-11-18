import pytest

import cryptopals.base as crypto_base


def test_hex_to_bytes_computes_correctly():
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
    result = bytes([o ^ c for o in block])
    assert crypto_base.single_byte_xor(block, c)


