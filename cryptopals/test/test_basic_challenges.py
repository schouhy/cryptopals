import base64
from pathlib import Path

import cryptopals.base as crypto_base

from cryptopals import challenge4, challenge6, challenge8


from Crypto.Cipher import AES

TEST_DIR = Path(__file__).parent


def test_challenge_1():
    string_in_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    string_in_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert base64.b64encode(crypto_base.hex_to_bytes(string_in_hex)) == string_in_base64.encode()

def test_challenge_2():
    block1 = crypto_base.hex_to_bytes("1c0111001f010100061a024b53535009181c")
    block2 = crypto_base.hex_to_bytes("686974207468652062756c6c277320657965")
    result = crypto_base.hex_to_bytes("746865206b696420646f6e277420706c6179")
    assert crypto_base.xor_block(block1, block2) == result

def test_challenge_3():
    original_message = b"Cooking MC's like a pound of bacon"
    cipher = crypto_base.hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    decrypted_message = crypto_base.get_most_englishy_single_byte_decryption(cipher)
    assert original_message == decrypted_message

def test_challenge_4():
    message_to_find = b"Now that the party is jumping\n"
    solver = challenge4.Solver(filepath=TEST_DIR / "challenge4.txt")
    assert solver.solve() == message_to_find

def test_challenge_5():
    message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ciphertext_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    ciphertext = crypto_base.hex_to_bytes(ciphertext_hex)
    scheme = crypto_base.RepeatingXOR(key=b"ICE")
    assert scheme.encrypt(message) == ciphertext

def test_challenge_6():
    # Load solution
    with open(TEST_DIR / "challenge6_plaintext.txt", "r") as solution_file:
        expected_plaintext = solution_file.readlines()
    expected_plaintext = "".join(expected_plaintext).encode()
    solver = challenge6.Solver(TEST_DIR / "challenge6.txt")
    assert solver.solve() == expected_plaintext

def test_challenge_7():
    ciphertext = crypto_base.load_multiline_base64(TEST_DIR / "challenge7.txt")
    key = b"YELLOW SUBMARINE"
    plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
    # Load solution
    with open(TEST_DIR / "challenge7_plaintext.txt", "r") as solution_file:
        expected_plaintext = solution_file.readlines()
    expected_plaintext = "".join(expected_plaintext)
    # Assert the expected plaintext and the solution match
    assert plaintext.decode() == expected_plaintext

def test_challenge_8():
    line_to_find = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    solver = challenge8.Solver(TEST_DIR / "challenge8.txt")
    assert solver.solve() == line_to_find

