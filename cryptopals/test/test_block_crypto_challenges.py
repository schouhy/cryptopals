import cryptopals.base as crypto_base
from pathlib import Path

from cryptopals import challenge11

TEST_DIR = Path(__file__).parent

def test_challenge_9():
    plaintext = b"YELLOW SUBMARINE"
    expectd_padded_plaintext = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    assert crypto_base.pkcs7_padding(plaintext, 20) == expectd_padded_plaintext

def test_challenge_10():
    ciphertext = crypto_base.load_multiline_base64(TEST_DIR / "challenge10.txt")
    key = b"YELLOW SUBMARINE"
    initialization_vector = b"\x00"*16
    scheme = crypto_base.AESCBC(key=key)
    plaintext = scheme.decrypt(ciphertext, initialization_vector)
    # Load solution
    with open(TEST_DIR / "challenge10_plaintext.txt", "r") as solution_file:
        expected_plaintext = solution_file.readlines()
    expected_plaintext = "".join(expected_plaintext)
    assert plaintext.decode() == expected_plaintext

def test_challenge_11():
    oracle = challenge11.Oracle()
    for _ in range(100):
        detected_mode = challenge11.detect_oracle_mode(oracle.encrypt)
        assert detected_mode == oracle._last_mode




