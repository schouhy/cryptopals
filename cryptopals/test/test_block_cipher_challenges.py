import cryptopals.base as crypto_base
from pathlib import Path

from cryptopals.challenge17 import Oracle, OracleResult
from cryptopals import challenge6
import base64


TEST_DIR = Path(__file__).parent


def test_challenge_17():
    cookies = None
    with open(TEST_DIR / "challenge17.txt", "r") as infile:
        cookies = infile.readlines()
    cookies = [o.strip("\n").encode() for o in cookies]
    key = b"\x01" * 16
    oracle = Oracle(cookies, key)
    assert oracle.check_cookie_padding(oracle.sample_cookie())
    dummy_oracle_result = OracleResult(bytes([1] * 16), bytes([1] * 16))
    assert not oracle.check_cookie_padding(dummy_oracle_result)


def test_challenge_18():
    key = b"YELLOW SUBMARINE"
    nonce = b"\x00" * 8
    ciphertext = base64.b64decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    expected_plaintext = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    scheme = crypto_base.AESCRT(key)
    plaintext = scheme.decrypt(ciphertext, nonce)

    assert plaintext == expected_plaintext


def test_challenge_19():
    # Challenge to be solved by hand
    pass


def test_challenge_20():
    key = b"YELLOW SUBMARINE"
    nonce = b"\x00" * 8
    with open(TEST_DIR / "challenge_20.txt", "r") as file:
        plaintexts = file.readlines()
    plaintexts = [base64.b64decode(line.strip("\n")) for line in plaintexts]
    scheme = crypto_base.AESCRT(key)
    ciphertexts = [scheme.encrypt(plaintext, nonce) for plaintext in plaintexts]
    expected_plaintext = b"".join([plaintext[:48] for plaintext in plaintexts])

    min_length = min([len(ciphertext) for ciphertext in ciphertexts])
    min_length = (min_length // 16) * 16
    ciphertexts = [ciphertext[:min_length] for ciphertext in ciphertexts]
    ciphertext = b"".join(ciphertexts)

    solver = challenge6.Solver()
    plaintext = solver.break_repeating_xor(ciphertext, min_length)
    assert len(plaintext) == len(expected_plaintext)
    num_matches = sum([plaintext[i] == expected_plaintext[i] for i in range(len(plaintext))])
    assert num_matches / len(plaintext) > 0.95
