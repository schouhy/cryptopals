import cryptopals.base as crypto_base
from pathlib import Path

from cryptopals.challenge17 import Oracle, OracleResult
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
    nonce = bytes([0] * 8)
    ciphertext = base64.b64decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    expected_plaintext = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    scheme = crypto_base.AESCRT(key)
    plaintext = scheme.decrypt(ciphertext, nonce)

    assert plaintext == expected_plaintext
