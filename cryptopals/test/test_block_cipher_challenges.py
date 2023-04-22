import pytest
import cryptopals.base as crypto_base
from pathlib import Path

from cryptopals.challenge17 import Oracle, OracleResult

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
