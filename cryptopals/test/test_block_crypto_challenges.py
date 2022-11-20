import cryptopals.base as crypto_base


def test_challenge_9():
    plaintext = b"YELLOW SUBMARINE"
    expectd_padded_plaintext = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    assert crypto_base.pkcs7_padding(plaintext, 20) == expectd_padded_plaintext
