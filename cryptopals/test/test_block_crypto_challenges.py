import base64
import cryptopals.base as crypto_base


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
    pass
    

    

