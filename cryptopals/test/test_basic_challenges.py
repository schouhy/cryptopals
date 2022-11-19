import base64
import cryptopals.base as crypto_base
from pathlib import Path

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
    # Load file
    with open(TEST_DIR / "challenge4.txt", "r") as file:
        lines = file.readlines()
    # Strip new line characters and parse hex as bytes
    lines     = list(map(lambda x: x.strip("\n"), lines))
    lines     = list(map(crypto_base.hex_to_bytes, lines))
    # Get the line `candidate` with minimum entropy
    entropies = [(crypto_base.entropy(line), i) for i, line in enumerate(lines)]
    _, candidate = sorted(entropies, key=lambda x: x[0])[0]
    ciphertext = lines[candidate]
    # Decrypt the candidate line using the most english like decryption heuristic
    plaintext = crypto_base.get_most_englishy_single_byte_decryption(ciphertext)
    assert plaintext == message_to_find 

def test_challenge_5():
    message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ciphertext_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    ciphertext = crypto_base.hex_to_bytes(ciphertext_hex)
    scheme = crypto_base.RepeatingXOR(key=b"ICE")
    assert scheme.encrypt(message) == ciphertext

def test_challenge_6():
    # Read ciphertext from file
    ciphertext = crypto_base.load_multiline_base64(TEST_DIR / "challenge6.txt")
    keysize, _ = crypto_base.get_keysize_candidates_entropy(ciphertext)[0]
    assert keysize == 29
    plaintext = crypto_base.break_repeating_xor(ciphertext, keysize=keysize)
    # Load solution
    with open(TEST_DIR / "challenge6_plaintext.txt", "r") as solution_file:
        expected_plaintext = solution_file.readlines()
    expected_plaintext = "".join(expected_plaintext)
    # Assert the expected plaintext and the solution match
    assert plaintext.decode() == expected_plaintext

    








    

    

