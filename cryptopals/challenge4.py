import cryptopals.base as crypto_base

class Solver:
    def __init__(self, filepath):
        with open(filepath, "r") as file:
            lines = file.readlines()
        # Strip new line characters and parse hex as bytes
        lines     = list(map(lambda x: x.strip("\n"), lines))
        lines     = list(map(crypto_base.hex_to_bytes, lines))
        self._lines = lines

    def solve(self):
        # Get the line `candidate` with minimum entropy
        entropies = [(crypto_base.entropy(line), i) for i, line in enumerate(self._lines)]
        _, candidate = sorted(entropies, key=lambda x: x[0])[0]
        ciphertext = self._lines[candidate]
        # Decrypt the candidate line using the most english like decryption heuristic
        return crypto_base.get_most_englishy_single_byte_decryption(ciphertext)

