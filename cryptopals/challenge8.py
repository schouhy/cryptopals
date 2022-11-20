import cryptopals.base as crypto_base

class Solver:
    def __init__(self, filepath):
        # Load file
        with open(filepath) as file:
            lines = file.readlines()
        self._lines = [crypto_base.hex_to_bytes(line.strip("\n")) for line in lines]

    def solve(self):
        # Find the line encrypted with ECB as the one with less entropy
        entropies = [(crypto_base.entropy(line), i) for i, line in enumerate(self._lines)]
        _, argmin = sorted(entropies, key=lambda x: x[0])[0]
        return self._lines[argmin].hex()

