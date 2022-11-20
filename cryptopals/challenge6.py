import cryptopals.base as crypto_base
import numpy as np

class Solver:
    def __init__(self, filepath):
        self._ciphertext = crypto_base.load_multiline_base64(filepath)

    def solve(self):
        keysize, _ = self.get_keysize_candidates_entropy(self._ciphertext)[0]
        return self.break_repeating_xor(self._ciphertext, keysize=keysize)

    @staticmethod
    def break_repeating_xor(s, keysize):
        cipher_chunks = [s[i : : keysize] for i in range(keysize)]
        text_chunks = [crypto_base.get_most_englishy_single_byte_decryption(chunk).decode() for chunk in cipher_chunks]
        return "".join(["".join(t) for t in zip(*text_chunks)]).encode()

    @staticmethod
    def get_keysize_candidates_normalized_hamming(s, min_size=2, max_size=40):
        nahd = []
        for keysize in range(min_size, max_size + 1):
            i = 0
            accum = []
            while i + 2*keysize < len(s):
                s1 = s[i: i + keysize]
                s2 = s[i + keysize: i + 2 * keysize]

                accum.append(hamming_distance(s1, s2) / keysize)
                i += keysize

            if len(accum) > 0:
                nahd.append((keysize, sum(accum) / len(accum)))

        return sorted(nahd, key = lambda x: x[1])

    @staticmethod
    def get_keysize_candidates_entropy(s, min_size=2, max_size=40):
        average_entropy = []
        for keysize in range(min_size, max_size + 1):
            m = np.array(([crypto_base.entropy(s[i::keysize]) for i in range(keysize)])).mean()
            average_entropy.append((keysize, m))
        return sorted(average_entropy, key = lambda x: x[1])

