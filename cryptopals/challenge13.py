import cryptopals.base as crypto_base


class Oracle:
    def __init__(self):
        self._scheme = crypto_base.AESECB(key=crypto_base.sample_random_bytes(16))

    @staticmethod
    def parse_dictionary(s: bytes):
        return dict(keyvalue.split("=") for keyvalue in s.decode().split("&"))

    @staticmethod
    def profile_for(email: bytes):
        if b"=" in email or b"&" in email:
            raise ValueError("email cannot contain & or =")
        return b"email=" + email + b"&uid=10&role=user"

    def make_profile(self, email):
        return self._scheme.encrypt(self.profile_for(email))

    def read_profile(self, ciphertext):
        return self.parse_dictionary(self._scheme.decrypt(ciphertext))


def get_oracle_block_size(func):
    m = len(func(b""))
    i = 1
    M = len(func(b"A" * i))
    while m == M:
        i += 1
        M = len(func(b"A" * i))
    return M - m


def forge_admin_user(oracle_make_profile_function):
    assert get_oracle_block_size(oracle_make_profile_function) == 16
    # Compute first blocks having "...&user=" block aligned so as to append a block corresponding
    # to the "admin||padding" after it.
    length1 = len(b"email=&uid=10&user=")
    offset = (-length1) % 16
    stem = oracle_make_profile_function(b"A" * offset)[:-16]
    # Have the oracle encrypt the block "admin||padding" as the second block of a
    # two block sized email address
    length2 = 16 - len(b"email=")
    admin_block = oracle_make_profile_function(
        b"A" * length2 + crypto_base.pkcs7_pad(b"admin", 16)
    )[16:32]
    return stem + admin_block
