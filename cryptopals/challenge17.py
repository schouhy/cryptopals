from collections import namedtuple
import cryptopals.base as crypto_base
import random
from pathlib import Path
from typing import List

DIR = Path(__file__).parent

OracleResult = namedtuple("OracleResult", ["cookie", "iv"])


class Oracle:
    def __init__(self, cookies_list: List[bytes], key=None) -> None:
        key = key or crypto_base.sample_random_bytes(size=16)
        self._list = cookies_list.copy()
        self._scheme = crypto_base.AESCBC(key=key)

    def sample_cookie(self) -> bytes:
        cookie = random.choice(self._list)
        iv = crypto_base.sample_random_bytes(16)
        cookie = crypto_base.pkcs7_pad(cookie, block_size=16)
        return OracleResult(cookie=self._scheme.encrypt(cookie, iv)[0], iv=iv)

    def check_cookie_padding(self, cookie_cipher: OracleResult) -> bytes:
        try:
            self._scheme.decrypt(cookie_cipher.cookie, cookie_cipher.iv)
            return True
        except crypto_base.BadPadding:
            return False
