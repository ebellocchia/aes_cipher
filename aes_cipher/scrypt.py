# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from typing import Union

from Crypto.Protocol.KDF import scrypt

from aes_cipher.aes_const import AesConst
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.utils import Utils


class Scrypt(IKeyDerivator):
    """Scrypt class."""

    n: int
    r: int
    p: int

    def __init__(self,
                 n: int,
                 r: int,
                 p: int) -> None:
        """Constructor.

        Args:
            n: CPU/memory cost parameter
            r: Block size parameter
            p: Parallelization parameter

        Raises:
            ValueError: If scrypt parameters are invalid
        """
        if n <= 0 or r <= 0 or p <= 0:
            raise ValueError(f"Invalid scrypt parameters ({n}, {r}, {p})")
        self.n = n
        self.r = r
        self.p = p

    def DeriveKey(self,
                  password: Union[str, bytes],
                  salt: Union[str, bytes]) -> bytes:
        """Derive key.

        Args:
            password: Password for key derivation
            salt: Salt for key derivation

        Returns:
            Derived key
        """
        return scrypt(
            Utils.Decode(password),  # type: ignore
            Utils.Encode(salt),  # type: ignore
            key_len=AesConst.KeySize() + AesConst.IvSize(),
            N=self.n,
            r=self.r,
            p=self.p,
        )


ScryptDefault = Scrypt(16384, 8, 8)
