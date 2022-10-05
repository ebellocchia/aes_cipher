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

#
# Imports
#
from typing import Union

from Crypto.Protocol.KDF import scrypt

from aes_cipher.aes_const import AesConst
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.utils import Utils


#
# Classes
#

# Scrypt class
class Scrypt(IKeyDerivator):

    n: int
    r: int
    p: int

    # Constructor
    def __init__(self,
                 n: int,
                 r: int,
                 p: int) -> None:
        if n <= 0 or r <= 0 or p <= 0:
            raise ValueError(f"Invalid scrypt parameters ({n}, {r}, {p})")
        self.n = n
        self.r = r
        self.p = p

    # Derive key
    def DeriveKey(self,
                  password: Union[str, bytes],
                  salt: Union[str, bytes]) -> bytes:
        return scrypt(
            Utils.Decode(password),     # type: ignore
            Utils.Encode(salt),         # type: ignore
            key_len=AesConst.KeySize() + AesConst.IvSize(),
            N=self.n,
            r=self.r,
            p=self.p
        )


# Default class
ScryptDefault = Scrypt(16384, 8, 8)
