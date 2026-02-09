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

from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2

from aes_cipher.aes_const import AesConst
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.utils import Utils


class Pbkdf2Sha512(IKeyDerivator):
    """PBKDF2-SHA512 class."""

    itr_num: int

    def __init__(self,
                 itr_num: int) -> None:
        """
        Constructor.

        Args:
            itr_num: Number of iterations

        Raises:
            ValueError: If iteration number is invalid
        """
        if itr_num <= 0:
            raise ValueError(f"Invalid iteration number ({itr_num})")
        self.itr_num = itr_num

    def DeriveKey(self,
                  password: Union[str, bytes],
                  salt: Union[str, bytes]) -> bytes:
        """
        Derive key.

        Args:
            password: Password for key derivation
            salt: Salt for key derivation

        Returns:
            Derived key
        """
        return PBKDF2(
            Utils.Decode(password),
            Utils.Encode(salt),
            AesConst.KeySize() + AesConst.IvSize(),
            self.itr_num,
            hmac_hash_module=SHA512,
        )


Pbkdf2Sha512Default = Pbkdf2Sha512(512 * 1024)
