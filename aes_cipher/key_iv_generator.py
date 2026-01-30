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

import os
from typing import Optional, Union

from aes_cipher.aes_const import AesConst
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.utils import Utils


class KeyIvGeneratorConst:
    """Constants for Key and IV generator class."""

    SALT_DEF_SIZE: int = 16


class KeyIvGenerator:
    """Key and IV generator class."""

    key_derivator: IKeyDerivator
    internal_key: bytes
    internal_iv: bytes
    master_key: bytes
    master_iv: bytes
    salt: bytes

    def __init__(self,
                 key_derivator: IKeyDerivator) -> None:
        """Constructor.

        Args:
            key_derivator: Key derivator instance
        """
        self.key_derivator = key_derivator
        self.internal_key = b""
        self.internal_iv = b""
        self.master_key = b""
        self.master_iv = b""
        self.bytes = b""

    def GenerateMaster(self,
                       password: Union[str, bytes],
                       salt: Optional[Union[str, bytes]] = None) -> None:
        """Generate master key and IV from password.

        Args:
            password: Password for key derivation
            salt: Optional salt (generated if not provided)
        """
        self.salt = Utils.Encode(salt) if salt is not None else os.urandom(KeyIvGeneratorConst.SALT_DEF_SIZE)

        der_key = self.key_derivator.DeriveKey(password, self.salt)
        self.master_key = der_key[: AesConst.KeySize()]
        self.master_iv = der_key[AesConst.KeySize() : AesConst.KeySize() + AesConst.IvSize()]

    def GenerateInternal(self) -> None:
        """Generate internal key and IV."""
        self.internal_key = os.urandom(AesConst.KeySize())
        self.internal_iv = os.urandom(AesConst.IvSize())

    def GetMasterKey(self) -> bytes:
        """Get master key.

        Returns:
            Master key
        """
        return self.master_key

    def GetMasterIV(self) -> bytes:
        """Get master IV.

        Returns:
            Master IV
        """
        return self.master_iv

    def GetInternalKey(self) -> bytes:
        """Get internal key.

        Returns:
            Internal key
        """
        return self.internal_key

    def GetInternalIV(self) -> bytes:
        """Get internal IV.

        Returns:
            Internal IV
        """
        return self.internal_iv

    def GetSalt(self) -> bytes:
        """Get salt.

        Returns:
            Salt
        """
        return self.salt
