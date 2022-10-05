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
import os
from typing import Optional, Union

from aes_cipher.aes_const import AesConst
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.utils import Utils


#
# Classes
#

# Constants for Key and IV generator class
class KeyIvGeneratorConst:
    # Default salt size
    SALT_DEF_SIZE: int = 16


# Key and IV generator class
class KeyIvGenerator:

    key_derivator: IKeyDerivator
    internal_key: bytes
    internal_iv: bytes
    master_key: bytes
    master_iv: bytes
    salt: bytes

    # Constructor
    def __init__(self,
                 key_derivator: IKeyDerivator) -> None:
        self.key_derivator = key_derivator
        self.internal_key = b""
        self.internal_iv = b""
        self.master_key = b""
        self.master_iv = b""
        self.bytes = b""

    # Generate master key and IV from password
    def GenerateMaster(self,
                       password: Union[str, bytes],
                       salt: Optional[Union[str, bytes]] = None) -> None:
        # Generate salt if needed
        self.salt = Utils.Encode(salt) if salt is not None else os.urandom(KeyIvGeneratorConst.SALT_DEF_SIZE)

        # Compute master key and IV
        der_key = self.key_derivator.DeriveKey(password, self.salt)
        self.master_key = der_key[:AesConst.KeySize()]
        self.master_iv = der_key[AesConst.KeySize(): AesConst.KeySize() + AesConst.IvSize()]

    # Generate internal key and IV
    def GenerateInternal(self) -> None:
        # Generate random internal key and IV
        self.internal_key = os.urandom(AesConst.KeySize())
        self.internal_iv = os.urandom(AesConst.IvSize())

    # Get master key
    def GetMasterKey(self) -> bytes:
        return self.master_key

    # Get master IV
    def GetMasterIV(self) -> bytes:
        return self.master_iv

    # Get internal key
    def GetInternalKey(self) -> bytes:
        return self.internal_key

    # Get internal IV
    def GetInternalIV(self) -> bytes:
        return self.internal_iv

    def GetSalt(self) -> bytes:
        return self.salt
