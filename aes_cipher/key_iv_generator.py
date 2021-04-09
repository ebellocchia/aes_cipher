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
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from aes_cipher.aes_const import AesConst
from aes_cipher.pbkdf2_sha512 import Pbkdf2Sha512
from aes_cipher.utils import Utils


#
# Classes
#

# Constants for Key and IV generator class
class KeyIvGeneratorConst:
    ITR_NUM = 524288
    DEF_SALT = b"[]=?AeS_CiPhEr><()"
    KEY_LEN = AesConst.BlockSize() * 2
    IV_LEN = AesConst.BlockSize()


# Key and IV generator class
class KeyIvGenerator:
    # Constructor
    def __init__(self):
        self.master_key = b""
        self.master_iv = b""
        self.internal_key = b""
        self.internal_iv = b""

    # Generate master key and IV from password
    def GenerateMaster(self, password, salt, itr_num):
        salt = KeyIvGeneratorConst.DEF_SALT if salt is None else salt
        itr_num = KeyIvGeneratorConst.ITR_NUM if itr_num is None else itr_num
        password = Utils.Encode(password)

        # Compute master key and IV from PBKDF2-SHA512
        kdf = Pbkdf2Sha512.Compute(password, salt, itr_num)
        self.master_key = kdf[:KeyIvGeneratorConst.KEY_LEN]
        self.master_iv = kdf[KeyIvGeneratorConst.KEY_LEN:KeyIvGeneratorConst.KEY_LEN + KeyIvGeneratorConst.IV_LEN]

    # Generate internal key and IV
    def GenerateInternal(self):
        # Compute internal key and IV
        self.internal_key = os.urandom(KeyIvGeneratorConst.KEY_LEN)
        self.internal_iv = os.urandom(KeyIvGeneratorConst.IV_LEN)

    # Get master key
    def GetMasterKey(self):
        return self.master_key

    # Get master IV
    def GetMasterIV(self):
        return self.master_iv

    # Get internal key
    def GetInternalKey(self):
        return self.internal_key

    # Get internal IV
    def GetInternalIV(self):
        return self.internal_iv
