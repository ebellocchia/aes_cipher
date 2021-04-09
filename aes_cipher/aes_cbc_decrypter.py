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
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from aes_cipher.aes_const import AesConst
from aes_cipher.utils import Utils


#
# Classes
#

# AES-CBC decrypter class
class AesCbcDecrypter:
    # Constructor
    def __init__(self, key, iv):
        self.decrypted_data = ""
        self.aes = AES.new(Utils.Encode(key), AES.MODE_CBC, iv=iv)

    # Decrypt data
    def Decrypt(self, data):
        self.decrypted_data = self.UnPad(self.aes.decrypt(data))

    # Get decrypted data
    def GetDecryptedData(self):
        return self.decrypted_data

    # Unpad data
    @staticmethod
    def UnPad(data):
        return unpad(Utils.Encode(data), AesConst.BlockSize())
