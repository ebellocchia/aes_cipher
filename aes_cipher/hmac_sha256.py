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
from Crypto.Hash import HMAC, SHA256
from aes_cipher.utils import Utils


#
# Classes
#

# HMAC-SHA256 class
class HmacSha256:

    hmac: HMAC.HMAC

    # Constructor
    def __init__(self,
                 key: Union[str, bytes]) -> None:
        self.hmac = HMAC.new(Utils.Encode(key), digestmod=SHA256)

    # Update HMAC
    def Update(self,
               data: Union[str, bytes]) -> None:
        self.hmac.update(Utils.Encode(data))

    # Update HMAC
    def Verify(self,
               hmac_tbv: bytes) -> bool:
        try:
            self.hmac.verify(hmac_tbv)
            res = True
        except ValueError:
            res = False

        return res

    # Get digest
    def GetDigest(self) -> bytes:
        return self.hmac.digest()

    # Quick compute HMAC digest
    @staticmethod
    def QuickDigest(key: Union[str, bytes],
                    data: Union[str, bytes]) -> bytes:
        hmac = HmacSha256(key)
        hmac.Update(data)

        return hmac.GetDigest()

    # Quick verify HMAC digest
    @staticmethod
    def QuickVerify(key: Union[str, bytes],
                    data: Union[str, bytes],
                    hmac_tbv: bytes) -> bool:
        hmac = HmacSha256(key)
        hmac.Update(data)
        return hmac.Verify(hmac_tbv)

    # Get digest size
    @staticmethod
    def DigestSize() -> int:
        return SHA256.digest_size
