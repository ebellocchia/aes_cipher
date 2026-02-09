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

from Crypto.Hash import HMAC, SHA256

from aes_cipher.utils import Utils


class HmacSha256:
    """HMAC-SHA256 class."""

    hmac: HMAC.HMAC

    def __init__(self,
                 key: Union[str, bytes]) -> None:
        """
        Constructor.

        Args:
            key: HMAC key
        """
        self.hmac = HMAC.new(Utils.Encode(key), digestmod=SHA256)

    def Update(self,
               data: Union[str, bytes]) -> None:
        """
        Update HMAC.

        Args:
            data: Data to update HMAC with
        """
        self.hmac.update(Utils.Encode(data))

    def Verify(self,
               hmac_tbv: bytes) -> bool:
        """
        Verify HMAC.

        Args:
            hmac_tbv: HMAC to be verified

        Returns:
            True if valid, False otherwise
        """
        try:
            self.hmac.verify(hmac_tbv)
            res = True
        except ValueError:
            res = False

        return res

    def GetDigest(self) -> bytes:
        """
        Get digest.

        Returns:
            HMAC digest
        """
        return self.hmac.digest()

    @staticmethod
    def QuickDigest(key: Union[str, bytes],
                    data: Union[str, bytes]) -> bytes:
        """
        Quick compute HMAC digest.

        Args:
            key: HMAC key
            data: Data to compute HMAC for

        Returns:
            HMAC digest
        """
        hmac = HmacSha256(key)
        hmac.Update(data)

        return hmac.GetDigest()

    @staticmethod
    def QuickVerify(key: Union[str, bytes],
                    data: Union[str, bytes],
                    hmac_tbv: bytes) -> bool:
        """
        Quick verify HMAC digest.

        Args:
            key: HMAC key
            data: Data to verify HMAC for
            hmac_tbv: HMAC to be verified

        Returns:
            True if valid, False otherwise
        """
        hmac = HmacSha256(key)
        hmac.Update(data)
        return hmac.Verify(hmac_tbv)

    @staticmethod
    def DigestSize() -> int:
        """
        Get digest size.

        Returns:
            Digest size in bytes
        """
        return SHA256.digest_size
