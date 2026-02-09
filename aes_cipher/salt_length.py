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


class SaltLengthConst:
    """Constant for salt length class."""

    SALT_LEN_SIZE: int = 4


class SaltLength:
    """Salt length class."""

    @staticmethod
    def EncodedLengthSize() -> int:
        """
        Get encoded length size.

        Returns:
            Encoded length size in bytes
        """
        return SaltLengthConst.SALT_LEN_SIZE

    @staticmethod
    def DecodeLength(salt_len_bytes: bytes) -> int:
        """
        Decode length.

        Args:
            salt_len_bytes: Salt length bytes

        Returns:
            Decoded salt length
        """
        return int.from_bytes(salt_len_bytes, "big")

    @staticmethod
    def EncodeLength(salt: bytes) -> bytes:
        """
        Encode length.

        Args:
            salt: Salt bytes

        Returns:
            Encoded salt length
        """
        return len(salt).to_bytes(SaltLengthConst.SALT_LEN_SIZE, "big")
