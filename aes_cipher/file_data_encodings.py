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
import base64
from enum import Enum, auto, unique
from aes_cipher.file_ex import FileEncodingError
from aes_cipher.utils import Utils


#
# Classes
#

# File data encodings
@unique
class FileDataEncodings(Enum):
    BINARY = auto(),
    BASE64 = auto(),


# File data encoder class
class FileDataEncoder:
    # Encode data
    @staticmethod
    def EncodeData(data, data_encoding):
        if data_encoding == FileDataEncodings.BINARY:
            return Utils.Encode(data)
        elif data_encoding == FileDataEncodings.BASE64:
            return Utils.Base64Encode(data)
        else:
            raise FileEncodingError("Invalid data format")
