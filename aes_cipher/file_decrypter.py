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
from typing import List, Optional, Union
from aes_cipher.data_decrypter import DataDecrypter
from aes_cipher.file_reader import FileReader
from aes_cipher.file_writer import FileWriter
from aes_cipher.logger import Logger


#
# Classes
#

# File decrypter class
class FileDecrypter:

    decrypter: DataDecrypter

    # Constructor
    def __init__(self,
                 logger: Logger = Logger()) -> None:
        self.decrypter = DataDecrypter(logger)

    # Decrypt
    def Decrypt(self,
                file_in: str,
                passwords: List[Union[str, bytes]],
                salt: Optional[Union[str, bytes]] = None,
                itr_num: Optional[int] = None) -> None:
        # Read file
        file_data = FileReader.Read(file_in)
        # Decrypt it
        self.decrypter.Decrypt(file_data, passwords, salt, itr_num)

    # Get decrypted data
    def GetDecryptedData(self) -> bytes:
        return self.decrypter.GetDecryptedData()

    # Save to file
    def SaveTo(self,
               file_out: str) -> None:
        FileWriter.Write(file_out, self.GetDecryptedData())
