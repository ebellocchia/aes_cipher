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

from typing import List, Optional, Union

from aes_cipher.data_encrypter import DataEncrypter
from aes_cipher.file_reader import FileReader
from aes_cipher.file_writer import FileWriter
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.logger import Logger
from aes_cipher.pbkdf2_sha512 import Pbkdf2Sha512Default


class FileEncrypter:
    """File encrypter class."""

    encrypter: DataEncrypter

    def __init__(self,
                 key_derivator: IKeyDerivator = Pbkdf2Sha512Default) -> None:
        """
        Constructor.

        Args:
            key_derivator: Key derivator instance
        """
        self.encrypter = DataEncrypter(key_derivator)

    def Logger(self) -> Logger:
        """
        Get logger.

        Returns:
            Logger instance
        """
        return self.encrypter.Logger()

    def Encrypt(self,
                file_in: str,
                passwords: List[Union[str, bytes]],
                salts: Optional[List[Union[str, bytes]]] = None) -> None:
        """
        Encrypt.

        Args:
            file_in: Input file path
            passwords: List of passwords for encryption
            salts: Optional list of salts
        """
        file_data = FileReader.Read(file_in)
        self.encrypter.Encrypt(file_data, passwords, salts)

    def GetEncryptedData(self) -> bytes:
        """
        Get encrypted data.

        Returns:
            Encrypted data
        """
        return self.encrypter.GetEncryptedData()

    def SaveTo(self,
               file_out: str) -> None:
        """
        Save to file.

        Args:
            file_out: Output file path
        """
        FileWriter.Write(file_out, self.GetEncryptedData())
