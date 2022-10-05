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
import io
from typing import List, Optional, Tuple, Union

from aes_cipher.aes_cbc_encrypter import AesCbcEncrypter
from aes_cipher.hmac_sha256 import HmacSha256
from aes_cipher.key_iv_generator import KeyIvGenerator
from aes_cipher.loggable_base import LoggableBase
from aes_cipher.utils import Utils


#
# Classes
#

# Data encrypter class
class DataEncrypter(LoggableBase):

    encrypted_data: bytes

    # Constructor
    def __init__(self) -> None:
        super().__init__()
        self.encrypted_data = b""

    # Encrypt
    def Encrypt(self,
                data: Union[str, bytes],
                passwords: List[Union[str, bytes]],
                salt: Optional[Union[str, bytes]] = None,
                itr_num: Optional[int] = None) -> None:
        # Log
        if salt is not None:
            self.logger.GetLogger().info(f"Salt: {Utils.DataToString(salt)}")

        # Initialize current data
        curr_data = Utils.Encode(data)

        # Encrypt multiple times, one for each given password
        for password in passwords:
            # Log
            self.logger.GetLogger().info(f"Encrypting with password: {Utils.DataToString(password)}")
            self.logger.GetLogger().info(f"  Current data: {Utils.DataToString(curr_data)}")

            # Generate keys and IVs
            key_iv_gen = KeyIvGenerator()
            key_iv_gen.GenerateMaster(password, salt, itr_num)
            key_iv_gen.GenerateInternal()

            # Process internal key and IV
            key_iv_encrypted, key_iv_digest = self.__ProcessInternalKeyIv(key_iv_gen)
            # Process data
            data_encrypted, data_digest = self.__ProcessData(curr_data, key_iv_gen)

            # Write to buffer
            data_buffer = io.BytesIO()
            data_buffer.write(key_iv_encrypted)
            data_buffer.write(key_iv_digest)
            data_buffer.write(data_encrypted)
            data_buffer.write(data_digest)

            # Log
            self.logger.GetLogger().info(f"  Buffer: {Utils.BytesToHexStr(data_buffer.getvalue())}")

            # Update current data
            curr_data = data_buffer.getvalue()

        self.encrypted_data = curr_data

    # Get encrypted data
    def GetEncryptedData(self) -> bytes:
        return self.encrypted_data

    # Process internal key and IV
    def __ProcessInternalKeyIv(self,
                               key_iv_gen: KeyIvGenerator) -> Tuple[bytes, bytes]:
        # Encrypt internal key and IV with master key and IV
        aes_encrypter = AesCbcEncrypter(key_iv_gen.GetMasterKey(), key_iv_gen.GetMasterIV())
        aes_encrypter.Encrypt(key_iv_gen.GetInternalKey() + key_iv_gen.GetInternalIV())
        key_iv_encrypted = aes_encrypter.GetEncryptedData()
        # Compute their digest
        key_iv_digest = HmacSha256.QuickDigest(key_iv_gen.GetMasterKey(),
                                               key_iv_gen.GetInternalKey() + key_iv_gen.GetInternalIV())

        # Log
        self.logger.GetLogger().info(f"  Encrypted internal key/IV: {Utils.BytesToHexStr(key_iv_encrypted)}")
        self.logger.GetLogger().info(f"  Internal key/IV digest: {Utils.BytesToHexStr(key_iv_digest)}")

        return key_iv_encrypted, key_iv_digest

    # Process data
    def __ProcessData(self,
                      data: Union[str, bytes],
                      key_iv_gen: KeyIvGenerator) -> Tuple[bytes, bytes]:
        # Encrypt data with internal key and IV
        aes_encrypter = AesCbcEncrypter(key_iv_gen.GetInternalKey(), key_iv_gen.GetInternalIV())
        aes_encrypter.Encrypt(data)
        data_encrypted = aes_encrypter.GetEncryptedData()
        # Compute its digest
        data_digest = HmacSha256.QuickDigest(key_iv_gen.GetInternalKey(), data)

        # Log
        self.logger.GetLogger().info(f"  Encrypted data: {Utils.BytesToHexStr(data_encrypted)}")
        self.logger.GetLogger().info(f"  Data digest: {Utils.BytesToHexStr(data_digest)}")

        return data_encrypted, data_digest
