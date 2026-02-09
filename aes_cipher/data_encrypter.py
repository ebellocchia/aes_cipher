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

import io
from typing import List, Optional, Tuple, Union

from aes_cipher.aes_cbc_encrypter import AesCbcEncrypter
from aes_cipher.hmac_sha256 import HmacSha256
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.key_iv_generator import KeyIvGenerator
from aes_cipher.loggable_base import LoggableBase
from aes_cipher.pbkdf2_sha512 import Pbkdf2Sha512Default
from aes_cipher.salt_length import SaltLength
from aes_cipher.utils import Utils


class DataEncrypter(LoggableBase):
    """Data encrypter class."""

    encrypted_data: bytes
    key_derivator: IKeyDerivator

    def __init__(self,
                 key_derivator: IKeyDerivator = Pbkdf2Sha512Default) -> None:
        """
        Constructor.

        Args:
            key_derivator: Key derivator instance
        """
        super().__init__()
        self.encrypted_data = b""
        self.key_derivator = key_derivator

    def Encrypt(self,
                data: Union[str, bytes],
                passwords: List[Union[str, bytes]],
                salts: Optional[List[Union[str, bytes]]] = None) -> None:
        """
        Encrypt.

        Args:
            data: Data to encrypt
            passwords: List of passwords for encryption
            salts: Optional list of salts

        Raises:
            ValueError: If number of salts doesn't match number of passwords
        """
        if salts is not None and len(salts) != len(passwords):
            raise ValueError("Number of salts shall be the same of passwords")

        # Initialize current data
        curr_data = Utils.Encode(data)

        # Encrypt multiple times, one for each given password
        for i, password in enumerate(passwords):
            # Generate keys and IVs
            key_iv_gen = KeyIvGenerator(self.key_derivator)
            key_iv_gen.GenerateMaster(password, salts[i] if salts is not None else None)
            key_iv_gen.GenerateInternal()

            # Log
            self.logger.GetLogger().info(f"Encrypting with password: {Utils.DataToString(password)}")
            self.logger.GetLogger().info(f"  Current data: {Utils.DataToString(curr_data)}")

            # Process salt
            salt, salt_enc_len = self.__ProcessSalt(key_iv_gen)
            # Encrypt internal key and IV
            key_iv_encrypted, key_iv_digest = self.__EncryptInternalKeyIv(key_iv_gen)
            # Encrypt data
            data_encrypted, data_digest = self.__EncryptData(curr_data, key_iv_gen)

            # Write to buffer
            data_buffer = io.BytesIO()
            data_buffer.write(salt_enc_len)
            data_buffer.write(salt)
            data_buffer.write(key_iv_encrypted)
            data_buffer.write(key_iv_digest)
            data_buffer.write(data_encrypted)
            data_buffer.write(data_digest)

            # Log
            self.logger.GetLogger().info(f"  Buffer: {Utils.BytesToHexStr(data_buffer.getvalue())}")

            # Update current data
            curr_data = data_buffer.getvalue()

        self.encrypted_data = curr_data

    def GetEncryptedData(self) -> bytes:
        """
        Get encrypted data.

        Returns:
            Encrypted data
        """
        return self.encrypted_data

    def __ProcessSalt(self,
                      key_iv_gen: KeyIvGenerator) -> Tuple[bytes, bytes]:
        """
        Process salt.

        Args:
            key_iv_gen: Key/IV generator instance

        Returns:
            Tuple of (salt, encoded salt length)
        """
        salt = key_iv_gen.GetSalt()
        salt_enc_len = SaltLength.EncodeLength(salt)
        self.logger.GetLogger().info(f"  Salt: {Utils.DataToString(salt)}")
        self.logger.GetLogger().info(f"  Salt encoded length: {Utils.BytesToHexStr(salt_enc_len)}")

        return salt, salt_enc_len

    def __EncryptInternalKeyIv(self,
                               key_iv_gen: KeyIvGenerator) -> Tuple[bytes, bytes]:
        """
        Encrypt internal key and IV.

        Args:
            key_iv_gen: Key/IV generator instance

        Returns:
            Tuple of (encrypted key/IV, digest)
        """
        aes_encrypter = AesCbcEncrypter(key_iv_gen.GetMasterKey(),
                                        key_iv_gen.GetMasterIV())
        aes_encrypter.Encrypt(key_iv_gen.GetInternalKey() + key_iv_gen.GetInternalIV())
        key_iv_encrypted = aes_encrypter.GetEncryptedData()
        key_iv_digest = HmacSha256.QuickDigest(key_iv_gen.GetMasterKey(),
                                               key_iv_gen.GetInternalKey() + key_iv_gen.GetInternalIV())

        self.logger.GetLogger().info(f"  Encrypted internal key/IV: {Utils.BytesToHexStr(key_iv_encrypted)}")
        self.logger.GetLogger().info(f"  Internal key/IV digest: {Utils.BytesToHexStr(key_iv_digest)}")

        return key_iv_encrypted, key_iv_digest

    def __EncryptData(self,
                      data: Union[str, bytes],
                      key_iv_gen: KeyIvGenerator) -> Tuple[bytes, bytes]:
        """
        Encrypt data.

        Args:
            data: Data to encrypt
            key_iv_gen: Key/IV generator instance

        Returns:
            Tuple of (encrypted data, digest)
        """
        aes_encrypter = AesCbcEncrypter(key_iv_gen.GetInternalKey(),
                                        key_iv_gen.GetInternalIV())
        aes_encrypter.Encrypt(data)
        data_encrypted = aes_encrypter.GetEncryptedData()
        data_digest = HmacSha256.QuickDigest(key_iv_gen.GetInternalKey(), data)

        self.logger.GetLogger().info(f"  Encrypted data: {Utils.BytesToHexStr(data_encrypted)}")
        self.logger.GetLogger().info(f"  Data digest: {Utils.BytesToHexStr(data_digest)}")

        return data_encrypted, data_digest
