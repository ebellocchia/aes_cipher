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

from typing import List, Tuple, Union

from aes_cipher.aes_cbc_decrypter import AesCbcDecrypter
from aes_cipher.aes_const import AesConst
from aes_cipher.data_ex import DataDecryptError, DataHmacError
from aes_cipher.hmac_sha256 import HmacSha256
from aes_cipher.ikey_derivator import IKeyDerivator
from aes_cipher.key_iv_generator import KeyIvGenerator
from aes_cipher.loggable_base import LoggableBase
from aes_cipher.pbkdf2_sha512 import Pbkdf2Sha512Default
from aes_cipher.salt_length import SaltLength
from aes_cipher.utils import Utils


class DataDecrypterConst:
    """Constants for data decrypter."""

    SALT_LEN_OFF: int = 0
    SALT_OFF: int = SaltLength.EncodedLengthSize()

    INT_KEY_OFF: int = 0
    INT_IV_OFF: int = AesConst.KeySize()
    INT_KEY_IV_PAD_OFF: int = AesConst.KeySize() + AesConst.IvSize()
    INT_KEY_IV_DIG_OFF: int = AesConst.KeySize() + AesConst.IvSize() + AesConst.PadSize()

    DATA_ENC_OFF: int = AesConst.KeySize() + AesConst.IvSize() + AesConst.PadSize() + HmacSha256.DigestSize()
    DATA_DIG_OFF: int = -1 * HmacSha256.DigestSize()


class DataDecrypter(LoggableBase):
    """Data decrypter class."""

    decrypted_data: bytes
    key_derivator: IKeyDerivator

    def __init__(self,
                 key_derivator: IKeyDerivator = Pbkdf2Sha512Default) -> None:
        """
        Constructor.

        Args:
            key_derivator: Key derivator instance
        """
        super().__init__()
        self.decrypted_data = b""
        self.key_derivator = key_derivator

    def Decrypt(self,
                data: bytes,
                passwords: List[Union[str, bytes]]) -> None:
        """
        Decrypt.

        Args:
            data: Data to decrypt
            passwords: List of passwords for decryption

        Raises:
            DataDecryptError: If decryption fails
        """
        # Initialize current data
        curr_data = data

        # Decrypt multiple times, one for each given password in reverse order
        for password in reversed(passwords):
            # Log
            self.logger.GetLogger().info(f"Decrypting with password: {Utils.DataToString(password)}")
            self.logger.GetLogger().info(f"  Current data: {Utils.BytesToHexStr(curr_data)}")

            # Get salt
            try:
                salt = self.__ReadSalt(curr_data)
            except IndexError as ex:
                raise DataDecryptError("Unable to decrypt file (cannot read salt)") from ex

            # Generate keys and IVs
            key_iv_gen = KeyIvGenerator(self.key_derivator)
            key_iv_gen.GenerateMaster(password, salt)

            try:
                data_without_salt = curr_data[DataDecrypterConst.SALT_OFF + len(salt) :]
                # Read internal key and IV
                internal_key, internal_iv = self.__ReadInternalKeyIv(data_without_salt, key_iv_gen)
                # Read data
                curr_data = self.__ReadData(data_without_salt, internal_key, internal_iv)
            except (IndexError, ValueError) as ex:
                raise DataDecryptError("Unable to decrypt file") from ex

        self.decrypted_data = curr_data

    def GetDecryptedData(self) -> bytes:
        """
        Get decrypted data.

        Returns:
            Decrypted data
        """
        return self.decrypted_data

    def __ReadSalt(self,
                   data: bytes) -> bytes:
        """
        Read salt.

        Args:
            data: Data to read salt from

        Returns:
            Salt bytes
        """
        salt_len = SaltLength.DecodeLength(data[DataDecrypterConst.SALT_LEN_OFF : DataDecrypterConst.SALT_OFF])
        salt = data[DataDecrypterConst.SALT_OFF : DataDecrypterConst.SALT_OFF + salt_len]
        self.logger.GetLogger().info(f"  Salt: {Utils.BytesToHexStr(salt)}")
        self.logger.GetLogger().info(f"  Salt length: {salt_len}")

        return salt

    def __ReadInternalKeyIv(self,
                            data: bytes,
                            key_iv_gen: KeyIvGenerator) -> Tuple[bytes, bytes]:
        """
        Read internal key and IV.

        Args:
            data: Data to read from
            key_iv_gen: Key/IV generator instance

        Returns:
            Tuple of (internal key, internal IV)

        Raises:
            DataHmacError: If HMAC verification fails
        """
        key_iv_encrypted = data[DataDecrypterConst.INT_KEY_OFF : DataDecrypterConst.INT_KEY_IV_DIG_OFF]
        key_iv_digest = data[DataDecrypterConst.INT_KEY_IV_DIG_OFF : DataDecrypterConst.DATA_ENC_OFF]

        self.logger.GetLogger().info(f"  Encrypted internal key/IV: {Utils.BytesToHexStr(key_iv_encrypted)}")
        self.logger.GetLogger().info(f"  Internal key/IV digest: {Utils.BytesToHexStr(key_iv_digest)}")

        aes_decrypter = AesCbcDecrypter(key_iv_gen.GetMasterKey(), key_iv_gen.GetMasterIV())
        aes_decrypter.Decrypt(key_iv_encrypted)
        key_iv_decrypted = aes_decrypter.GetDecryptedData()
        if not HmacSha256.QuickVerify(key_iv_gen.GetMasterKey(), key_iv_decrypted, key_iv_digest):
            raise DataHmacError("Invalid HMAC for internal key and IV")

        return (
            key_iv_decrypted[DataDecrypterConst.INT_KEY_OFF : DataDecrypterConst.INT_IV_OFF],
            key_iv_decrypted[DataDecrypterConst.INT_IV_OFF : DataDecrypterConst.INT_KEY_IV_PAD_OFF],
        )

    def __ReadData(self,
                   data: bytes,
                   internal_key: bytes,
                   internal_iv: bytes) -> bytes:
        """
        Read data.

        Args:
            data: Data to read from
            internal_key: Internal key for decryption
            internal_iv: Internal IV for decryption

        Returns:
            Decrypted data

        Raises:
            DataHmacError: If HMAC verification fails
        """
        data_encrypted = data[DataDecrypterConst.DATA_ENC_OFF : DataDecrypterConst.DATA_DIG_OFF]
        data_digest = data[DataDecrypterConst.DATA_DIG_OFF :]

        self.logger.GetLogger().info(f"  Encrypted data: {Utils.BytesToHexStr(data_encrypted)}")
        self.logger.GetLogger().info(f"  Data digest: {Utils.BytesToHexStr(data_digest)}")

        aes_decrypter = AesCbcDecrypter(internal_key, internal_iv)
        aes_decrypter.Decrypt(data_encrypted)
        data_decrypted = aes_decrypter.GetDecryptedData()
        if not HmacSha256.QuickVerify(internal_key, data_decrypted, data_digest):
            raise DataHmacError("Invalid HMAC for data")

        self.logger.GetLogger().info(f"  Decrypted data: {Utils.BytesToHexStr(data_decrypted)}")

        return data_decrypted
