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

import argparse
import logging
import sys
from enum import Enum, auto, unique
from pathlib import Path
from typing import Any, Dict, List, Tuple

from aes_cipher import DataDecryptError, DataHmacError, FileDecrypter, FileEncrypter, Pbkdf2Sha512


@unique
class ArgumentTypes(Enum):
    """Argument types."""

    MODE = auto()
    PASSWORDS = auto()
    INPUT_PATHS = auto()
    OUTPUT_PATH = auto()
    SALT = auto()
    ITR_NUM = auto()
    VERBOSE = auto()


class Arguments:
    """Arguments."""

    MODES: Tuple[str, str] = ("dec", "enc")

    args_val: Dict[ArgumentTypes, Any]

    def __init__(self) -> None:
        """Constructor."""
        self.Reset()

    def GetValue(self,
                 arg_type: ArgumentTypes) -> Any:
        """Get argument value.

        Args:
            arg_type: Argument type

        Returns:
            Argument value

        Raises:
            TypeError: If argument type is invalid
        """
        if not isinstance(arg_type, ArgumentTypes):
            raise TypeError("Invalid argument type")
        return self.args_val[arg_type]

    def SetValue(self,
                 value: Any,
                 arg_type: ArgumentTypes) -> None:
        """Set argument value.

        Args:
            value: Value to set
            arg_type: Argument type

        Raises:
            TypeError: If argument type is invalid
        """
        if not isinstance(arg_type, ArgumentTypes):
            raise TypeError("Invalid argument type")
        self.args_val[arg_type] = value

    def IsVerbose(self) -> bool:
        """Get if verbose.

        Returns:
            True if verbose mode is enabled
        """
        return self.GetValue(ArgumentTypes.VERBOSE)

    def IsDecryptMode(self) -> bool:
        """Get if decrypt mode.

        Returns:
            True if in decrypt mode
        """
        return self.GetValue(ArgumentTypes.MODE) == self.MODES[0]

    def IsEncryptMode(self) -> bool:
        """Get if encrypt mode.

        Returns:
            True if in encrypt mode
        """
        return self.GetValue(ArgumentTypes.MODE) == self.MODES[1]

    def Reset(self) -> None:
        """Reset."""
        self.args_val = {
            ArgumentTypes.MODE: "",
            ArgumentTypes.PASSWORDS: "",
            ArgumentTypes.INPUT_PATHS: None,
            ArgumentTypes.OUTPUT_PATH: None,
            ArgumentTypes.SALT: None,
            ArgumentTypes.ITR_NUM: None,
            ArgumentTypes.VERBOSE: False,
        }


class ArgumentsParser:
    """Argument parser."""

    parser: argparse.ArgumentParser

    def __init__(self) -> None:
        """Constructor."""
        self.parser = argparse.ArgumentParser()
        required = self.parser.add_argument_group("required arguments")
        optional = self.parser.add_argument_group("optional arguments")
        required.add_argument(
            "-m", "--mode",
            choices=["dec", "enc"],
            type=str,
            required=True,
            help="operation mode"
        )
        required.add_argument(
            "-p", "--password",
            type=lambda v: v.split(","),
            required=True,
            help="passwords used for encrypting/decrypting (single password or comma-separated list of passwords)"
        )
        required.add_argument(
            "-i", "--input",
            type=self.__ParseInputPaths,
            required=True,
            help="input to be encrypted/decrypted (single file, comma-separated list of files or a folder)"
        )
        required.add_argument(
            "-o", "--output",
            type=Path,
            required=True,
            help="output folder where the encrypted/decrypted files will be saved"
        )
        optional.add_argument(
            "-s", "--salt",
            default=None,
            type=lambda v: v.split(","),
            help="custom salts for master key and IV derivation, random generated if not specified "
                 "(only for encrypting)"
        )
        optional.add_argument(
            "-t", "--iteration",
            default=524288,
            type=int,
            help="specify the number of iteration for PBKDF2-SHA512 algorithm, default value: 524288"
        )
        optional.add_argument(
            "-v", "--verbose",
            help="enable verbose mode",
            action="store_true"
        )

    def Parse(self) -> Arguments:
        """Parse arguments.

        Returns:
            Arguments object
        """
        parsed_args = self.parser.parse_args()

        args = Arguments()
        args.SetValue(parsed_args.mode.lower(), ArgumentTypes.MODE)
        args.SetValue(parsed_args.password, ArgumentTypes.PASSWORDS)
        args.SetValue(parsed_args.input, ArgumentTypes.INPUT_PATHS)
        args.SetValue(parsed_args.output, ArgumentTypes.OUTPUT_PATH)
        args.SetValue(parsed_args.salt, ArgumentTypes.SALT)
        args.SetValue(parsed_args.iteration, ArgumentTypes.ITR_NUM)
        args.SetValue(parsed_args.verbose, ArgumentTypes.VERBOSE)

        return args

    @staticmethod
    def __ParseInputPaths(value: str) -> List[Path]:
        """Parse input paths.

        Args:
            value: Input path string

        Returns:
            List of Path objects
        """
        curr_path = Path(value)
        if curr_path.is_dir():
            files = [p for p in curr_path.iterdir() if p.is_file() and not p.name.startswith(".")]
        else:
            files = [Path(p) for p in value.split(",") if Path(p).is_file()]

        return files


def EncryptFile(in_file: str,
                out_path: str,
                args: Arguments) -> None:
    """Encrypt file.

    Args:
        in_file: Input file path
        out_path: Output file path
        args: Arguments object
    """
    print(f"Encrypting file: '{in_file}'...")

    file_encrypter = FileEncrypter(
        Pbkdf2Sha512(args.GetValue(ArgumentTypes.ITR_NUM))
    )
    if args.IsVerbose():
        file_encrypter.Logger().SetLevel(logging.INFO)
    file_encrypter.Encrypt(
        in_file,
        args.GetValue(ArgumentTypes.PASSWORDS),
        args.GetValue(ArgumentTypes.SALT)
    )
    file_encrypter.SaveTo(out_path)

    print(f"Output file saved to: '{out_path}'")


def DecryptFile(in_file: str,
                out_path: str,
                args: Arguments) -> None:
    """Decrypt file.

    Args:
        in_file: Input file path
        out_path: Output file path
        args: Arguments object
    """
    print(f"Decrypting file: '{in_file}'...")

    try:
        file_decrypter = FileDecrypter(
            Pbkdf2Sha512(args.GetValue(ArgumentTypes.ITR_NUM))
        )
        if args.IsVerbose():
            file_decrypter.Logger().SetLevel(logging.INFO)
        file_decrypter.Decrypt(
            in_file,
            args.GetValue(ArgumentTypes.PASSWORDS)
        )
        file_decrypter.SaveTo(out_path)

        print(f"Output file saved to: '{out_path}'")
    except DataHmacError:
        print(f"ERROR: file HMAC is not valid '{in_file}'")
    except DataDecryptError:
        print(f"ERROR: unable to decrypt file '{in_file}'")


def RunApp(args: Arguments) -> None:
    """Run application.

    Args:
        args: Arguments object
    """
    enc_suffix: str = "_enc"

    # Get input files
    input_paths = args.GetValue(ArgumentTypes.INPUT_PATHS)
    if len(input_paths) == 0:
        print("No input files specified, exiting...")
        sys.exit(1)

    print(f"Input files: {', '.join([str(p) for p in input_paths])}")

    # Get output path
    output_path = args.GetValue(ArgumentTypes.OUTPUT_PATH)

    # Creating output directory
    print("Creating output directory...")
    output_path.mkdir(parents=True, exist_ok=True)

    # Encrypt files
    if args.IsEncryptMode():
        for curr_path in input_paths:
            out_path = output_path / curr_path.with_stem(curr_path.stem + enc_suffix).name
            EncryptFile(curr_path, out_path, args)
    # Decrypt files
    elif args.IsDecryptMode():
        for curr_path in input_paths:
            out_path = output_path / curr_path.with_stem(curr_path.stem.replace(enc_suffix, "")).name
            DecryptFile(curr_path, out_path, args)

    print("Operation completed")


def main() -> None:
    """Main."""
    args_parser = ArgumentsParser()
    RunApp(args_parser.Parse())


if __name__ == "__main__":
    main()
