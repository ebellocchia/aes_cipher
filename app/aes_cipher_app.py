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
import argparse
import logging
import sys
from enum import Enum, auto, unique
from pathlib import Path
from typing import Any, Dict, List, Tuple
from aes_cipher import FileDecrypter, FileEncrypter, DataHmacError, DataDecryptError


#
# Classes
#

# Argument types
@unique
class ArgumentTypes(Enum):
    MODE = auto(),
    PASSWORDS = auto(),
    INPUT_PATHS = auto(),
    OUTPUT_PATH = auto(),
    SALT = auto(),
    ITR_NUM = auto(),
    VERBOSE = auto(),


# Arguments
class Arguments:
    MODES: Tuple[str, str] = ("dec", "enc")

    args_val: Dict[ArgumentTypes, Any]

    # Constructor
    def __init__(self) -> None:
        self.Reset()

    # Get argument value
    def GetValue(self,
                 arg_type: ArgumentTypes) -> Any:
        if not isinstance(arg_type, ArgumentTypes):
            raise TypeError("Invalid argument type")
        return self.args_val[arg_type]

    # Set argument value
    def SetValue(self,
                 value: Any,
                 arg_type: ArgumentTypes) -> None:
        if not isinstance(arg_type, ArgumentTypes):
            raise TypeError("Invalid argument type")
        self.args_val[arg_type] = value

    # Get if verbose
    def IsVerbose(self) -> bool:
        return self.GetValue(ArgumentTypes.VERBOSE)

    # Get if decrypt mode
    def IsDecryptMode(self) -> bool:
        return self.GetValue(ArgumentTypes.MODE) == self.MODES[0]

    # Get if encrypt mode
    def IsEncryptMode(self) -> bool:
        return self.GetValue(ArgumentTypes.MODE) == self.MODES[1]

    # Reset
    def Reset(self) -> None:
        self.args_val = {
            ArgumentTypes.MODE: "",
            ArgumentTypes.PASSWORDS: "",
            ArgumentTypes.INPUT_PATHS: None,
            ArgumentTypes.OUTPUT_PATH: None,
            ArgumentTypes.SALT: None,
            ArgumentTypes.ITR_NUM: None,
            ArgumentTypes.VERBOSE: False,
        }


# Argument parser
class ArgumentsParser:

    parser: argparse.ArgumentParser

    # Constructor
    def __init__(self) -> None:
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
            help="password used for encrypting/decrypting (single password or a list of comma-separated passwords)"
        )
        required.add_argument(
            "-i", "--input",
            type=lambda v: self.__ParseInputPaths(v),
            required=True,
            help="input to be encrypted/decrypted, it can be a single file, a list of files separated by a comma or a folder"
        )
        required.add_argument(
            "-o", "--output",
            type=lambda v: Path(v),
            required=True,
            help="output folder where the encrypted/decrypted files will be saved"
        )
        optional.add_argument(
            "-s", "--salt",
            default="",
            type=str,
            help="specify a custom salt for master key and IV derivation, default value: []=?AeS_CiPhEr><()"
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

    # Parse arguments
    def Parse(self) -> Arguments:
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

    # Parse input paths
    @staticmethod
    def __ParseInputPaths(value: str) -> List[Path]:
        curr_path = Path(value)
        if curr_path.is_dir():
            files = [p for p in curr_path.iterdir() if p.is_file() and not p.name.startswith(".")]
        else:
            files = [Path(p) for p in value.split(",") if Path(p).is_file()]

        return files


#
# Functions
#

# Run application
def RunApp(args: Arguments) -> None:
    enc_suffix: str = "_enc"

    # Get input files
    input_paths = args.GetValue(ArgumentTypes.INPUT_PATHS)
    if len(input_paths) == 0:
        print("No input files specified, exiting...")
        sys.exit(1)

    print("Input files: %s" % ", ".join([str(p) for p in input_paths]))

    # Get output path
    output_path = args.GetValue(ArgumentTypes.OUTPUT_PATH)

    # Creating output directory
    print("Creating output directory...")
    output_path.mkdir(parents=True, exist_ok=True)

    # Encrypt files
    if args.IsEncryptMode():
        for curr_path in input_paths:
            out_path = output_path / curr_path.with_stem(curr_path.stem + enc_suffix).name

            print("Encrypting file: '%s'..." % curr_path)

            file_encrypter = FileEncrypter()
            if args.IsVerbose():
                file_encrypter.Logger().SetLevel(logging.INFO)
            file_encrypter.Encrypt(
                curr_path,
                args.GetValue(ArgumentTypes.PASSWORDS),
                args.GetValue(ArgumentTypes.SALT),
                args.GetValue(ArgumentTypes.ITR_NUM))
            file_encrypter.SaveTo(out_path)

            print("Output file saved to: '%s'" % out_path)

    # Decrypt files
    elif args.IsDecryptMode():
        for curr_path in input_paths:
            out_path = output_path / curr_path.with_stem(curr_path.stem.replace(enc_suffix, "")).name

            print("Decrypting file: '%s'..." % curr_path)

            try:
                file_decrypter = FileDecrypter()
                if args.IsVerbose():
                    file_decrypter.Logger().SetLevel(logging.INFO)
                file_decrypter.Decrypt(
                    curr_path,
                    args.GetValue(ArgumentTypes.PASSWORDS),
                    args.GetValue(ArgumentTypes.SALT),
                    args.GetValue(ArgumentTypes.ITR_NUM))
                file_decrypter.SaveTo(out_path)

                print("Output file saved to: '%s'" % out_path)
            except DataHmacError:
                print("ERROR: file HMAC is not valid '%s'" % curr_path)
            except DataDecryptError:
                print("ERROR: unable to decrypt file '%s'" % curr_path)

    print("Operation completed")


# Main
def main() -> None:
    # Get arguments
    args_parser = ArgumentsParser()
    # Run application
    RunApp(args_parser.Parse())


# Execute main
if __name__ == "__main__":
    main()
