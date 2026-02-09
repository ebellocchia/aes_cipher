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

import logging


class LoggerConst:
    """Constant for logger class."""

    LOGGER_NAME: str = "aes_cipher"
    LOG_FORMAT: str = "  LOG %(levelname)s - %(message)s"


class Logger:
    """Logger class."""

    logger: logging.Logger

    def __init__(self) -> None:
        """Constructor."""
        self.__CreateLogger()
        self.__ConfigureLogger()

    def SetLevel(self,
                 level: int) -> None:
        """
        Set level.

        Args:
            level: Logging level
        """
        self.logger.setLevel(level)

    def GetLogger(self) -> logging.Logger:
        """
        Get logger.

        Returns:
            Logger instance
        """
        return self.logger

    def __CreateLogger(self) -> None:
        """Create logger."""
        self.logger = logging.getLogger(LoggerConst.LOGGER_NAME)

    def __ConfigureLogger(self) -> None:
        """Configure logger."""
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter(LoggerConst.LOG_FORMAT))
        self.logger.addHandler(ch)
