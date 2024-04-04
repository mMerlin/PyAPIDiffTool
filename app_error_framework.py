# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""Error class framework for the applications"""

class ApplicationRootError(Exception):
    """Base class for application-specific exceptions."""

class ApplicationFlagError(ApplicationRootError):
    """
    Signals that an error has been handled; the caller should continue.
    Useful for control flow where raising a conventional error, or returning a flag value
    is not desired.
    """

class ApplicationLogicError(ApplicationRootError):
    """
    Indicates a violation in the program's logic or assumptions.
    Can be used to catch programming errors early.
    """

class RetryLimitExceeded(ApplicationRootError):
    """Too many retries for operation.
    Specify the context in the message.
    """
