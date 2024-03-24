# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""Error class framework for the applications"""

class ApplicationRootError(BaseException):
    """Application specific Exception type. (to be) Part of Exception handling framework"""

class ApplicationFlagError(ApplicationRootError):
    """
    Indicates that an error case has already been handled, and the caller just needs to continue.
    Used as a signal between functions and their callers.
    """

class ApplicationLogicError(ApplicationRootError):
    """
    Indicates an error in the program's logic, suggesting that the assumptions made by the code
    are violated.
    """
