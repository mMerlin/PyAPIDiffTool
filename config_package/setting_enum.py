# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
`setting enum`

An enum that defines the (names for) configuration settings used for
comparison of module apis

"""
from enum import Enum, auto

class Setting(Enum):
    """settings that can be accessed from internal configuration"""
    SCOPE = auto()
    LOGGING_LEVEL = auto()
    REPORT_EXACT_MATCH = auto()
    REPORT_MATCHED = auto()
    REPORT_NOT_IMPLEMENTED = auto()
    REPORT_EXTENSION = auto()
    REPORT_SKIPPED = auto()
    USE_BUILTIN = auto()
    IGNORE_MODULE_ATTRIBUTES = auto()
    IGNORE_GLOBAL_ATTRIBUTES = auto()
    IGNORE_CLASS_ATTRIBUTES = auto()
    IGNORE_DOCSTRING = auto()
    IGNORE_ADDED_ANNOTATION = auto()
    # Add more configuration setting keys as needed
