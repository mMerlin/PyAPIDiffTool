# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
`utility functions and support classes for comparing module interfaces`
==================

"""
from collections import namedtuple
from dataclasses import dataclass, field
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys
from typing import Callable, FrozenSet

from app_error_framework import RetryLimitExceeded, ApplicationFlagError
from profiling_utils import annotation_str
from introspection_tools import (
    AttributeProfileKey as APKey,
    InspectIs as Is,
    ProfileConstant as PrfC,
    Tag as ITag,
)
from generic_tools import ReportHandler, SentinelTag, generate_random_alphanumeric
from profile_module import ProfileModule

MatchingContext = namedtuple(
    'MatchingContext', ['base_path', 'port_path', 'base_element', 'port_element'])
"""
A context for profiling base and port implementations

Fields:
    base_path: Tuple[str] path to object, starting from comparison root (typically the module
        (package))
    port_path: Tuple[str] path to object, starting from comparison root (typically the module
        (package))
    base_element: object base implementation element being profiled (from full base_path)
    port_element: object port implementation element being profiled (from full port_path)
"""

@dataclass(frozen=True)
class ContextSet:
    """
    Constants for individual and groups of contexts to be matched
    """
    routine: FrozenSet[str] = frozenset({Is.ROUTINE})
    data_node: FrozenSet[str] = frozenset({PrfC.DATA_NODE})
    data_leaf: FrozenSet[str] = frozenset({PrfC.DATA_LEAF})
    other_leaf: FrozenSet[str] = frozenset({PrfC.A_CLASS, PrfC.unhandled_value})
    descriptor: FrozenSet[str] = frozenset({PrfC.A_CLASS, Is.DATADESCRIPTOR})
    dunder: FrozenSet[str] = frozenset({PrfC.DUNDER})

@dataclass(frozen=True)
class Key:
    """
    Constants for lookup indexes and keys, to avoid possible typos in strings used to
    reference them.
    """
    # pylint:disable=too-many-instance-attributes
    compare_name: int = 1
    """index to actual attribute name in (sorted) comparison key"""
    sent_header_diff: str = 'diff header sent'
    sent_header_sig: str = 'signature header sent'
    parameter_index: str = 'parameter index'
    cur_param_type: str = 'parameter type'
    match_positional: str = 'POSITIONAL'
    match_keyword: str = 'KEYWORD'
    report_positional: str = 'positional'
    report_keyword: str = 'keyword'
    base_implementation: str = 'base'
    port_implementation: str = 'port'

@dataclass()
class MatchPair:
    """
    Details about the current base and port implementation queue entries being processed.
    """
    base: ProfileModule
    port: ProfileModule

@dataclass()
class Report:
    """Access to logging for reporting

    This class contains 2 linked sets of fields. <name> and <name>_logger. The
    <name>_logger fields are custom Logger instances to buffer related report
    content. The <name> fields are references to the .info method for the
    associated Logger. All reporting is intended to be done at the logging.INFO
    level.
    The fields are all initialized at instantiation using __post_init__.

    Usage:
        report = Report()
        report.matched_logger.setLevel(logging.INFO)
        report.matched('test %s', 'this')

        To suppress recording of specific report content:
        report.skipped_logger.setLevel(logging.ERROR)
    The valid arguments to matched, and the other <name> methods, is the same as
    logging.info()
    """
    # pylint:disable=too-many-instance-attributes
    matched_logger: logging.Logger = field(init=False)
    not_implemented_logger: logging.Logger = field(init=False)
    extension_logger: logging.Logger = field(init=False)
    skipped_logger: logging.Logger = field(init=False)

    matched: Callable[..., None] = field(init=False)
    not_implemented: Callable[..., None] = field(init=False)
    extension: Callable[..., None] = field(init=False)
    skipped: Callable[..., None] = field(init=False)

    def __post_init__(self):
        """initialize reporting loggers and assign logging methods"""
        self.matched_logger = _reporting_logger('matched_')
        self.not_implemented_logger = _reporting_logger('not_implemented_')
        self.extension_logger = _reporting_logger('extension_')
        self.skipped_logger = _reporting_logger('skipped_')
        self.matched = self.matched_logger.info
        self.not_implemented = self.not_implemented_logger.info
        self.extension = self.extension_logger.info
        self.skipped = self.skipped_logger.info

def initialize_exception_logging(log_file: Path = 'errors.log',
                                  *, retries: int = 3) -> logging.Logger:
    """
    gets a Logger instance to be used application wide for exception reporting

    Args:
        name(str): the name to use for the logger
        retries (int): keyword only number of retries attempting to get unused
            logger name
        kwargs: optional arguments to pass to RotatingFileHandler instantiation
    """

    app_logger = _get_unique_logger('exceptions_', retries=retries)

    err_handler = RotatingFileHandler(log_file, encoding='utf-8', maxBytes=1024*1024,
                                      backupCount=5, delay=True, errors='backslashreplace')
    # '%(asctime)s %(created)f %(levelname)s %(message)s %(module)s %(funcName)s'
    # ' %(lineno)d %(threadName)s %(thread)d'
    err_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(lineno)d - %(message)s',
        '%Y-%m-%d %H:%M:%S',
        '%')
    err_handler.setFormatter(err_formatter)
    app_logger.addHandler(err_handler)
    app_logger.propagate = False
    return app_logger

def _reporting_logger(name_prefix: str, *, retries: int = 3) -> logging.Logger:
    """
    get a custom logger to use to accumulate report information.

    Args:
        name_prefix (str): human readable prefix for logger name
        retries (int): passed to get_unique_logger
    Returns:
        an initialized Logger instance with custom report buffering handler

    Raises
        RetryLimitExceeded in get_unique_logger
    """
    # This check is more restrictive than really necessary, but is in line with
    # the intended usage.
    if not isinstance(name_prefix, str) and name_prefix.isidentifier:
        raise ApplicationFlagError(f'prefix {repr(name_prefix)} expected to be a valid identifier')
    report_handler = ReportHandler()
    report_handler.setLevel(logging.DEBUG)
    new_logger = _get_unique_logger(name_prefix, retries=retries)
    new_logger.addHandler(report_handler)
    new_logger.propagate = False
    return new_logger

def _get_unique_logger(name_prefix: str, *, retries: int = 3) -> logging.Logger:
    """
    get a logger instance that has not been configured (with a handler) yet.

    Args:
        name_prefix (str): human readable prefix for logger name
        retries (int): keyword only number of retries attempting to get unused
            logger name

    Raises
        RetryLimitExceeded if unable to create a Logger instance that is not
            already being used.
    """
    while True:
        logger_name = name_prefix + generate_random_alphanumeric(15)
        new_logger = logging.getLogger(logger_name)
        # Make sure this really is a new logger instance, not getting one previously initialized
        if not new_logger.handlers:
            return new_logger
        retries -= 1
        if retries <= 0:
            raise RetryLimitExceeded(
                f'new logger "{logger_name}" has {len(new_logger.handlers)} handlers: should be 0')

def fmt_return_annotation(sig_data: tuple) -> str:
    """
    get return type annotation from routine signature details

    Args:
        sig_data (tuple): signature profile information for a routine
    """
    return annotation_str(sig_data[APKey.sig_return], SentinelTag(ITag.NO_RETURN_ANNOTATION))

def adjust_module_search_path() -> None:
    """
    Add some extra folders to the python import search path, if not already there.

    Avoid some issues locating modules, and dependencies, to be imported.
    """
    current_dir = Path.cwd()
    app_dir = Path(__file__).parent
    subfolder_name: str = "lib"
    # Some common locations to find python modules to import from
    _insert_to_path(app_dir)
    _insert_to_path(app_dir.joinpath(subfolder_name))
    _insert_to_path(current_dir)
    _insert_to_path(current_dir.joinpath(subfolder_name))

def _insert_to_path(path: Path) -> None:
    """
    Insert a folder to the start of the python module search path if it exists
    and is not already there.

    Args:
        path (Path) the folder to add to the search list.
    """
    if path.exists() and path.is_dir():
        target_dir = str(path)
        if target_dir not in sys.path:
            sys.path.insert(0, target_dir)

# cSpell:words pathlib backslashreplace levelname DATADESCRIPTOR DUNDER
# cSpell:ignore fstring
# cSpell:allowCompoundWords true
