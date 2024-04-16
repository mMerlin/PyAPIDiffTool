# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
`compare module interfaces`
==================

Compare the visible api interface for different modules.

Written to see differences in CircuitPython specific module interfaces
compared to the standard cPython libraries.

This needs to run from cPython for its intended purpose. CircuitPython
does not implement some of the required libraries (inspect).

"""
from collections import namedtuple
from dataclasses import dataclass, field
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from queue import Queue
import types
from typing import Callable, Tuple, Union, Dict

from app_error_framework import RetryLimitExceeded, ApplicationFlagError
from config_package import ProfileConfiguration, Setting, SetKey
from profiling_utils import validate_profile_data
#     annotation_str, default_str, report_profile_data_exceptions
from introspection_tools import (
    AttributeProfileKey as APKey,
    ProfileConstant as PrfC,
    attribute_name_compare_key,
)
from generic_tools import (
    ReportHandler, LoggerMixin,
    generate_random_alphanumeric,
    StrOrTag,
)
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

AttributeProfile = Tuple[StrOrTag, str, Tuple[StrOrTag, types.ModuleType], Tuple[str, ...],
                         Tuple[tuple, StrOrTag]]

@dataclass(frozen=True)
class Key:
    """
    Constants for lookup indexes and keys, to avoid possible typos in strings used to
    reference them.
    """
    compare_name: int = 1
    """index to actual attribute name in (sorted) comparison key"""
    sent_header_diff: str = 'diff header sent'

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
        self.matched_logger = reporting_logger('matched_')
        self.not_implemented_logger = reporting_logger('not_implemented_')
        self.extension_logger = reporting_logger('extension_')
        self.skipped_logger = reporting_logger('skipped_')
        self.matched = self.matched_logger.info
        self.not_implemented = self.not_implemented_logger.info
        self.extension = self.extension_logger.info
        self.skipped = self.skipped_logger.info

class CompareModuleAPI:  # pylint:disable=too-few-public-methods
    """Compares module APIs for compatibility between different implementations.

    This class provides functionality to compare the interfaces of modules, classes, and functions,
    highlighting differences that might affect compatibility. It supports loading configuration from
    files and command-line arguments to customize the comparison process.

    Attributes:
        settings (ProfileConfiguration): Stores the application's configuration settings.
        base_module
        port_module
        report
        _logger
    """
    APP_NAME: str = 'CompareModuleAPI'
    HIGH_VALUES = attribute_name_compare_key('_~')
    """High-value sentinel, lexicographically greater than any valid attribute name

    For added certainty, could use a lexicographically higher utf-8 character. Like '°' (degrees)

    With the sort order used, private attribute names sort last
    """

    def __init__(self):
        self._logger = _initialize_exception_logging(self.APP_NAME + ".log")
        self._logger.setLevel(logging.DEBUG)
        LoggerMixin.set_logger(self._logger)
        self.settings = ProfileConfiguration(self.APP_NAME, self._logger.name)
        self._logger.setLevel(self.settings[Setting.LOGGING_LEVEL.name])
        self.report: Report = Report()
        self._shared: Dict[str, Union[int, bool]] = {}
        self.base_module = self.settings.base
        self.port_module = self.settings.port
        self._configure_reporting()
        self._expand_queue = Queue()  # A FIFO queue

    def _configure_reporting(self) -> None:
        """Sets logging level to info when reporting, error when not reporting."""
        self.report.matched_logger.setLevel(logging.INFO
            if self.settings[Setting.REPORT_MATCHED.name] else logging.ERROR)
        self.report.not_implemented_logger.setLevel(logging.INFO
            if self.settings[Setting.REPORT_NOT_IMPLEMENTED.name] else logging.ERROR)
        self.report.extension_logger.setLevel(logging.INFO
            if self.settings[Setting.REPORT_EXTENSION.name] else logging.ERROR)
        self.report.skipped_logger.setLevel(logging.INFO
            if self.settings[Setting.REPORT_SKIPPED.name] else logging.ERROR)

    def process_expand_queue(self) -> None:
        """
        Compares attributes profiles between base and port implementations based on the
        configuration settings.
        """
        match_pair = MatchPair(
            base=ProfileModule(self.base_module, self.settings, self.report.skipped),
            port=ProfileModule(self.port_module, self.settings, self.report.skipped))
        match_count, not_impl_count, extension_count = 0, 0, 0
        base_skip_count, port_skip_count = 0, 0
        processing_complete = False
        while not processing_complete:
            base_attribute_profile = match_pair.base.profile_attributes(False)
            port_attribute_profile = match_pair.port.profile_attributes(True)

            base_key, base_profile = next(base_attribute_profile, (self.HIGH_VALUES, None))
            port_key, port_profile = next(port_attribute_profile, (self.HIGH_VALUES, None))
            while base_key < self.HIGH_VALUES or port_key < self.HIGH_VALUES:
                if base_key == port_key:
                    match_count += 1
                    self._handle_matched_attribute(match_pair, base_key[Key.compare_name],
                                                  base_profile, port_profile)
                    base_key, base_profile = next(base_attribute_profile, (self.HIGH_VALUES, None))
                    port_key, port_profile = next(port_attribute_profile, (self.HIGH_VALUES, None))
                elif base_key < port_key:
                    not_impl_count += 1
                    self._handle_unmatched_attribute(match_pair, 'base',
                        base_key[Key.compare_name], base_profile)
                    base_key, base_profile = next(base_attribute_profile, (self.HIGH_VALUES, None))
                else: # compare_base > compare_port
                    extension_count += 1
                    self._handle_unmatched_attribute(match_pair, 'port',
                        port_key[Key.compare_name], port_profile)
                    port_key, port_profile = next(port_attribute_profile, (self.HIGH_VALUES, None))
            base_skip_count += match_pair.base.context_data.skipped
            port_skip_count += match_pair.port.context_data.skipped
            if self._expand_queue.empty():
                processing_complete = True
            else:
                # Get an entry from self._expand_queue and prepare to process it
                que_ent: MatchingContext = self._expand_queue.get()
                match_pair.base.update_context(que_ent.base_path, que_ent.base_element)
                match_pair.port.update_context(que_ent.port_path, que_ent.port_element)

        print(f'\n{base_skip_count} base attributes skipped, {port_skip_count}'
              ' port attributes skipped.')
        print(f'{match_count} Matched, {not_impl_count} Not Implemented, and {extension_count} '
              'Extension attributes found.')
        self._report_match_details()

    def _queue_attribute_expansion(self, name: str, context: MatchPair) -> None:
        """
        Add an entry to the queue for later profile matching

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
        """
        self._expand_queue.put(MatchingContext(
            base_path=context.base.context_data.path + (name,),
            port_path=context.port.context_data.path + (name,),
            base_element=getattr(context.base.context_data.element, name, None),
            port_element=getattr(context.port.context_data.element, name, None),
        ))

    def _handle_matched_attribute(self, context: MatchPair, name: str,
                                 profile_base: Tuple, profile_port: Tuple) -> None:
        """
        Handles attributes that exist in both base and port implementations.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            profile_base (Tuple): The profile information for the attribute in the base
                implementation.
            profile_port (Tuple): The profile information for the attribute in the ported
                implementation.
        """
        validate_profile_data(name, context.base.context_data, profile_base)
        validate_profile_data(name, context.port.context_data, profile_port)
        rpt_target = self.report.matched_logger
        # need to watch for the need to expand both attributes
        self._shared[Key.sent_header_diff] = False
        if profile_base[APKey.annotation] != profile_port[APKey.annotation] and \
                SetKey.scope not in self.settings.get(Setting.IGNORE_ADDED_ANNOTATION):
            self._send_match_diff_header(name, context)
            rpt_target.info(f'  Annotation: Base {profile_base[APKey.annotation]};' +
                            f' Port {profile_port[APKey.annotation]}')
        if profile_base[APKey.data_type] != profile_port[APKey.data_type]:
            self._send_match_diff_header(name, context)
            rpt_target.info(f'  Type: Base {profile_base[APKey.data_type]};' +
                            f' Port {profile_port[APKey.data_type]}')
            # 'type' could match 'function'. A class constructor could do the same
            # as a function: logging._logRecordFactory
            # doing that sort of match is going to need smarter processing. Currently
            # a class is tagged for later expansion, while function signature is
            # handled in the current pass.
            # ?re-tag the function to be expanded? ?logic to only expand the constructor?
            # process the class constructor now, and match to function signature?
            # -- the class is its constructor??
        if profile_base[APKey.tags] != profile_port[APKey.tags]:
            self._send_match_diff_header(name, context)
            rpt_target.info(f'  "is" tags: Base {profile_base[APKey.tags]};' +
                            f' Port {profile_port[APKey.tags]}')
        # compare profile_«»[Key.source]. Not expecting to match if part of packages
        # being compared

        base_category = profile_base[APKey.details]
        port_category = profile_port[APKey.details]
        if self._handle_simple_details(name, context, base_category, port_category):
            return
        # check if name is published in one implementation but not the other
        if name in context.base.context_data.published and \
                name not in context.port.context_data.published:
            self._send_match_diff_header(name, context)
            rpt_target.info('  published in base implementation, but not in the port')
        if name not in context.base.context_data.published and \
                name in context.port.context_data.published:
            self._send_match_diff_header(name, context)
            rpt_target.info('  published in port implementation, but not in the base')
        if base_category[APKey.context] == PrfC.DATA_NODE:
            self._queue_attribute_expansion(name, context)
            if not self._shared[Key.sent_header_diff]:  # Exact match (so far)
                if self.settings.get(Setting.REPORT_EXACT_MATCH):
                    rpt_target.info(f'"{name}" Expand matched node: ' +
                        f'{context.base.context_data.path}¦{context.port.context_data.path}')
            return
        if base_category[APKey.context] in (
                PrfC.A_CLASS, PrfC.DATA_LEAF, PrfC.unhandled_value):
            self._send_match_diff_header(name, context)
            rpt_target.info(f'  compare context: Base {base_category};' +
                            f' Port {port_category}')
            return
        self._handle_str_category(name, context, base_category, port_category)

    def _send_match_diff_header(self, name: str, context: MatchPair) -> None:
        """
        Send a (report detail block) header line, if it has not yet been sent

        Args:
            name (str) the name of the attribute being reported
            context (MatchPair): The context data for the base and port implementations.
        """
        if not self._shared[Key.sent_header_diff]:
            self.report.matched(f'"{name}" Differences: {context.base.context_data.path}¦' +
                                f'{context.port.context_data.path}')
            self._shared[Key.sent_header_diff] = True

    def _handle_unmatched_attribute(self, context: MatchPair, base_or_port: str, name: str,
                                   profile: AttributeProfile) -> None:
        pass  # Stub
    def _report_match_details(self) -> None:
        pass  # Stub
    def _handle_simple_details(self, name: str, context: MatchPair,
            base_category: Tuple[StrOrTag, tuple], port_category: Tuple[StrOrTag, tuple]):
        pass  # Stub
    def _handle_str_category(self, name: str, context: MatchPair, base_category: Tuple,
                             port_category: Tuple) -> None:
        pass  # Stub

def _initialize_exception_logging(log_file: Path = 'errors.log',
                                  *, retries: int = 3) -> logging.Logger:
    """
    gets a Logger instance to be used application wide for exception reporting

    Args:
        name(str): the name to use for the logger
        retries (int): keyword only number of retries attempting to get unused
            logger name
        kwargs: optional arguments to pass to RotatingFileHandler instantiation
    """

    app_logger = get_unique_logger('exceptions_', retries=retries)

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

def reporting_logger(name_prefix: str, *, retries: int = 3) -> logging.Logger:
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
    new_logger = get_unique_logger(name_prefix, retries=retries)
    new_logger.addHandler(report_handler)
    new_logger.propagate = False
    return new_logger

def get_unique_logger(name_prefix: str, *, retries: int = 3) -> logging.Logger:
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

if __name__ == "__main__":
    app = CompareModuleAPI()
    app.process_expand_queue()

# cSpell:words pathlib backslashreplace levelname
# cSpell:ignore
# cSpell:allowCompoundWords true
