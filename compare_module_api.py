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

from app_error_framework import RetryLimitExceeded, ApplicationFlagError, ApplicationDataError
from config_package import ProfileConfiguration
from profiling_utils import validate_profile_data
from introspection_tools import (
    AttributeProfileKey as APKey,
    InspectIs as Is,
    ProfileConstant as PrfC,
    Tag as ITag,
    ParameterDetail,
    attribute_name_compare_key,
)
from generic_tools import (
    ReportHandler, LoggerMixin, SentinelTag,
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

MethodSignatureDetail = Tuple[str, Tuple[Tuple[ParameterDetail, ...], StrOrTag]]
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
        self._logger.setLevel(self.settings.logging_level)
        self.report: Report = Report()
        self._shared: Dict[str, Union[int, bool]] = {}
        self.base_module = self.settings.base
        self.port_module = self.settings.port
        self._configure_reporting()
        self._expand_queue = Queue()  # A FIFO queue

    def _configure_reporting(self) -> None:
        """Sets logging level to info when reporting, error when not reporting."""
        self.report.matched_logger.setLevel(logging.INFO
            if self.settings.report_matched else logging.ERROR)
        self.report.not_implemented_logger.setLevel(logging.INFO
            if self.settings.report_not_implemented else logging.ERROR)
        self.report.extension_logger.setLevel(logging.INFO
            if self.settings.report_extensions else logging.ERROR)
        self.report.skipped_logger.setLevel(logging.INFO
            if self.settings.report_skipped else logging.ERROR)

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
                    self._handle_matched_attribute(base_key[Key.compare_name], match_pair,
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

    def _handle_matched_attribute(self, name: str, context: MatchPair,  # pylint:disable=too-many-return-statements
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
        # need to watch for the need to expand both attributes
        self._shared[Key.sent_header_diff] = False
        self._check_match_annotation(name, context, profile_base, profile_port)
        self._check_match_data_type(name, context, profile_base, profile_port)
        self._check_attribute_tags(name, context, profile_base, profile_port)
        # compare profile_«»[Key.source]. Not expecting to match if part of packages
        # being compared

        base_category = profile_base[APKey.details]
        port_category = profile_port[APKey.details]
        if self._check_category_discrepancy(name, context, base_category, port_category):
            return
        if self._check_different_category_key(name, context, base_category, port_category):
            return
        if self._check_data_leaf(name, context, base_category, port_category):
            return
        self._check_published_changes(name, context)
        if self._check_data_node(name, context, base_category):
            return
        if self._check_special_leaf(name, context, base_category, port_category):
            return
        if self._check_expandable(name, context, base_category, port_category):
            return
        if self._check_expand_cutoff(name, context, base_category, port_category):
            return
        self._handle_matched_routine(name, context, base_category, port_category)

    def _check_match_annotation(self, name: str, context: MatchPair,
                                profile_base: Tuple, profile_port: Tuple) -> None:
        """
        Reports relevant differences in (scope) annotation information.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            profile_base (Tuple): The profile information for the attribute in the base
                implementation.
            profile_port (Tuple): The profile information for the attribute in the ported
                implementation.
        """
        if not (profile_base[APKey.annotation] == profile_port[APKey.annotation] or (
                    profile_base[APKey.annotation] is SentinelTag(ITag.NO_ATTRIBUTE_ANNOTATION)
                    and self.settings.annotation_ignore_scope)):
            self._send_match_diff_header(name, context)
            self.report.matched_logger.info('  Annotation: Base '  # pylint:disable=logging-fstring-interpolation
                f'{profile_base[APKey.annotation]}; Port {profile_port[APKey.annotation]}')

    def _check_match_data_type(self, name: str, context: MatchPair,
                                profile_base: Tuple, profile_port: Tuple) -> None:
        """
        Reports differences in attribute data type information.

        A type of 'type' could match 'function'. A class constructor could do the same as a
        function: logging._logRecordFactory
        doing that sort of match is going to need smarter processing. Currently a class is
        tagged for later expansion, while a function signature is handled in the current pass.
        ?re-tag the function to be expanded? ?logic to only expand the constructor?
        process the class constructor now, and match to function signature?
        -- the class (signature) is its constructor??

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            profile_base (Tuple): The profile information for the attribute in the base
                implementation.
            profile_port (Tuple): The profile information for the attribute in the ported
                implementation.
        """
        if profile_base[APKey.data_type] != profile_port[APKey.data_type]:
            self._send_match_diff_header(name, context)
            self.report.matched_logger.info(f'  Type: Base {profile_base[APKey.data_type]};' +
                                            f' Port {profile_port[APKey.data_type]}')

    def _check_attribute_tags(self, name: str, context: MatchPair,
                                profile_base: Tuple, profile_port: Tuple) -> None:
        """
        Reports differences in attribute tags information.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            profile_base (Tuple): The profile information for the attribute in the base
                implementation.
            profile_port (Tuple): The profile information for the attribute in the ported
                implementation.
        """
        if profile_base[APKey.tags] != profile_port[APKey.tags]:
            self._send_match_diff_header(name, context)
            self.report.matched_logger.info(  # pylint:disable=logging-fstring-interpolation
                f'  "is" tags: Base {profile_base[APKey.tags]}; Port {profile_port[APKey.tags]}')
            # IDEA: report added and remove tags instead of all

    def _check_category_discrepancy(self, name: str, context: MatchPair,
            base_category: Tuple[StrOrTag, tuple], port_category: Tuple[StrOrTag, tuple]) -> None:
        """
        Reports unexpected structure conditions for category information.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_category (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_category (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        if len(base_category) != len(port_category):
            self._send_match_diff_header(name, context)
            self.report.matched(
                f'  Context length {len(base_category)} not = {len(port_category)}: '
                'cannot compare further')
            self.report.matched(f'    {base_category}')
            self.report.matched(f'    {port_category}')
            return True
        if len(base_category) != 2:
            self._send_match_diff_header(name, context)
            self.report.matched(f'  Odd(unhandled) context size {len(base_category)}:')
            self.report.matched(f'    {base_category}')
            self.report.matched(f'    {port_category}')
            return True
        return False

    def _check_different_category_key(self, name: str, context: MatchPair,
            base_category: Tuple[StrOrTag, tuple], port_category: Tuple[StrOrTag, tuple]) -> None:
        """
        Reports different category identifier for base and port implementations.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_category (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_category (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        if base_category[APKey.context] != port_category[APKey.context]:
            self._send_match_diff_header(name, context)
            self.report.matched(f'  Base detail key {base_category[APKey.context]} ' +
                       f'not equal port key {port_category[APKey.context]}: '
                       'cannot compare further')
            self.report.matched(f'    {base_category}')
            self.report.matched(f'    {port_category}')
            return True
        return False

    def _check_data_leaf(self, name: str, context: MatchPair,
            base_category: Tuple[StrOrTag, tuple], port_category: Tuple[StrOrTag, tuple]) -> None:
        """
        Report differences data leaf (literal) values.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_category (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_category (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        if base_category[APKey.context] == PrfC.DATA_LEAF:
            if base_category[APKey.detail] == port_category[APKey.detail]:
                if not self._shared[Key.sent_header_diff]:  # Exact match
                    if self.settings.report_exact:
                        self.report.matched(f'"{name}" No Difference: ' +
                            f'{context.base.context_data.path}¦{context.port.context_data.path}')
                return True
            self._send_match_diff_header(name, context)
            self.report.matched('  Literal value changed (possibly truncated):')
            # future: generic function to more smartly truncate content
            #  append … if truncated
            #  trim and collapse whitespace
            #  specify maximum length «account for appended ellipse»
            #  smarter: start with ellipse and make sure to show segment that is different
            self.report.matched(f'    base content = {base_category[APKey.detail]:.50}')
            self.report.matched(f'    port content = {port_category[APKey.detail]:.50}')
            return True
        return False

    def _is_ignored_docstring(self, name: str, context: MatchPair) -> bool:
        """
        check if the attribute is a docstring that is to be ignored (for differences)

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
        """
        return (
            name == '__doc__' and
            # context.base.context_data.mode == PrfC:MODULE_MODE and
            (isinstance(context.base.context_data.element, types.ModuleType) and
             self.settings.docstring_ignore_module) or
            # context.base.context_data.mode == PrfC:CLASS_MODE and
            ((isinstance(context.base.context_data.element, type) or
              repr(type(context.base.context_data.element)).startswith('<class ') or
              context.base.context_data.mode == PrfC.KEY_VALUE_MODE) and
             self.settings.docstring_ignore_class) or
            (isinstance(context.base.context_data.element, types.FunctionType) and
             self.settings.docstring_ignore_method)
        )

    def _check_published_changes(self, name: str, context: MatchPair) -> None:
        """
        Reports attribute published status differences

        Checks if name is published in one implementation but not the other

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            profile_base (Tuple): The profile information for the attribute in the base
                implementation.
            profile_port (Tuple): The profile information for the attribute in the ported
                implementation.
        """
        if name in context.base.context_data.published and \
                name not in context.port.context_data.published:
            self._send_match_diff_header(name, context)
            self.report.matched_logger.info(
                '  published in base implementation, but not in the port')
        if name not in context.base.context_data.published and \
                name in context.port.context_data.published:
            self._send_match_diff_header(name, context)
            self.report.matched_logger.info(
                '  published in port implementation, but not in the base')

    def _check_data_node(self, name: str, context: MatchPair, base_category: Tuple) -> bool:
        """
        Reports pending expansion of matching data nodes.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_category (Tuple): The base profile attribute details

        Returns
            True when a data node has been found, False otherwise.
        """
        if base_category[APKey.context] == PrfC.DATA_NODE:
            self._queue_attribute_expansion(name, context)
            if not self._shared[Key.sent_header_diff]:  # Exact match (so far)
                if self.settings.report_exact:
                    self.report.matched_logger.info(f'"{name}" Expand matched node: ' +
                        f'{context.base.context_data.path}¦{context.port.context_data.path}')
            return True
        return False

    def _check_special_leaf(self, name: str, context: MatchPair,
                         base_category: Tuple, port_category: Tuple) -> bool:
        """
        Reports leaf type match details

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_category (Tuple): The base profile attribute details
            port_category (Tuple): The port profile attribute details

        Returns
            True when a leaf type has been found, False otherwise.
        """
        if base_category[APKey.context] in (
                PrfC.A_CLASS, PrfC.unhandled_value):
            if base_category[APKey.detail] == port_category[APKey.detail]:
                if self.settings.report_exact:
                    self.report.matched(f'"{name}" category {base_category[APKey.context]} ' +
                        f'  Details Matched: {base_category[APKey.detail]}')
            else:
                self._send_match_diff_header(name, context)
                self.report.matched(f'  compare context: Base {base_category};' +
                                    f' Port {port_category}')
            return True
        return False

    def _check_expandable(self, name: str, context: MatchPair, base_category: Tuple,
                             port_category: Tuple) -> bool:
        """
        Adds expandable attribute to the queue

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_category (Tuple): The base profile attribute details
            port_category (Tuple): The port profile attribute details

        Returns
            True when an expandable attribute has been found, False otherwise.
        """
        if base_category[APKey.detail] is SentinelTag(PrfC.expandable):
            if port_category[APKey.detail] is not SentinelTag(PrfC.expandable):
                raise ApplicationDataError(
                    f'"{name}" base {base_category[APKey.context]} is expandable, but ' +
                    f'port is {repr(port_category[APKey.detail])}')
            if base_category[APKey.context] not in (PrfC.A_CLASS, Is.DATADESCRIPTOR):
                raise ApplicationDataError(f'Unhandled expand for {base_category[APKey.context]} ' +
                                           f'category for "{name}" attribute.')
            self._queue_attribute_expansion(name, context)
            if not self._shared[Key.sent_header_diff]:  # Exact match (so far)
                if self.settings.report_exact:
                    self.report.matched(f'"{name}" Expand both for ' +
                        f'{base_category[APKey.context]}: ' +
                        f'{context.base.context_data.path}¦{context.port.context_data.path}')
            return True
        return False

    def _check_expand_cutoff(self, name: str, context: MatchPair, base_category: Tuple,
                             port_category: Tuple) -> bool:
        """
        Reports nested expansion cutoff tag

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_category (Tuple): The base profile attribute details
            port_category (Tuple): The port profile attribute details

        Returns
            True when an expandable attribute has been found, False otherwise.
        """
        if base_category[APKey.detail] is SentinelTag(PrfC.cutoff):
            if port_category[APKey.detail] is not SentinelTag(PrfC.cutoff):
                raise ApplicationDataError(
                    f'"{name}" is cutoff for {context.base.context_data.path} ' +
                    f'but not for {context.port.context_data.path}')
            if base_category[APKey.context] not in (PrfC.DUNDER,):
                raise ApplicationDataError('Self tag context '
                    f'"{base_category[APKey.context]}" found for "{name}" attribute.')
            return True
        return False

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

    def _handle_matched_routine(self, name: str, context: MatchPair,
                               base_category: MethodSignatureDetail,
                               port_category: MethodSignatureDetail) -> None:
        pass  # Stub
    def _handle_unmatched_attribute(self, context: MatchPair, base_or_port: str, name: str,
                                   profile: AttributeProfile) -> None:
        pass  # Stub
    def _report_match_details(self) -> None:
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

# cSpell:words pathlib backslashreplace levelname DATADESCRIPTOR DUNDER
# cSpell:ignore fstring
# cSpell:allowCompoundWords true
