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
from typing import Callable, Tuple, FrozenSet, Union, Dict

from app_error_framework import (
    RetryLimitExceeded, ApplicationFlagError, ApplicationDataError,
)
from config_package import ProfileConfiguration
from profiling_utils import validate_profile_data, annotation_str, default_str
from introspection_tools import (
    AttributeProfileKey as APKey,
    InspectIs as Is,
    ProfileConstant as PrfC,
    Tag as ITag,
    ParameterDetail,
    attribute_name_compare_key, split_routine_parameters
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

MethodSignature = Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]
RoutineDetail = Tuple[str, MethodSignature]
AttributeDetail = Tuple[StrOrTag, Tuple]

AttributeProfile = Tuple[StrOrTag, str, Tuple[StrOrTag, types.ModuleType], Tuple[str, ...],
                         Tuple[AttributeDetail, StrOrTag]]

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
    # END_DETAIL = ParameterDetail(name='z', kind='KEYWORD', annotation='str', default=None)
    END_DETAIL = ParameterDetail(name='z', kind='undefined', annotation='str', default=None)
    """EOF marker for processing ParameterDetail instances"""

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

    def _handle_matched_attribute(self, name: str, context: MatchPair,
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

        base_attr_details = profile_base[APKey.details]
        port_attr_details = profile_port[APKey.details]
        # chain functions. First that returns true skips remainder.
        if self._check_category_discrepancy(name, context, base_attr_details, port_attr_details) \
                or self._check_different_category_key(name, context, base_attr_details,
                                                      port_attr_details) \
                or self._check_data_leaf(name, context, base_attr_details, port_attr_details):
            return
        self._check_published_changes(name, context)
        # chain functions. First that returns true skips remainder.
        if self._check_data_node(name, context, base_attr_details) \
                or self._check_special_leaf(name, context, base_attr_details, port_attr_details) \
                or self._check_expandable(name, context, base_attr_details, port_attr_details) \
                or self._check_expand_cutoff(name, context, base_attr_details, port_attr_details):
            return
        self._check_only_routine(name, context, base_attr_details, port_attr_details)
        self._check_routine_data_structure(name, context, base_attr_details, port_attr_details)
        self._handle_matched_routine(name, context, base_attr_details, port_attr_details)

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
            base_attr_details: Tuple[StrOrTag, tuple],
            port_attr_details: Tuple[StrOrTag, tuple]) -> None:
        """
        Reports unexpected structure conditions for category information.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_attr_details (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_attr_details (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        if len(base_attr_details) != len(port_attr_details):
            self._send_match_diff_header(name, context)
            self.report.matched(
                f'  Context length {len(base_attr_details)} not = {len(port_attr_details)}: '
                'cannot compare further')
            self.report.matched(f'    {base_attr_details}')
            self.report.matched(f'    {port_attr_details}')
            return True
        if len(base_attr_details) != 2:
            self._send_match_diff_header(name, context)
            self.report.matched(f'  Odd(unhandled) context size {len(base_attr_details)}:')
            self.report.matched(f'    {base_attr_details}')
            self.report.matched(f'    {port_attr_details}')
            return True
        return False

    def _check_different_category_key(self, name: str, context: MatchPair,
            base_attr_details: Tuple[StrOrTag, tuple],
            port_attr_details: Tuple[StrOrTag, tuple]) -> None:
        """
        Reports different category identifier for base and port implementations.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_attr_details (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_attr_details (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        if base_attr_details[APKey.context] != port_attr_details[APKey.context]:
            self._send_match_diff_header(name, context)
            self.report.matched(f'  Base detail key {base_attr_details[APKey.context]} ' +
                       f'not equal port key {port_attr_details[APKey.context]}: '
                       'cannot compare further')
            self.report.matched(f'    {base_attr_details}')
            self.report.matched(f'    {port_attr_details}')
            return True
        return False

    def _check_data_leaf(self, name: str, context: MatchPair,
            base_attr_details: Tuple[StrOrTag, tuple],
            port_attr_details: Tuple[StrOrTag, tuple]) -> None:
        """
        Report differences data leaf (literal) values.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_attr_details (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_attr_details (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        if base_attr_details[APKey.context] in ContextSet.data_leaf:
            if base_attr_details[APKey.detail] == port_attr_details[APKey.detail]:
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
            self.report.matched(f'    base content = {base_attr_details[APKey.detail]:.50}')
            self.report.matched(f'    port content = {port_attr_details[APKey.detail]:.50}')
            return True
        return False

    def _is_ignored_docstring(self, name: str, context: MatchPair) -> bool:
        """
        check if the attribute is a docstring that is to be ignored (for differences).

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
        Reports attribute published status differences.

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

    def _check_data_node(self, name: str, context: MatchPair, base_attr_details: Tuple) -> bool:
        """
        Reports pending expansion of matching data nodes.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_attr_details (Tuple): The base profile attribute details.

        Returns
            True when a data node has been found, False otherwise.
        """
        if base_attr_details[APKey.context] in ContextSet.data_node:
            self._queue_attribute_expansion(name, context)
            if not self._shared[Key.sent_header_diff]:  # Exact match (so far)
                if self.settings.report_exact:
                    self.report.matched_logger.info(f'"{name}" Expand matched node: ' +
                        f'{context.base.context_data.path}¦{context.port.context_data.path}')
            return True
        return False

    def _check_special_leaf(self, name: str, context: MatchPair,
                         base_attr_details: Tuple, port_attr_details: Tuple) -> bool:
        """
        Reports leaf type match details.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_attr_details (Tuple): The base profile attribute details.
            port_attr_details (Tuple): The port profile attribute details.

        Returns
            True when a leaf type has been found, False otherwise.
        """
        if base_attr_details[APKey.context] in ContextSet.other_leaf:
            if base_attr_details[APKey.detail] == port_attr_details[APKey.detail]:
                if self.settings.report_exact:
                    self.report.matched(f'"{name}" category {base_attr_details[APKey.context]} ' +
                        f'  Details Matched: {base_attr_details[APKey.detail]}')
            else:
                self._send_match_diff_header(name, context)
                self.report.matched(f'  compare context: Base {base_attr_details};' +
                                    f' Port {port_attr_details}')
            return True
        return False

    def _check_expandable(self, name: str, context: MatchPair, base_attr_details: Tuple,
                             port_attr_details: Tuple) -> bool:
        """
        Adds expandable attribute to the queue.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_attr_details (Tuple): The base profile attribute details.
            port_attr_details (Tuple): The port profile attribute details.

        Returns
            True when an expandable attribute has been found, False otherwise.
        """
        if base_attr_details[APKey.detail] is SentinelTag(PrfC.expandable):
            if port_attr_details[APKey.detail] is not SentinelTag(PrfC.expandable):
                self._logger(f'"{name}" ' +
                    f'<{context.base.context_data.path}¦{context.port.context_data.path}> ' +
                    f'category {base_attr_details[APKey.context]}, ' +
                    f'base is {repr(base_attr_details[APKey.detail])}, ' +
                    f'but port is {repr(port_attr_details[APKey.detail])}')
                raise ApplicationDataError(
                    f'"{name}" base {base_attr_details[APKey.context]} is expandable, but ' +
                    f'port is {repr(port_attr_details[APKey.detail])}')
            if base_attr_details[APKey.context] not in ContextSet.descriptor:
                self._logger(f'"{name}" ' +
                    f'<{context.base.context_data.path}¦{context.port.context_data.path}> ' +
                    f' category {base_attr_details[APKey.context]} ' +
                    f'not in {repr(set(ContextSet.descriptor))}')
                raise ApplicationDataError(
                    f'Unhandled expand for {base_attr_details[APKey.context]} ' +
                    f'category for "{name}" attribute.')
            self._queue_attribute_expansion(name, context)
            if not self._shared[Key.sent_header_diff]:  # Exact match (so far)
                if self.settings.report_exact:
                    self.report.matched(f'"{name}" Expand both for ' +
                        f'{base_attr_details[APKey.context]}: ' +
                        f'{context.base.context_data.path}¦{context.port.context_data.path}')
            return True
        return False

    def _check_expand_cutoff(self, name: str, context: MatchPair, base_attr_details: Tuple,
                             port_attr_details: Tuple) -> bool:
        """
        Reports nested expansion cutoff tag.

        Args:
            context (MatchPair): The context data for the base and port implementations.
            name (str): The name of the matched attribute.
            base_attr_details (Tuple): The base profile attribute details.
            port_attr_details (Tuple): The port profile attribute details.

        Returns
            True when an expandable attribute has been found, False otherwise.
        """
        if base_attr_details[APKey.detail] is SentinelTag(PrfC.cutoff):
            if port_attr_details[APKey.detail] is not SentinelTag(PrfC.cutoff):
                self._logger(f'"{name}" ' +
                    f'<{context.base.context_data.path}¦{context.port.context_data.path}> ' +
                    f' category {base_attr_details[APKey.context]} with base detail ' +
                    f'{repr(base_attr_details[APKey.detail])} but port detail' +
                    f'{repr(port_attr_details[APKey.detail])} but port detail')
                raise ApplicationDataError(
                    f'"{name}" is cutoff for {context.base.context_data.path} ' +
                    f'but not for {context.port.context_data.path}')
            if base_attr_details[APKey.context] not in ContextSet.dunder:
                self._logger(f'"{name}" ' +
                    f'<{context.base.context_data.path}¦{context.port.context_data.path}> ' +
                    f' category {base_attr_details[APKey.context]} is not in ' +
                    f'{repr(set(ContextSet.dunder))} for {repr(base_attr_details[APKey.detail])}')
                raise ApplicationDataError('Self tag context '
                    f'"{base_attr_details[APKey.context]}" found for "{name}" attribute.')
            return True
        return False

    def _check_only_routine(self, name: str, context: MatchPair,
                               base_attr_details: RoutineDetail,
                               port_attr_details: RoutineDetail) -> None:
        """
        Checks that the category information is for a function.

        Everything else should already have been processed.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_attr_details (tuple): the base implementation function signature information.
            port_attr_details (tuple): the port implementation function signature information.
                RoutineDetail is Tuple[str, MethodSignature]
                MethodSignature is Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]

        Raises:
            ApplicationDataError if either base or port context key is not for a function.
        """
        if base_attr_details[APKey.context] not in ContextSet.routine:
            self._logger.error(
                f'"{name}" <{context.base.context_data.path}> ' +
                f'had unhandled detail category {base_attr_details[APKey.context]}.\n' +
                f'  expecting {repr(set(ContextSet.routine))}')
            raise ApplicationDataError(
                f'unhandled "{base_attr_details[APKey.context]}" context for ' +
                f'"{name}"¦{context.base.context_data.path}¦{context.port.context_data.path}.\n' +
                f'  Base detail: {base_attr_details[APKey.detail]}\n' +
                f'  Port detail: {port_attr_details[APKey.detail]}')
        if port_attr_details[APKey.context] not in ContextSet.routine:
            self._logger.error(
                f'"{name}" <{context.port.context_data.path}> ' +
                f'had unhandled detail category {base_attr_details[APKey.context]}.\n' +
                f'  expecting {repr(set(ContextSet.routine))}')
            raise ApplicationDataError(
                f'unhandled "{base_attr_details[APKey.context]}" context for ' +
                f'"{name}"¦{context.base.context_data.path}¦{context.port.context_data.path}.\n' +
                f'  Base detail: {base_attr_details[APKey.detail]}\n' +
                f'  Port detail: {port_attr_details[APKey.detail]}')

    def _check_routine_data_structure(self, name: str, context: MatchPair,
                               base_attr_details: RoutineDetail,
                               port_attr_details: RoutineDetail) -> bool:
        """
        Checks that the function profile detail data is in the expected structure.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_attr_details (tuple): the base implementation function signature information.
            port_attr_details (tuple): the port implementation function signature information.
                RoutineDetail is Tuple[str, MethodSignature]
                MethodSignature is Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]

        Raises:
            ApplicationDataError if the profile detail data structure is not for a function.
        """

        if not (isinstance(base_attr_details[APKey.detail], tuple) and
                isinstance(port_attr_details[APKey.detail], tuple)):
            self._logger.error(
                f'"{name}" <{context.base.context_data.path}¦{context.port.context_data.path}> ' +
                'routine category expected detail types (tuple,tuple): found (' +
                f'{type(base_attr_details[APKey.detail]).__name__},' +
                f'{type(port_attr_details[APKey.detail]).__name__})')
            raise ApplicationDataError(
                f'"{name}" {base_attr_details[APKey.context]} detail types are ' +
                f'{type(base_attr_details[APKey.detail]).__name__},' +
                f'{type(port_attr_details[APKey.detail]).__name__} instead of tuple,tuple')
        if not (len(base_attr_details[APKey.detail]) == APKey.sig_elements and
                len(port_attr_details[APKey.detail]) == APKey.sig_elements):
            self._logger(
                f'"{name}" <{context.base.context_data.path}¦{context.port.context_data.path}> ' +
                'routine category detail items counts are (' +
                f'{len(base_attr_details[APKey.detail])},' +
                f'{len(port_attr_details[APKey.detail])}), ' +
                f'not {APKey.sig_elements},{APKey.sig_elements}),')
            self._logger(f'  Base details: {base_attr_details[APKey.detail]}')
            self._logger(f'  Port details: {port_attr_details[APKey.detail]}')
            raise ApplicationDataError(
                f'"{name}" {base_attr_details[APKey.context]} detail tuples contain ' +
                f'{len(base_attr_details[APKey.detail])},{len(port_attr_details[APKey.detail])} ' +
                f'elements: expecting {APKey.sig_elements},{APKey.sig_elements}')

    def _handle_matched_routine(self, name: str, context: MatchPair,
                               base_attr_details: RoutineDetail,
                               port_attr_details: RoutineDetail) -> bool:
        """
        Handle reporting (miss) matches of signatures for matched function elements.

        This looks at function parameter details, the return type annotation, and the
        function docstring.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_attr_details (tuple): the base implementation function signature information
            port_attr_details (tuple): the port implementation function signature information
                RoutineDetail is Tuple[str, MethodSignature]
                MethodSignature is Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]
        """
        self._handle_parameter_comparison(name, context, base_attr_details, port_attr_details)
        self._check_return_annotation(name, context,
            base_attr_details[APKey.detail], port_attr_details[APKey.detail])
        self._check_routine_docstring(name, context,
            base_attr_details[APKey.detail], port_attr_details[APKey.detail])

    def _handle_parameter_comparison(self, name: str, context: MatchPair,
            base_attr_details: RoutineDetail, port_attr_details: RoutineDetail) -> None:
        """
        Reports differences in method parameter details.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_attr_details (RoutineDetail): full category information for base implementation.
            port_attr_details (RoutineDetail): full category information for port implementation.
                RoutineDetail is Tuple[str, MethodSignature]
                MethodSignature is Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]
        """
        base_positional, base_keywords = split_routine_parameters(
            base_attr_details[APKey.detail][APKey.sig_parameters])
        port_positional, port_keywords = split_routine_parameters(
            port_attr_details[APKey.detail][APKey.sig_parameters])
        self._shared[Key.sent_header_sig] = False

        # Compare positional parameters
        min_len = min(len(base_positional), len(port_positional))
        max_len = max(len(base_positional), len(port_positional))
        for key in range(max_len):
            kind_header = self._param_prefix(key)
            if key < min_len:
                self._compare_parameter_detail(name, context, kind_header,
                                               base_positional[key], port_positional[key])
            elif key < len(base_positional):
                self._report_unmatched_positional_parameter(
                    name, context, key, base_positional[key], is_port_extension=False)
            else:
                self._report_unmatched_positional_parameter(
                    name, context, key, port_positional[key], is_port_extension=True)

        # Compare keyword parameters
        base_names = frozenset({param.name for param in base_positional})
        port_names = frozenset({param.name for param in port_positional})
        for key in set(base_keywords.keys()).union(port_keywords.keys()):
            kind_header = self._param_prefix(key)
            if key in base_keywords and key in port_keywords:
                self._compare_parameter_detail(name, context, kind_header,
                                               base_keywords[key], port_keywords[key])
            elif key in base_keywords:
                self._report_unmatched_keyword_parameter(
                    name, context, base_keywords[key], port_names, is_port_extension=False)
            else:
                self._report_unmatched_keyword_parameter(
                    name, context, port_keywords[key], base_names, is_port_extension=True)

    def _compare_parameter_detail(self, name: str, context: MatchPair, param_ref: str,  # pylint:disable=too-many-arguments,line-too-long
                                base_det: ParameterDetail, port_det: ParameterDetail) -> None:
        """
        Compare and report differences in individual parameter details.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            param_ref (str): formatted prefix for positional or keyword parameter.
            base_det (ParameterDetail): Detail from the base implementation.
            port_det (ParameterDetail): Detail from the port implementation.
        """
        if base_det.name != port_det.name:
            # only applies to positional parameters
            self._send_match_sig_header(name, context)
            self.report.matched(
                f'{param_ref} name: base "{base_det.name}"; port "{port_det.name}"')
        if base_det.kind != port_det.kind:
            self._send_match_sig_header(name, context)
            self.report.matched(
                f'{param_ref} kind: base "{base_det.kind}"; port "{port_det.kind}"')
        if base_det.annotation != port_det.annotation and \
                base_det.annotation is SentinelTag(ITag.NO_PARAMETER_ANNOTATION) and \
                not self.settings.annotation_ignore_parameter:
            self._send_match_sig_header(name, context)
            # pylint:disable=line-too-long
            self.report.matched(f'{param_ref} annotation: ' +
                f'base {annotation_str(base_det.annotation, SentinelTag(ITag.NO_PARAMETER_ANNOTATION))}; ' +
                f'port {annotation_str(port_det.annotation, SentinelTag(ITag.NO_PARAMETER_ANNOTATION))}')
        if base_det.default != port_det.default:
            self._send_match_sig_header(name, context)
            self.report.matched(f'{param_ref} default: ' +
                f'base {default_str(base_det.default)}; ' +
                f'port {default_str(port_det.default)}')

    def _report_unmatched_positional_parameter(self, name: str, context: MatchPair, index: int,  # pylint:disable=too-many-arguments,line-too-long
            parameter: ParameterDetail, is_port_extension: bool) -> None:
        """
        report a (positional) parameter that exists in one implementation but not the other.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            index (int): existing positional parameter index
            parameter (ParameterDetail): The positional parameter that exists in only one
                implementation.
            is_port_extension (bool): when True, exists in port not base, when False the reverse
        """
        self._send_match_sig_header(name, context)
        exists_in, missing_from = (Key.port_implementation, Key.base_implementation) \
            if is_port_extension else (Key.base_implementation, Key.port_implementation)
        self.report.matched(f'    positional parameter {index} exists in {exists_in}, ' +
                            f'but not in {missing_from} implementation: {repr(parameter)}')

    def _report_unmatched_keyword_parameter(  # pylint:disable=too-many-arguments
            self, name: str, context: MatchPair, parameter: ParameterDetail,
            positional_names: FrozenSet[str], is_port_extension: bool) -> None:
        """
        Report a (keyword )parameter that exists in one implementation but not the other.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            parameter (ParameterDetail): The keyword parameter that exists in only one
                implementation.
            positional_names (FrozenSet[str]): positional parameter names as alternate matches
            is_port_extension (bool): when True, exists in port not base, when False the reverse
        """
        self._send_match_sig_header(name, context)
        exists_in, missing_from = (Key.port_implementation, Key.base_implementation) \
            if is_port_extension else (Key.base_implementation, Key.port_implementation)
        if parameter.name in positional_names:
            self.report.matched(
                f'    keyword parameter exists in {exists_in}, but is a positional ' +
                f'parameter in {missing_from} implementation: {repr(parameter)}')
        else:
            self.report.matched(
                f'    keyword parameter exists in {exists_in}, but not in ' +
                f'{missing_from} implementation: {repr(parameter)}')

    def _param_prefix(self, index_or_name: Union[int, str]) -> str:
        """
        formatted indexed positional parameter information prefix

        Args:
            index_or_name (Union[int, str]): positional parameter index or keyword parameter name
        """
        if isinstance(index_or_name, int):
            return f'    positional parameter {index_or_name}'
        return f'    {index_or_name} keyword parameter'

    def _check_return_annotation(self, name: str, context: MatchPair, base_sig: MethodSignature,
                                 port_sig: MethodSignature) -> None:
        """
        Reports differences in method return type annotation

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_sig (MethodSignature) method signature information for base implementation.
            port_sig (MethodSignature) method signature information for port implementation.
                MethodSignature is Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]
        """
        if base_sig[APKey.sig_return] != port_sig[APKey.sig_return] and \
                base_sig[APKey.sig_return] is SentinelTag(ITag.NO_RETURN_ANNOTATION) and \
                not self.settings.annotation_ignore_return:
            self._send_match_sig_header(name, context)
            self.report.matched('    routine return annotation: base '
                f'{_fmt_return_annotation(base_sig)}; port {_fmt_return_annotation(port_sig)}')

    def _check_routine_docstring(self, name: str, context: MatchPair, base_sig: MethodSignature,
                                 port_sig: MethodSignature) -> None:
        """
        Reports changes to method docstring

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_sig (MethodSignature) method signature information for base implementation.
            port_sig (MethodSignature) method signature information for port implementation.
                MethodSignature is Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]
        """
        if base_sig[APKey.sig_doc] != port_sig[APKey.sig_doc] and \
                not self.settings.docstring_ignore_method:
            self._send_match_sig_header(name, context)
            self.report.matched(f'    routine docstring: base ¦{base_sig[APKey.sig_doc]}¦; ' +
                             f'port ¦{port_sig[APKey.sig_doc]}¦')

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

    def _send_match_sig_header(self, name: str, context: MatchPair) -> None:
        """
        Send a (method signature block) header line, if it has not yet been sent

        Args:
            name (str) the name of the attribute being reported
            context (MatchPair): The context data for the base and port implementations.
        """
        self._send_match_diff_header(name, context)
        if not self._shared[Key.sent_header_sig]:
            self.report.matched('  Method Parameters:')
            self._shared[Key.sent_header_sig] = True

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

def _fmt_return_annotation(sig_data: tuple) -> str:
    """
    get return type annotation from routine signature details

    Args:
        sig_data (tuple): signature profile information for a routine
    """
    return annotation_str(sig_data[APKey.sig_return], SentinelTag(ITag.NO_RETURN_ANNOTATION))

if __name__ == "__main__":
    app = CompareModuleAPI()
    app.process_expand_queue()

# cSpell:words pathlib backslashreplace levelname DATADESCRIPTOR DUNDER
# cSpell:ignore fstring
# cSpell:allowCompoundWords true
