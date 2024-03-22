# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""attribute profiling iteration prototyping"""
# pylint:disable=too-many-lines

import types
from typing import Iterable, Tuple, Hashable, Union, Dict, FrozenSet
from collections import namedtuple
from dataclasses import dataclass
# import inspect
import logging
from queue import Queue
from prototype_import import import_module
from prototype_support import (
    ApplicationFlagError,
    ObjectContextData,
    ListHandler,
    SentinelTag,
    Tag,
    InspectIs as Is,
    ProfileConstant as PrfC,
    ParameterDetail,
    attribute_name_compare_key,
    get_attribute_info,
    # get_object_context_data,
    populate_object_context,
)
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

StrOrTag = Union[str, SentinelTag]
MethodSignatureDetail = Tuple[str, Tuple[Tuple[ParameterDetail, ...], StrOrTag]]
AttributeProfile = Tuple[StrOrTag, str, Tuple[StrOrTag, types.ModuleType], Tuple[str, ...],
                         Tuple[tuple, StrOrTag]]
"""
    parent context typehint annotation
    type
    (source file path, source module)
    ("is" keywords)
    «hpd need to expand»
"""

@dataclass(frozen=True)
class Key:
    """
    Constants for lookup indexes, to avoid possible typos in strings used to reference them
    """
    # pylint:disable=invalid-name,too-many-instance-attributes
    REPORT_NOT_IMPLEMENTED: str = 'not implemented in port'
    REPORT_EXTENSION: str = 'extension in port'
    REPORT_ATTRIBUTE_SKIPPED: str = 'attribute skipped'
    REPORT_MATCHED_ATTRIBUTE: str = 'matched attribute'
    POS_IDX: str = 'positional index'
    KEY_IDX: str = 'keyword index'
    HDR_SENT_SIG: str = 'signature header sent'
    HDR_SENT_DIF: str = 'diff header sent'
    POS_PARAM_TYPE: str = 'positional'
    KEY_PARAM_TYPE: str = 'keyword'
    COMPARE_NAME: int = 1
    INFO_NAME: int = 0
    INFO_PROFILE: int = 1
    PROFILE_ELEMENTS: int = 5
    PROFILE_ANNOTATION: int = 0
    PROFILE_TYPE: int = 1
    PROFILE_SOURCE: int = 2
    SOURCE_ELEMENTS: int = 2
    SOURCE_FILE: int = 0
    SOURCE_MODULE: int = 1
    PROFILE_TAGS: int = 3
    PROFILE_DETAIL: int = 4
    DETAIL_ELEMENTS: int = 2
    DETAIL_KEY: int = 0
    DETAIL_CONTENT: int = 1
    SIG_ELEMENTS: int = 3
    SIG_PARAMETERS: int = 0
    SIG_RETURN: int = 1
    SIG_DOC: int = 2

@dataclass(frozen=True)
class Cfg:
    """
    Constants for configuration settings lookup
    """
    profile_scope: str = 'scope of attributes'
    report_exact: str = 'report exact matches'
    ignore_differences: str = 'ignore specified differences'
    all_scope: str = 'all'
    published_scope: str = 'published'
    public_scope: str = 'public'

@dataclass(frozen=True)
class Ignore:
    """
    Constants for reportable items to suppress
    """
    docstring: str = 'docstring'
    scope_annotation: str = 'scope level annotation'

@dataclass(frozen=True)
class Match:
    """
    Constants for string matching, to avoid possible typos in strings used to compare them
    """
    # pylint:disable=invalid-name
    POSITIONAL: str = 'POSITIONAL'

@dataclass()
class MatchPair:
    """
    Details about the current base and port queue entries being processed.
    """
    base: ObjectContextData
    port: ObjectContextData

class ProfilePrototype:
    """
    Create profiles and compare the api for a pair of modules
    """
    HIGH_VALUES = attribute_name_compare_key('_~')
    """High-value sentinel, lexicographically greater than any valid attribute name

    For added certainty, could use a lexicographically higher utf-8 character. Like '°' (degrees)

    With the sort order used, private attribute names sort last
    """
    END_DETAIL = ParameterDetail(name='z', kind='KEYWORD', annotation='str', default=None)
    """Default value to use instead, to avoid issues testing fields"""
    DYNAMIC_MODULE_ATTRIBUTES = frozenset({'__builtins__', '__cached__', '__file__', '__package__'})
    """Attribute names that are dynamically populated for a package (when it is loaded),
    that are not useful for comparing implementations"""

    def __init__(self, module_base_name: str, module_port_name: str):
        """
        Initializes the ProfilePrototype instance with base and port module names.

        Args:
            module_base_name (str): The name of the base module.
            module_port_name (str): The name of the ported module.
        """
        self._base_module = module_base_name
        self._port_module = module_port_name
        self._configuration_settings: Dict[str, str] = {}  # Configuration settings
        self.load_configuration()  # Loads configuration settings
        self._reports: Dict[str, logging.Logger] = {}
        self._reports[Key.REPORT_NOT_IMPLEMENTED] = self.create_logger(Key.REPORT_NOT_IMPLEMENTED)
        self._reports[Key.REPORT_EXTENSION] = self.create_logger(Key.REPORT_EXTENSION)
        self._reports[Key.REPORT_MATCHED_ATTRIBUTE] = \
            self.create_logger(Key.REPORT_MATCHED_ATTRIBUTE)
        self._reports[Key.REPORT_ATTRIBUTE_SKIPPED] = \
            self.create_logger(Key.REPORT_ATTRIBUTE_SKIPPED)
        self._shared: Dict[str, Union[int, bool]] = {}
        self._expand_queue = Queue()  # A FIFO queue
        self._expand_queue.put(MatchingContext(
            base_path=(module_base_name,),
            port_path=(module_port_name,),
            base_element=import_module(module_base_name),
            port_element=import_module(module_port_name)))

    def create_logger(self, context: str) -> logging.Logger:
        """
        get a custom logger to use to accumulate information for a specific context

        Args:
            context (str): The context name for the accumulated information.
        Returns:
            an initialized Logger instance with custom handler
        """
        list_handler = ListHandler()
        list_handler.setLevel(1)
        new_logger = logging.getLogger(context)
        # Make sure this really is a new logger instance, not getting one previously created
        assert len(new_logger.handlers) == 0, \
            f'new logger "{context}" has {len(new_logger.handlers)} ' \
            'handlers: should be 0'
        # With logging hierarchy, effective level becomes for first non-zero level going up the
        # «parent» chain. The default root logger level is 30, so that is what this becomes if
        # set to zero. Use level 1 to avoid interaction with the root logger level.
        new_logger.setLevel(1)
        new_logger.addHandler(list_handler)
        new_logger.propagate = False
        return new_logger

    def get_logger(self, context: str) -> logging.Logger:
        """
        Get a previously configured custom logger

        Args:
            context (str): The context name for the logger.
        Returns:
            an existing Logger instance with custom handler
        """
        existing_logger = logging.getLogger(context)
        assert len(existing_logger.handlers) == 1, \
            f'custom logger "{context}" has {len(existing_logger.handlers)} ' \
            'handlers: should only be 1'
        assert isinstance(existing_logger.handlers[0], ListHandler), \
            f'custom logger "{context}" has {type(existing_logger.handlers[0])} ' \
            'handler, instead of ListHandler'
        return existing_logger

    def load_configuration(self) -> None:
        """Loads configuration settings.

        Simulate getting application specific configuration data from external sources
        - user and project configuration files
        - command line arguments
        """
        # populate builtin default configuration
        self._configuration_settings = {
            'strictness': {
                'ignore_docstrings': (),  # module, class, method
                'ignore_added_annotations': (),  # parameter, return, scope
                'ignore_attributes': {
                    'global': (),
                    'module': (),
                    'class': (),
                    # Additional contexts as needed
                },
            },
            'report': {
                'difference_in_matched': True,
                'exact_match': True,
                'not_implemented_in_port': True,
                'extension_in_port': True,
            },
            Cfg.profile_scope: Cfg.all_scope,  # or 'public', 'published'
        }
        # attr_scope = getattr(module, 'ATTR_SCOPE', 'all')
        # self._configuration_settings[Cfg.profile_scope] = getattr(module, 'ATTR_SCOPE', 'all')
        # module level variables
        self._configuration_settings[Cfg.ignore_differences] = set()
        self._configuration_settings[Cfg.profile_scope] = ATTR_SCOPE
        self._configuration_settings[Cfg.report_exact] = REPORT_EXACT_MATCH
        if IGNORE_DOCSTRING_DIFFERENCES:
            self._configuration_settings[Cfg.ignore_differences].add(Ignore.docstring)

    def get_configuration(self, key: str) -> Union[bool, str, set]:
        """
        Get a configuration setting

        Args:
            key (str): The name of the configuration setting

        Returns The value for the configuration
            Union[bool, str, set]

        Raises
            KeyError if no configuration has been set for the requested key
        """
        # if key == Cfg.profile_scope:
        return self._configuration_settings[key]

    def iterate_object_attributes(self, impl_source: str,
                                  context: ObjectContextData) -> Iterable[Tuple[str, Tuple]]:
        """
        Iterates over attributes of an object in (custom) sorted order, handling errors in
        attribute information retrieval. This method dynamically adjusts the scope of
        attributes based on the implementation source ('base' or 'port') and predefined
        configuration settings.

        Configuration inputs:
            attr_scope (str): Determines the scope used for filtering attribute names in the
                'base' module. Can be 'all', 'published', or 'public'. The scope is overridden
                to 'all' for the 'port' module, ensuring comprehensive coverage for comparison,
                including identifying attributes that are unique to or missing from either
                implementation. This setting is critical for tailoring the attribute comparison
                process to specific requirements or conventions of the modules being compared.

        Args:
            impl_source (str): Specifies the context of the object being processed.
                Acceptable values are 'base' or 'port'. This distinction allows for
                differentiated handling of the attribute set, especially relevant for
                comparisons where one might want to ensure a ported module includes all
                relevant attributes from the base module and to identify any additional
                attributes introduced in the port.
            context (ObjectContextData): dataclass instance with path and element filled in

        Updates context instance

        Yields:
            Iterable[Tuple[Tuple[int, str], Tuple]]: An iterable of tuples, each containing the
                sort key of an attribute name and a tuple with collected profile information.
                This output is crucial for subsequent comparison or analysis steps, providing
                detailed insights into the attributes present in each module and facilitating a
                thorough review of the API compatibility and completeness.
        """
        populate_object_context(context)
        attr_scope = self.get_configuration(Cfg.profile_scope) if impl_source == 'base' else 'all'
        # if context.mode == 'namedtuple':
        #     # for namedtuple element only look at the attributes specified in _fields
        #     attr_scope = 'published'
        #     # handled as a Data:Leaf at the parent level
        if context.mode in ('sequence', 'key_value'):
            # for sequence and dict type elements only look at the the contained elements
            attr_scope = 'published'
        attr_names = {
            'all': context.all,
            'published': context.published \
                if context.published else context.public,
            'public': context.public
        }.get(attr_scope, context.all)
        rpt_target = self._reports[Key.REPORT_ATTRIBUTE_SKIPPED]

        ignorable = self.get_ignored_attributes(context)
        for name in sorted(attr_names, key=attribute_name_compare_key):
            if name in ignorable:
                # skip ignored attribute names (for context)
                self.report_iterate_skip(context, (attribute_name_compare_key(name),
                                                   SentinelTag('Exclude by name')))
                continue
            raw_result = get_attribute_info(context, name)
            assert raw_result[Key.INFO_NAME] == name, 'get_attribute_info should return the ' \
                f'requested attribute name: "{raw_result[Key.INFO_PROFILE]}" not equal "{name}"'
            result = (attribute_name_compare_key(name),) + raw_result[1:]
            if isinstance(result[Key.INFO_PROFILE], ApplicationFlagError):
                rpt_target.error(f'**** Error accessing {context.path} "{name}" attribute: ' +
                    f'{result}')
                context.skipped += 1
                print(f'{result[Key.INFO_NAME]} {context.path} skipped')  # TRACE
                continue
            if self.filter_by_source(context, name, result):
                continue
            key = result[Key.INFO_PROFILE][Key.PROFILE_DETAIL][Key.DETAIL_CONTENT]
            if key is SentinelTag(Tag.SYS_EXCLUDE) or key is SentinelTag(Tag.BUILTIN_EXCLUDE):
                self.report_iterate_skip(context, result)
                continue
            yield result

    def get_ignored_attributes(self, context: ObjectContextData) -> FrozenSet:
        """
        return the set of attribute names that are to be skipped for the current context

        Args:
            context (ObjectContextData): dataclass instance with path and element filled in

        Returns (FrozenSet) of attribute names identified to not be included in the current
            context for profile matching.
        """
        if isinstance(context.element, types.ModuleType) and len(context.path) == 1:
            return self.DYNAMIC_MODULE_ATTRIBUTES
        # if isinstance(context.element, type):  # a class
        return frozenset()

    def filter_by_source(self, context: ObjectContextData, name: str, result: tuple) -> bool:
        """
        detect attribute (profiles) that are to be skipped based on the source (module)

        Args:
            context (ObjectContextData): dataclass instance with path and element filled in
            name (str): the name of the attribute being profiled
            result (tuple): collected profile information for the attribute

        Returns True is the attribute is to be discarded, else False
        """
        src_file, src_module = result[Key.INFO_PROFILE][Key.PROFILE_SOURCE]
        # if not ((src_file is SentinelTag(Tag.NO_SOURCE) and src_module is None) or \
        #         (src_file == context.source and src_module is context.module) or \
        #         (src_file is SentinelTag(Tag.NO_SOURCE) and src_module is context.module)):
        if not ((src_file is SentinelTag(Tag.NO_SOURCE) and src_module is None) or \
                ((src_file == context.source or src_file is SentinelTag(Tag.NO_SOURCE)) and \
                 src_module is context.module)):
            if src_file is SentinelTag(Tag.BUILTIN_EXCLUDE):
                self.report_iterate_skip(context, result)
                return True
            assert isinstance(src_module, types.ModuleType), \
                f'{type(src_module).__name__ = } for {name} in {context.path}: {result}'
            assert src_file is SentinelTag(Tag.NO_SOURCE) or \
                src_file is SentinelTag(Tag.GET_SOURCE_FAILURE) or isinstance(src_file, str), \
                f'{type(src_file).__name__ = } for {name} in {context.path}: {result}'
            self.report_iterate_skip(context, result)
            return True
            # debug_modules_without_str = ('typing',
            #     'importlib._bootstrap_external', 'importlib._bootstrap',
            #     '_weakrefset', 'weakref', '_thread', 'string',
            # )
            # debug_modules_with_str = ('types', 'typing', 'string', 'collections', 'io', 'os',
            #     're', 'threading', 'traceback', 'warnings', 'weakref',
            # )
            # if src_file is SentinelTag(Tag.NO_SOURCE):
            #     if src_module.__name__ in debug_modules_without_str:
            #         self.report_iterate_skip(context, result)
            #         return True
            # else:
            #     if src_module.__name__ in debug_modules_with_str:
            #         self.report_iterate_skip(context, result)
            #         return True
            # assert src_module == context.module, \
            #     f'not {context.path} module {context.module}: {result}'
        return False

    def report_iterate_skip(self, context: ObjectContextData,
                            result: Union[tuple, SentinelTag]) -> None:
        """
        report an attribute being skipped before yielding to process it

        Args:
            impl_source (str): the implementation of the attribute; base or port
            profile:
                (tuple): the information collected for the attribute implementation
                (SentinelTag): marker when no attempt has been made to collect attribute information
        """
        rpt_target = self._reports[Key.REPORT_ATTRIBUTE_SKIPPED]
        if not isinstance(result, tuple):
            assert result is SentinelTag('Exclude by name')
        rpt_target.info(f'{context.path} '
                        f'{result}')
        print(f'{result[Key.INFO_NAME]} {context.path} skipped')  # TRACE
        context.skipped += 1

    def process_expand_queue(self) -> None:
        """
        Compares attributes profiles between base and port implementations based on the
        configuration settings.
        """
        debug_count = 0
        match_count, not_impl_count, extension_count = 0, 0, 0
        base_skip_count, port_skip_count = 0, 0
        while not self._expand_queue.empty():
            # Get an entry from the self.expand_queue and process it
            que_ent: MatchingContext = self._expand_queue.get()
            match_pair = MatchPair(
                base=ObjectContextData(path=que_ent.base_path, element=que_ent.base_element),
                port=ObjectContextData(path=que_ent.port_path, element=que_ent.port_element))
            iter_base = self.iterate_object_attributes('base', match_pair.base)
            iter_port = self.iterate_object_attributes('port', match_pair.port)

            compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
            compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))
            while compare_base < self.HIGH_VALUES or compare_port < self.HIGH_VALUES:
                # print(min(compare_base, compare_port))
                if compare_base == compare_port:
                    print(f'{compare_base} both')  # TRACE
                    match_count += 1
                    self.handle_matched_attribute(match_pair, compare_base[Key.COMPARE_NAME],
                                                  profile_base, profile_port)
                    compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
                    compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))
                elif compare_base < compare_port:
                    print(f'{compare_base} {que_ent.base_path} not implemented')  # TRACE
                    not_impl_count += 1
                    self.handle_unmatched_attribute(match_pair, 'base',
                        compare_base[Key.COMPARE_NAME], profile_base)
                    compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
                else: # compare_base > compare_port
                    print(f'{compare_port} {que_ent.port_path} extension')  # TRACE
                    extension_count += 1
                    self.handle_unmatched_attribute(match_pair, 'port',
                        compare_port[Key.COMPARE_NAME], profile_port)
                    compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))
            # debug_count += 1
            base_skip_count += match_pair.base.skipped
            port_skip_count += match_pair.port.skipped
            if debug_count > 10:
                break  # DEBUG, abort further processing to see how the reporting is progressing

        print(f'\n{base_skip_count} base attributes skipped, {port_skip_count}'
              ' port attributes skipped.')
        print(f'{match_count} Matched, {not_impl_count} Not Implemented, and {extension_count} '
              'Extension attributes found.')
        self.report_match_details()

    def handle_matched_attribute(self, context: MatchPair, name: str,
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
        validate_profile_data(name, context.base, profile_base)
        validate_profile_data(name, context.port, profile_port)
        rpt_target = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        # need to watch for the need to expand both attributes
        self._shared[Key.HDR_SENT_DIF] = False
        if profile_base[Key.PROFILE_ANNOTATION] != profile_port[Key.PROFILE_ANNOTATION]:
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  Annotation: Base {profile_base[Key.PROFILE_ANNOTATION]};' +
                            f' Port {profile_port[Key.PROFILE_ANNOTATION]}')
        if profile_base[Key.PROFILE_TYPE] != profile_port[Key.PROFILE_TYPE]:
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  Type: Base {profile_base[Key.PROFILE_TYPE]};' +
                            f' Port {profile_port[Key.PROFILE_TYPE]}')
            # 'type' could match 'function'. A class constructor could do the same
            # as a function: logging._logRecordFactory
            # doing that sort of match is going to need smarter processing. Currently
            # a class is tagged for later expansion, while function signature is
            # handled in the current pass.
            # ?re-tag the function to be expanded? ?logic to only expand the constructor?
            # process the class constructor now, and match to function signature?
            # -- the class is its constructor??
        if profile_base[Key.PROFILE_TAGS] != profile_port[Key.PROFILE_TAGS]:
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  "is" tags: Base {profile_base[Key.PROFILE_TAGS]};' +
                            f' Port {profile_port[Key.PROFILE_TAGS]}')
        # compare profile_«»[Key.PROFILE_SOURCE]. Not expecting to match if part of packages
        # being compared

        base_category = profile_base[Key.PROFILE_DETAIL]
        port_category = profile_port[Key.PROFILE_DETAIL]
        if self._handle_simple_details(name, context, base_category, port_category):
            return
        if base_category[Key.DETAIL_KEY] is SentinelTag(Tag.DATA_NODE):
            self.queue_attribute_expansion(name, context)
            if not self._shared[Key.HDR_SENT_DIF]:  # Exact match (so far)
                if self.get_configuration(Cfg.report_exact):
                    rpt_target.info(
                        f'"{name}" Expand matched node: {context.base.path}¦{context.port.path}')
            return
        if not isinstance(base_category[Key.DETAIL_KEY], str):
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  compare context: Base {base_category};' +
                            f' Port {port_category}')
            return
        self._handle_str_category(name, context, base_category, port_category)

    def _handle_simple_details(self, name: str, context: MatchPair,
            base_category: Tuple[StrOrTag, tuple], port_category: Tuple[StrOrTag, tuple]):
        """
        Handle some of the simple checks for profile detail implementation differences

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_category (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_category (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        rpt_target = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        if len(base_category) != len(port_category):
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  Context length {len(base_category)} not = {len(port_category)}: '
                            'cannot compare further')
            rpt_target.info(f'    {base_category}')
            rpt_target.info(f'    {port_category}')
            return True
        if len(base_category) != 2:
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  Odd(unhandled) context size {len(base_category)}:')
            rpt_target.info(f'    {base_category}')
            rpt_target.info(f'    {port_category}')
            return True
        # len(handling_category) == 2
        if base_category[Key.DETAIL_KEY] != port_category[Key.DETAIL_KEY]:
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  Base detail key {base_category[Key.DETAIL_KEY]} ' +
                            f'not equal port key {port_category[Key.DETAIL_KEY]}: '
                            'cannot compare further')
            rpt_target.info(f'    {base_category}')
            rpt_target.info(f'    {port_category}')
            return True
        if base_category[Key.DETAIL_KEY] is SentinelTag(Tag.DATA_LEAF):
            if base_category[Key.DETAIL_CONTENT] == port_category[Key.DETAIL_CONTENT]:
                if not self._shared[Key.HDR_SENT_DIF]:  # Exact match
                    if self.get_configuration(Cfg.report_exact):
                        rpt_target.info(
                            f'"{name}" No Difference: {context.base.path}¦{context.port.path}')
                return True
            self.send_match_diff_header(name, context)
            rpt_target.info('  Literal value changed (possibly truncated):')
            # future: generic function to more smartly truncate content
            #  append … if truncated
            #  trim and collapse whitespace
            #  specify maximum length «account for appended ellipse»
            #  smarter: start with ellipse and make sure to show segment that is different
            rpt_target.info(f'    base content = {base_category[Key.DETAIL_CONTENT]:.50}')
            rpt_target.info(f'    port content = {port_category[Key.DETAIL_CONTENT]:.50}')
            return True
        return False

    def _handle_str_category(self, name: str, context: MatchPair, base_category: Tuple,
                             port_category: Tuple) -> None:
        """
        Handles attributes that exist in both base and port implementations, and have a str
        category 0.

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_category (Tuple): Attribute category profile information for the attribute in
                the base implementation.
            port_category (Tuple): Attribute category profile information for the attribute in
                the ported implementation.
        """
        rpt_target = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        assert isinstance(base_category[Key.DETAIL_KEY], str) and \
            isinstance(port_category[Key.DETAIL_KEY], str), \
            f'{name} handling category 0 is {type(base_category[Key.DETAIL_KEY])}, ' + \
            f'{type(port_category[Key.DETAIL_KEY])} instead of str, str.'
        if base_category[Key.DETAIL_KEY] != port_category[Key.DETAIL_KEY]:
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  Handling category 0 "{base_category[Key.DETAIL_KEY]}" != ' +
                            f'"{port_category[Key.DETAIL_KEY]}": cannot compare further')
            rpt_target.info(f'    {base_category}')
            rpt_target.info(f'    {port_category}')
            return
        if base_category[Key.DETAIL_CONTENT] is SentinelTag(Tag.OTHER_EXPAND) \
                and base_category[Key.DETAIL_CONTENT] is port_category[Key.DETAIL_CONTENT]:
            assert base_category[Key.DETAIL_KEY] in (PrfC.A_CLASS, Is.DATADESCRIPTOR), 'Other ' \
                f'expand context "{base_category[Key.DETAIL_KEY]}" found for "{name}" attribute.'
            self.queue_attribute_expansion(name, context)
            if not self._shared[Key.HDR_SENT_DIF]:  # Exact match (so far)
                if self.get_configuration(Cfg.report_exact):
                    rpt_target.info(
                        f'"{name}" Expand matched other: {context.base.path}¦{context.port.path}')
            return
        if base_category[Key.DETAIL_CONTENT] is SentinelTag(Tag.SELF_NO_EXPAND) \
                and base_category[Key.DETAIL_CONTENT] is port_category[Key.DETAIL_CONTENT]:
            assert base_category[Key.DETAIL_KEY] in (PrfC.DUNDER,), \
                f'Self tag context "{base_category[Key.DETAIL_KEY]}" found for "{name}" attribute.'
            # print('Self:No Expand context')
            return
        self.handle_matched_routine(name, context, base_category, port_category)

    @staticmethod
    def _sanity_check_matched_categories(name: str, base_category: MethodSignatureDetail,
                                         port_category: MethodSignatureDetail) -> None:
        """
        Verify that the high level signature detail information makes sense

        Args:
            name (str): The name of the matched attribute.
            base_category (tuple): the base implementation function signature information
            port_category (tuple): the port implementation function signature information
                MethodSignatureDetail is Tuple[str, Tuple[Tuple[ParameterDetail, ...], StrOrTag]]
        """
        assert isinstance(base_category[Key.DETAIL_CONTENT], tuple), \
            f'{name} handling category 1 is {type(base_category[Key.DETAIL_KEY])} ' + \
            f'instead of tuple.\n{base_category}\n{port_category}'
        assert base_category[Key.DETAIL_KEY] in (Is.ROUTINE,), 'unhandled' \
            f' "{base_category[Key.DETAIL_KEY]}" context 0.\n{base_category}\n{port_category}'
        assert isinstance(base_category[Key.DETAIL_CONTENT], tuple) and \
            isinstance(port_category[Key.DETAIL_CONTENT], tuple), \
            '"routine" category[Key.DETAIL_CONTENT], ' \
            f'{type(base_category[Key.DETAIL_CONTENT]).__name__}, ' + \
            f'{type(port_category[Key.DETAIL_CONTENT]).__name__}, not tuple, tuple'
        # print(f'{base_category = }')
        ele_cnt = 3
        assert len(base_category[Key.DETAIL_CONTENT]) == ele_cnt and \
            len(port_category[Key.DETAIL_CONTENT]) == ele_cnt, \
            'len "routine category[Key.DETAIL_CONTENT] ' \
            f'{len(base_category[Key.DETAIL_CONTENT])}, ' + \
            f'{len(port_category[Key.DETAIL_CONTENT])}' + \
            f' not {ele_cnt}, {ele_cnt}'

    def handle_matched_routine(self, name: str, context: MatchPair,
                               base_category: MethodSignatureDetail,
                               port_category: MethodSignatureDetail) -> None:
        """
        Handle reporting (miss) matches of signatures for matched function elements

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            base_category (tuple): the base implementation function signature information
            port_category (tuple): the port implementation function signature information
                MethodSignatureDetail is Tuple[str, Tuple[Tuple[ParameterDetail, ...], StrOrTag]]
        """
        self._sanity_check_matched_categories(name, base_category, port_category)
        destination: logging.Logger = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        base_sig = base_category[Key.DETAIL_CONTENT]
        port_sig = port_category[Key.DETAIL_CONTENT]
        base_iter = tuple_generator(base_sig[Key.SIG_PARAMETERS])
        port_iter = tuple_generator(port_sig[Key.SIG_PARAMETERS])
        base_det: ParameterDetail = next(base_iter, self.END_DETAIL)
        port_det: ParameterDetail = next(port_iter, self.END_DETAIL)
        self._shared[Key.HDR_SENT_SIG] = False
        self._shared[Key.POS_IDX] = -1
        self._shared[Key.KEY_IDX] = -1
        while self.END_DETAIL not in (base_det, port_det):
            self._shared[Key.POS_IDX] += 1
            if Match.POSITIONAL in base_det.kind and Match.POSITIONAL in port_det.kind:
                self._handle_matched_parameters(name, context, Key.POS_PARAM_TYPE,
                                                base_det, port_det)
                base_det = next(base_iter, self.END_DETAIL)
                port_det = next(port_iter, self.END_DETAIL)
                continue
            if Match.POSITIONAL in base_det.kind:
                self.send_match_sig_header(name, context)
                destination.info(
                    f'{self._param_prefix(Key.POS_PARAM_TYPE)} in base but not port: {base_det}')
                base_det = next(base_iter, self.END_DETAIL)
                continue
            if Match.POSITIONAL in port_det.kind:
                self.send_match_sig_header(name, context)
                destination.info(
                    f'{self._param_prefix(Key.POS_PARAM_TYPE)} in port but not base: {port_det}')
                port_det = next(port_iter, self.END_DETAIL)
                continue
            # handle keyword (non-positional) parameters
            # potentially these could be out of order matches, to the logic here could be made
            # smarter: sort remaining ParameterDetail entries in both sets
            # 'pre' split, so the non-positional entries are handled separately, after positional

            # Currently *assumes* that keyword entries are in the same order for base and port.
            # If they are not, mismatches will be reported.
            self._shared[Key.KEY_IDX] += 1
            if base_det is not None and port_det is not None:
                self._handle_matched_parameters(name, context, Key.KEY_PARAM_TYPE,
                                                base_det, port_det)
                base_det = next(base_iter, self.END_DETAIL)
                port_det = next(port_iter, self.END_DETAIL)
                continue
            if base_det is not None:
                self.send_match_sig_header(name, context)
                destination.info(f'{self._param_prefix(Key.KEY_PARAM_TYPE)} in base ' +
                                 f'but not port: {base_det}')
                base_det = next(base_iter, self.END_DETAIL)
                continue
            self.send_match_sig_header(name, context)
            destination.info(f'{self._param_prefix(Key.KEY_PARAM_TYPE)} in port ' +
                             f'but not base: {port_det}')
            port_det = next(port_iter, self.END_DETAIL)

        if base_sig[Key.SIG_RETURN] != port_sig[Key.SIG_RETURN]:
            if Ignore.scope_annotation not in self.get_configuration(Cfg.ignore_differences):
                self.send_match_sig_header(name, context)
                destination.info('    routine return annotation: base '
                    f'{_no_return_annotation(base_sig)}; port {_no_return_annotation(port_sig)}')
        if base_sig[Key.SIG_DOC] != port_sig[Key.SIG_DOC]:
            if Ignore.docstring not in self.get_configuration(Cfg.ignore_differences):
                self.send_match_sig_header(name, context)
                destination.info(f'    routine docstring: base ¦{base_sig[Key.SIG_DOC]}¦; ' +
                                 f'port ¦{port_sig[Key.SIG_DOC]}¦')

    def _handle_matched_parameters(self, name: str, context: MatchPair, param_type: str,
            base_det: ParameterDetail, port_det: ParameterDetail) -> None:
        """
        Handle reporting miss-matches between base and port positional parameter details

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
            param_type (str): positional versus keyword parameter reporting
            base_det (ParameterDetail): the base implementation parameter signature information
            port_det (ParameterDetail): the port implementation parameter signature information
        """
        destination: logging.Logger = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        if base_det.name != port_det.name:
            self.send_match_sig_header(name, context)
            destination.info(f'{self._param_prefix(param_type)} name: ' +
                f'base "{base_det.name}"; port "{port_det.name}"')
        if base_det.kind != port_det.kind:
            self.send_match_sig_header(name, context)
            destination.info(f'{self._param_prefix(param_type)} kind: ' +
                f'base "{base_det.kind}"; port "{port_det.kind}"')
        if base_det.annotation != port_det.annotation:
            self.send_match_sig_header(name, context)
            # pylint:disable=line-too-long
            destination.info(f'{self._param_prefix(param_type)} annotation: ' +
                f'base {pretty_annotation(base_det.annotation, SentinelTag(Tag.NO_PARAMETER_ANNOTATION))}; ' +
                f'port {pretty_annotation(port_det.annotation, SentinelTag(Tag.NO_PARAMETER_ANNOTATION))}')
        if base_det.default != port_det.default:
            self.send_match_sig_header(name, context)
            destination.info(f'{self._param_prefix(param_type)} default: ' +
                f'base {pretty_default(base_det.default)}; ' +
                f'port {pretty_default(port_det.default)}')

    def _param_prefix(self, param_type: str) -> str:
        """formatted indexed positional parameter information prefix"""
        return f'    {param_type} parameter {self._shared[Key.POS_IDX]}'

    def handle_unmatched_attribute(self, context: MatchPair, base_or_port: str, name: str,
                                   profile: AttributeProfile) -> None:
        """
        Handles attributes that exist in only one of the base and port implementations

        Args:
            context (MatchPair): The context data for the base and port implementations.
            base_or_port (str): the key to the module that implements the attribute
            name (str): The name of the unmatched attribute.
            profile (AttributeProfile): The profile information for the implemented attribute.
                Tuple[StrOrTag, str, Tuple[str], Tuple[tuple, StrOrTag]]
        """
        impl_context = getattr(context, base_or_port)
        validate_profile_data(name, impl_context, profile)
        rpt_key = Key.REPORT_NOT_IMPLEMENTED if base_or_port == 'base' else Key.REPORT_EXTENSION
        rpt_target = self._reports[rpt_key]
        if report_profile_data_exceptions(rpt_target, name, profile):
            return

        # pylint:disable=logging-fstring-interpolation
        if profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY] == 'routine':
            sig = profile[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT]
            if not (isinstance(sig, tuple) and len(sig) == Key.SIG_ELEMENTS
                    and isinstance(sig[Key.SIG_PARAMETERS], tuple)):
                rpt_target.error(f'**** {type(sig).__name__ = } {len(sig) = } ' +
                    f'{type(sig[Key.SIG_PARAMETERS]).__name__ = } ' +
                    f'{type(sig[Key.SIG_RETURN]).__name__ = } ****')
                return
            rpt_target.info(f'{name}, {profile[Key.PROFILE_ANNOTATION]}, ' +
                f'{profile[Key.PROFILE_TYPE]}, {profile[Key.PROFILE_SOURCE]}, ' +
                f'{profile[Key.PROFILE_TAGS]}, {len(sig[Key.SIG_PARAMETERS])}')
            for field in sig[Key.SIG_PARAMETERS]:
                assert isinstance(field, ParameterDetail), f'{type(field) = }¦{sig =}'
                rpt_target.info(f'    {field}')
            rpt_target.info(f'    {sig[Key.SIG_RETURN]}')
        else:
            rpt_target.info(f'{name}, {profile[Key.PROFILE_ANNOTATION]}, ' +
                f'{profile[Key.PROFILE_TYPE]}, {profile[Key.PROFILE_SOURCE]}, ' +
                f'{profile[Key.PROFILE_TAGS]},')
            rpt_target.info(f'    {profile[Key.PROFILE_DETAIL]}')

    def queue_attribute_expansion(self, name: str, context: MatchPair) -> None:
        """
        Add an entry to the queue for later profile matching

        Args:
            name (str): The name of the matched attribute.
            context (MatchPair): The context data for the base and port implementations.
        """
        self._expand_queue.put(MatchingContext(
            base_path=context.base.path + (name,),
            port_path=context.port.path + (name,),
            base_element=getattr(context.base.element, name, None),
            port_element=getattr(context.port.element, name, None),
        ))

    def report_match_details(self) -> None:
        """Generate the report(s) for the module comparison"""
        print(f'\nMatched in "{self._base_module}" base and "{self._port_module}"'
              ' port implementations.')
        self.report_section_details(Key.REPORT_MATCHED_ATTRIBUTE)

        print(f'\nNot Implemented in "{self._port_module}" port implementation.')
        print('Attribute, Base Annotation, Type, Source, "is" Tags, Count, Details¦Fields')
        self.report_section_details(Key.REPORT_NOT_IMPLEMENTED)

        print(f'\nExtensions in the "{self._port_module}" port implementation.')
        print('Attribute, Base Annotation, Type, Source, "is" Tags, Count, Details¦Fields')
        self.report_section_details(Key.REPORT_EXTENSION)

        print('\nSkipped attributes for '
              f'"{self._base_module}" (base) and "{self._port_module}" (port)')
        self.report_section_details(Key.REPORT_ATTRIBUTE_SKIPPED)

    def report_section_details(self, section: str) -> None:
        """
        print a single report section

        Args:
            section (str): The name of logger use to buffer the content
        """
        content: ListHandler = self.get_logger(section).handlers[0]
        for rec in content.log_records:
            print(rec.msg)

    def send_match_diff_header(self, name: str, context: MatchPair) -> None:
        """
        Send a (report detail block) header line, if it has not yet been sent

        Args:
            name (str) the name of the attribute being reported
            context (MatchPair): The context data for the base and port implementations.
        """
        target: logging.Logger = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        if not self._shared[Key.HDR_SENT_DIF]:
            target.info(f'"{name}" Differences: {context.base.path}¦{context.port.path}')
            self._shared[Key.HDR_SENT_DIF] = True

    def send_match_sig_header(self, name: str, context: MatchPair) -> None:
        """
        Send a (method signature block) header line, if it has not yet been sent

        Args:
            name (str) the name of the attribute being reported
            context (MatchPair): The context data for the base and port implementations.
        """
        self.send_match_diff_header(name, context)
        target: logging.Logger = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        if not self._shared[Key.HDR_SENT_SIG]:
            target.info('  Method Parameters:')
            self._shared[Key.HDR_SENT_SIG] = True

def pretty_annotation(annotation: StrOrTag, sentinel: SentinelTag) -> str:
    """
    Format an annotation string or tag for display

    Args:
        annotation (StrOrTag): annotation detail information.
        sentinel (SentinelTag): The tag indicating not annotation exists

    Returns (str) Formatted annotation information, without the SentinelTag
    """
    return '«none»' if annotation is sentinel else f'"{annotation:s}"'

def _no_return_annotation(sig_data: tuple) -> str:
    """
    get return type annotation from routing signature details

    Args:
        sig_data (tuple): signature profile information for a routine
    """
    return pretty_annotation(sig_data[Key.SIG_RETURN], SentinelTag(Tag.NO_RETURN_ANNOTATION))

def pretty_default(default: Hashable) -> str:
    """
    Format a profile default value for display

    Args:
        default (Hashable): The collected default value profile

    Returns (str) Formatted default value information, without the SentinelTag
    """
    return '«none»' if default is SentinelTag(Tag.NO_DEFAULT) \
        else '"None"' if default is None else \
        f':{type(default).__name__} "{default}"'

def tuple_generator(src: tuple):
    """
    Create a generator to allow stepping through a tuple using next()

    Args:
        src (tuple): the tuple to create the generator for
    """
    yield from src

def validate_profile_data(name: str, implementation: ObjectContextData,
                          profile: AttributeProfile) -> None:
    """
    Do some sanity checks on the prototype profile information

    Args:
        name (str): The name of an attribute.
        implementation (ObjectContextData): context information for the attribute and profile
        profile (AttributeProfile): The profile information for the implemented attribute.
    """
    assert isinstance(name, str), \
        f'{type(name).__name__ = } ¦ {name}¦{profile}'
    # AttributeProfile
    assert isinstance(profile, tuple), \
        f'{type(profile).__name__ = } ¦ {name}¦{profile}'
    assert len(profile) == Key.PROFILE_ELEMENTS, \
        f'{len(profile) = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.PROFILE_ANNOTATION], StrOrTag), \
        f'{type(profile[Key.PROFILE_ANNOTATION]).__name__ = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.PROFILE_TYPE], str), \
        f'{type(profile[Key.PROFILE_TYPE]).__name__ = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.PROFILE_SOURCE], tuple), \
        f'{type(profile[Key.PROFILE_SOURCE]).__name__ = } ¦ {name}¦{profile}'
    assert len(profile[Key.PROFILE_SOURCE]) == Key.SOURCE_ELEMENTS, \
        f'{len(profile[Key.PROFILE_SOURCE]).__name__ = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.PROFILE_SOURCE][Key.SOURCE_FILE], (str, SentinelTag)), \
        f'{type(profile[Key.PROFILE_SOURCE][Key.SOURCE_FILE]).__name__ = }' + \
        f' ¦ {name}¦{profile}'
    if isinstance(profile[Key.PROFILE_SOURCE][Key.SOURCE_FILE], SentinelTag):
        assert profile[Key.PROFILE_SOURCE][Key.SOURCE_FILE] is SentinelTag(Tag.NO_SOURCE), \
            f'{type(profile[Key.PROFILE_SOURCE][Key.SOURCE_FILE]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
        if profile[Key.PROFILE_SOURCE][Key.SOURCE_MODULE] is not None:
            assert profile[Key.PROFILE_SOURCE][Key.SOURCE_MODULE] is implementation.module, \
                f'{profile[Key.PROFILE_SOURCE][Key.SOURCE_FILE]} ' + \
                f'{type(profile[Key.PROFILE_SOURCE][Key.SOURCE_MODULE]).__name__ = }' + \
                f' ¦ {name}¦{profile}'
    else:
        assert profile[Key.PROFILE_SOURCE][Key.SOURCE_MODULE] is not None, \
            f'{profile[Key.PROFILE_SOURCE][Key.SOURCE_FILE]} ' + \
            f'{type(profile[Key.PROFILE_SOURCE][Key.SOURCE_MODULE]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
    assert isinstance(profile[Key.PROFILE_TAGS], tuple), \
        f'{type(profile[Key.PROFILE_TAGS]).__name__ = } ¦ {name}¦{profile}'
    # assert profile[Key.PROFILE_TAGS] contains 0 or more str
    assert isinstance(profile[Key.PROFILE_DETAIL], tuple), \
        f'{type(profile[Key.PROFILE_DETAIL]).__name__ = } ¦ {name}¦{profile}'
    assert len(profile[Key.PROFILE_DETAIL]) == Key.DETAIL_ELEMENTS, \
        f'{len(profile[Key.PROFILE_DETAIL]) = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY], StrOrTag), \
        f'{type(profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY]).__name__ = }' + \
        ' ¦ {name}¦{profile_data}'
    if isinstance(profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY], str):
        assert profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY] in (Is.ROUTINE, Is.MODULE,
                Is.DATADESCRIPTOR, PrfC.A_CLASS, PrfC.NAMEDTUPLE,
                PrfC.PKG_CLS_INST, PrfC.DUNDER,
            ), f'str but {profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY] = } ¦ {name}¦{profile}'
        if profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY] in (PrfC.A_CLASS, PrfC.PKG_CLS_INST):
            assert profile[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT] \
                is SentinelTag(Tag.OTHER_EXPAND), 'expected expand: ' \
                f'{type(profile[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT]).__name__}' + \
                f' ¦ {name}¦{profile}'
        elif profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY] == Is.MODULE:
            raise ValueError(('"%s" module detected, should filter?: %s', name, str(profile)))
        # something else: app error?
    elif profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY] is SentinelTag(Tag.DATA_LEAF):
        assert isinstance(profile[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT], (type(None), str,
                int, float)), \
            f'leaf but {type(profile[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
        # pass
    else:
        assert profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY] is SentinelTag(Tag.DATA_NODE), \
            f'{type(profile[Key.PROFILE_DETAIL][Key.DETAIL_KEY]).__name__ = } ¦' + \
            f'¦{implementation.path}{name}¦{profile}'
        assert profile[Key.PROFILE_TAGS] == (), \
            f'{profile[Key.PROFILE_TAGS] = } ¦{implementation.path}¦{name}¦{profile}'
        if profile[Key.PROFILE_TYPE] not in ('list', 'dict'):
            print(f'**** {implementation.path} {name = }, {profile} ****')

def report_profile_data_exceptions(destination: logging.Logger, name: str,
                                   profile_data: Tuple) -> bool:
    """
    Report some exception cases that are not sever enough to abort further processing.

    Args:
        destination (Logger): the report (segment) to append any exception information to
        name (str): The name of an attribute.
        profile_data (Tuple): The profile information for base or port implementation attribute.
            Tuple[StrOrTag, str, Tuple[str], Tuple[tuple, StrOrTag]]

    Returns:
        True when an exception case has been detected and reported
        False when no exception case has been detected
    """
    details_count = len(profile_data)
    if details_count != Key.PROFILE_ELEMENTS:
        destination.error(f'**** {details_count =} ¦ {name}¦{profile_data} ****')
        return True
    if not isinstance(profile_data[Key.PROFILE_DETAIL], tuple):
        destination.error(
            f'**** {type(profile_data[Key.PROFILE_DETAIL]).__name__ =} ¦ {name}¦{profile_data} '
            '****')
        return True
    if len(profile_data[Key.PROFILE_DETAIL]) != Key.DETAIL_ELEMENTS:
        destination.error(
            f'**** {len(profile_data[Key.PROFILE_DETAIL]) =} ¦ {name}¦{profile_data} ****')
        return True
    return False

# Demonstration with sample case
# Simulated command line options. Real command line args are order dependant. For simulation
# purposes, that is being ignored
# ATTRIBUTE-SCOPE = 'all'  # 'all', 'public', 'published'
    # --attribute-scope       Scope of attributes to compare («all», public, published).

ATTR_SCOPE = 'all'
REPORT_EXACT_MATCH = True
IGNORE_DOCSTRING_DIFFERENCES = True
# Ignore port Annotation when not defined in base
IGNORE_ADDED_ANNOTATION_ALL = False
IGNORE_ADDED_ANNOTATION_PARAM = False
IGNORE_ADDED_ANNOTATION_RETURN = False
IGNORE_ADDED_ANNOTATION_SCOPE = False
IGNORE_ATTRIBUTES = ('__cached__', '__file__', '__package__')
# pylint:disable=line-too-long
# categorize attribute ignores: top (module), all, class, other
# StrictAnnotation
# --ignore-docstrings           Ignore differences in docstring content.
# --ignore-added-annotations    Ignore cases where the base did not specify any annotation, but the port did.
# --separate-annotations        Handle annotation change filters separately for parameters, return values, and parent scope.
# --ignore-attributes GLOBAL    Comma-separated list of attributes to globally ignore.
# --ignore-module-attributes    Comma-separated list of attributes to ignore in module context.
# --ignore-class-attributes     Comma-separated list of attributes to ignore in class context.
# --report-matched              Generate report for differences in matched attributes.
# --report-not-implemented      Generate report for attributes not implemented in the port.
# --report-extensions           Generate report for extensions implemented in the port.
# --attribute-scope SCOPE       Scope of attributes to compare (all, public, published).
# --ignore-exact-match          Do not report attributes with exact matches.

if __name__ == '__main__':
    cmp = ProfilePrototype('logging', 'lib.adafruit_logging')
    # cmp.match_attributes()
    cmp.process_expand_queue()

    # match_attributes('logging', 'lib.adafruit_logging')

# cSpell:words adafruit, dunder, inspectable
# cSpell:words datadescriptor
# cSpell:ignore fstring
# cSpell:allowCompoundWords true