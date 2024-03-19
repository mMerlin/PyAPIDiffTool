# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""attribute profiling iteration prototyping"""

# import types
from typing import Iterable, Tuple, Hashable, Union, Dict
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
    get_object_context_data,
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

@dataclass(frozen=True)
class Cfg:
    """
    Constants for configuration settings lookup
    """
    profile_scope: str = 'scope of attributes'
    report_exact: str = 'report exact matches'
    ignore_differences: str = 'ignore specified differences'

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
        # print_logger_hierarchy(self.reports[Key.REPORT_NOT_IMPLEMENTED])
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

        Simulated getting application specific configuration data from external sources
        - user and project configuration files
        - command line arguments
        """
        # attr_scope = getattr(module, 'ATTR_SCOPE', 'all')
        # self._configuration_settings[Cfg.profile_scope] = getattr(module, 'ATTR_SCOPE', 'all')
        # module level variableS
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
        return self._configuration_settings[key]

    def iterate_object_attributes(self, impl_source: str, nest_path: Tuple[Tuple[str], Tuple[str]],
                                   obj: object)-> Iterable[Tuple[str, Tuple]]:
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
            nest_path (tuple): The base and port paths to the (parent of the) object
                Tuple[Tuple[str], Tuple[str]]
            obj (object): The object to process the attributes of

        Yields:
            Iterable[Tuple[Tuple[int, str], Tuple]]: An iterable of tuples, each containing the
                sort key of an attribute name and a tuple with collected profile information.
                This output is crucial for subsequent comparison or analysis steps, providing
                detailed insights into the attributes present in each module and facilitating a
                thorough review of the API compatibility and completeness.
        """
        object_profile: ObjectContextData = get_object_context_data(nest_path, obj)
        attr_scope = self.get_configuration(Cfg.profile_scope) if impl_source == 'base' else 'all'
        attr_names = {
            'all': object_profile.all,
            'published': object_profile.published \
                if object_profile.published else object_profile.public,
            'public': object_profile.public
        }.get(attr_scope, object_profile.all)
        rpt_target = self._reports[Key.REPORT_ATTRIBUTE_SKIPPED]

        for name in sorted(attr_names, key=attribute_name_compare_key):
            result = get_attribute_info(object_profile, name)
            assert result[Key.INFO_NAME] == name, 'get_attribute_info should return the ' \
                f'requested attribute name: "{result[Key.INFO_PROFILE]}" not equal "{name}"'
            if isinstance(result[Key.INFO_PROFILE], ApplicationFlagError):
                rpt_target.error(f'**** Error accessing {impl_source}."{name}" ' +
                                 f'attribute: {result}')
                continue
            # result[Key.INFO_PROFILE][Key.PROFILE_SOURCE] # check source file information for
            # content outside package, then skip
            key = result[Key.INFO_PROFILE][Key.PROFILE_DETAIL][Key.DETAIL_CONTENT]
            if key is SentinelTag(Tag.SYS_EXCLUDE) or key is SentinelTag(Tag.BUILTIN_EXCLUDE):
                rpt_target.info(f'{impl_source} {result}')
                continue
            yield (attribute_name_compare_key(result[Key.INFO_NAME]),) + result[1:]

    def process_expand_queue(self) -> None:
        """
        Compares attributes profiles between base and port implementations based on the
        configuration settings.
        """
        debug_count = 0
        match_count, not_impl_count, extension_count = 0, 0, 0
        while not self._expand_queue.empty():
            # Get an entry from the self.expand_queue and process it
            new_context: MatchingContext = self._expand_queue.get()
            # root_context, base_ele, port_ele = self._expand_queue.get()
            iter_base = self.iterate_object_attributes(
                'base', new_context.base_path, new_context.base_element)
            iter_port = self.iterate_object_attributes(
                'port', new_context.port_path, new_context.port_element)

            compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
            compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))

            while compare_base < self.HIGH_VALUES or compare_port < self.HIGH_VALUES:
                # print(min(compare_base, compare_port))
                if compare_base == compare_port:
                    print(f'{compare_base} both')  # TRACE
                    match_count += 1
                    self.handle_matched_attribute(compare_base[Key.COMPARE_NAME], new_context,
                                                  profile_base, profile_port)
                    compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
                    compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))
                elif compare_base < compare_port:
                    print(f'{compare_base} {new_context.base_path}')  # TRACE
                    not_impl_count += 1
                    self.handle_unmatched_attribute('base', compare_base[Key.COMPARE_NAME],
                                                    profile_base)
                    compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
                else: # compare_base > compare_port
                    print(f'{compare_port} {new_context.port_path}')  # TRACE
                    extension_count += 1
                    self.handle_unmatched_attribute('port', compare_port[Key.COMPARE_NAME],
                                                    profile_port)
                    compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))
            debug_count += 1
            if debug_count > 0:
                break  # DEBUG, abort further processing to see how the reporting is progressing

        print(f'\n{match_count} Matched, {not_impl_count} Not Implemented, and {extension_count} '
              'Extension attributes found.')
        self.report_match_details()

    def handle_matched_attribute(self, name: str, context: MatchingContext,
                                 profile_base: Tuple, profile_port: Tuple) -> None:
        """
        Handles attributes that exist in both base and port implementations.

        Args:
            name (str): The name of the matched attribute.
            context (MatchingContext): The base and port paths to the (parent of the) attribute,
                as well the base and port element parents.
            profile_base (Tuple): The profile information for the attribute in the base
                implementation.
            profile_port (Tuple): The profile information for the attribute in the ported
                implementation.
        """

        validate_profile_data(name, context.base_path, profile_base)
        validate_profile_data(name, context.port_path, profile_port)
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
        if profile_base[Key.PROFILE_DETAIL] != profile_port[Key.PROFILE_DETAIL]:
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  compare context: Base {profile_base[Key.PROFILE_DETAIL]};' +
                            f' Port {profile_port[Key.PROFILE_DETAIL]}')

        base_category = profile_base[Key.PROFILE_DETAIL]
        port_category = profile_port[Key.PROFILE_DETAIL]
        if len(base_category) != len(port_category):
            self.send_match_diff_header(name, context)
            rpt_target.info(f'  context length {len(base_category)} not = {len(port_category)}: ' +
                            f'cannot compare further\n    {base_category}\n    {port_category}')
            return
        if len(base_category) != 2:
            self.send_match_diff_header(name, context)
            rpt_target.info('  Odd(unhandled) context size '
                f'{len(base_category)}:\n    {base_category}\n    {port_category}')
            return
        # len(handling_category) == 2
        if base_category[Key.DETAIL_KEY] is SentinelTag(Tag.DATA_NODE):
            self.queue_attribute_expansion(name, context)
            if not self._shared[Key.HDR_SENT_DIF]:  # Exact match (so far)
                if self.get_configuration(Cfg.report_exact):
                    rpt_target.info(
                        f'"{name}" Expand matched node: {context.base_path}¦{context.port_path}')
            return
        if base_category[Key.DETAIL_KEY] is SentinelTag(Tag.DATA_LEAF):
            if not self._shared[Key.HDR_SENT_DIF]:  # Exact match
                if self.get_configuration(Cfg.report_exact):
                    rpt_target.info(
                        f'"{name}" No Difference: {context.base_path}¦{context.port_path}')
            return
        self._handle_str_category(name, context, base_category, port_category)

    def _handle_str_category(self, name: str, context: MatchingContext, base_category: Tuple,
                             port_category: Tuple) -> None:
        """
        Handles attributes that exist in both base and port implementations, and have a str
        category 0.

        Args:
            name (str): The name of the matched attribute.
            context (MatchingContext): The base and port paths to the (parent of the) attribute,
                as well the base and port element parents.
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
                            f'"{port_category[Key.DETAIL_KEY]}"' +
                            f': cannot compare further\n    {base_category}\n    {port_category}')
            return
        if base_category[Key.DETAIL_CONTENT] is SentinelTag(Tag.OTHER_EXPAND) \
                and base_category[Key.DETAIL_CONTENT] is port_category[Key.DETAIL_CONTENT]:
            assert base_category[Key.DETAIL_KEY] in (PrfC.A_CLASS, Is.DATADESCRIPTOR), 'Other ' \
                f'expand context "{base_category[Key.DETAIL_KEY]}" found for "{name}" attribute.'
            self.queue_attribute_expansion(name, context)
            if not self._shared[Key.HDR_SENT_DIF]:  # Exact match (so far)
                if self.get_configuration(Cfg.report_exact):
                    rpt_target.info(
                        f'"{name}" Expand matched other: {context.base_path}¦{context.port_path}')
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

    def handle_matched_routine(self, name: str, context: MatchingContext,
                               base_category: MethodSignatureDetail,
                               port_category: MethodSignatureDetail) -> None:
        """
        Handle reporting (miss) matches of signatures for matched function elements

        Args:
            name (str): The name of the matched attribute.
            base_category (tuple): the base implementation function signature information
            port_category (tuple): the port implementation function signature information
                MethodSignatureDetail is Tuple[str, Tuple[Tuple[ParameterDetail, ...], StrOrTag]]
        """
        self._sanity_check_matched_categories(name, base_category, port_category)
        destination: logging.Logger = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        base_params, base_anno, base_doc = base_category[Key.DETAIL_CONTENT]
        port_params, port_anno, port_doc = port_category[Key.DETAIL_CONTENT]
        base_iter = tuple_generator(base_params)
        port_iter = tuple_generator(port_params)
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

        if base_anno != port_anno:
            if Ignore.scope_annotation not in self.get_configuration(Cfg.ignore_differences):
                self.send_match_sig_header(name, context)
                destination.info('    routine return annotation: base '
                    f'{pretty_annotation(base_anno, SentinelTag(Tag.NO_RETURN_ANNOTATION))}; ' +
                    f'port {pretty_annotation(port_anno, SentinelTag(Tag.NO_RETURN_ANNOTATION))}')
        if base_doc != port_doc:
            if Ignore.docstring not in self.get_configuration(Cfg.ignore_differences):
                self.send_match_sig_header(name, context)
                destination.info(f'    routine docstring: base ¦{base_doc}¦; port ¦{port_doc}¦')

    def _handle_matched_parameters(self, name: str, context: MatchingContext, param_type: str,
            base_det: ParameterDetail, port_det: ParameterDetail) -> None:
        """
        Handle reporting miss-matches between base and port positional parameter details

        Args:
            name (str): The name of the matched attribute.
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

    def handle_unmatched_attribute(self, base_or_port: str, name: str, profile: Tuple) -> None:
        """
        Handles attributes that exist in only one of the base and port implementations

        Args:
            base_or_port (str): the key to the module that implements the attribute
            name (str): The name of the unmatched attribute.
            profile_base (Tuple): The profile information for the implemented attribute.
                Tuple[StrOrTag, str, Tuple[str], Tuple[tuple, StrOrTag]]
        """
        validate_profile_data(name, base_or_port, profile)
        if base_or_port == 'base':
            rpt_target = self._reports[Key.REPORT_NOT_IMPLEMENTED]
        else:
            rpt_target = self._reports[Key.REPORT_EXTENSION]
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
                f'{profile[Key.PROFILE_TAGS]},\n    {profile[Key.PROFILE_DETAIL]}')

    def queue_attribute_expansion(self, name: str, context: MatchingContext) -> None:
        """
        Add an entry to the queue for later profile matching

        Args:
            name (str): The name of the matched attribute.
            context (MatchingContext): The base and port paths to the (parent of the) attribute,
                as well the base and port element parents.
        """
        self._expand_queue.put(MatchingContext(
            base_path=context.base_path + (name,),
            port_path=context.port_path + (name,),
            base_element=getattr(context.base_element, name, None),
            port_element=getattr(context.port_element, name, None),
        ))

    def report_match_details(self) -> None:
        """Generate the report(s) for the module comparison"""
        print(f'\nMatched in "{self._base_module}" base and "{self._port_module}"'
              ' port implementations.')
        self.report_section_details(Key.REPORT_MATCHED_ATTRIBUTE)

        print(f'\nNot Implemented in "{self._port_module}" port implementation.')
        print('Attribute, Base Annotation, Type, "is" Tags, Count, Details¦Fields')
        self.report_section_details(Key.REPORT_NOT_IMPLEMENTED)

        print(f'\nExtensions in the "{self._port_module}" port implementation.')
        print('Attribute, Base Annotation, Type, "is" Tags, Count, Details¦Fields')
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

    def send_match_diff_header(self, name: str, context: MatchingContext) -> None:
        """
        Send a (report detail block) header line, if it has not yet been sent

        Args:
            name (str) the name of the attribute being reported
        """
        target: logging.Logger = self._reports[Key.REPORT_MATCHED_ATTRIBUTE]
        if not self._shared[Key.HDR_SENT_DIF]:
            target.info(f'"{name}" Differences: {context.base_path}¦{context.port_path}')
            self._shared[Key.HDR_SENT_DIF] = True

    def send_match_sig_header(self, name: str, context: MatchingContext) -> None:
        """
        Send a (method signature block) header line, if it has not yet been sent

        Args:
            name (str) the name of the attribute being reported
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

def validate_profile_data(name: str, path: Tuple[str], profile_data: Tuple) -> None:
    """
    Do some sanity checks on the prototype profile information

    Args:
        name (str): The name of an attribute.
        profile_data (Tuple): The profile information for base or port implementation attribute.
            Tuple[StrOrTag, str, Tuple[str], Tuple[tuple, StrOrTag]]
    """
    assert isinstance(name, str), \
        f'{type(name).__name__ = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data, tuple), \
        f'{type(profile_data).__name__ = } ¦ {name}¦{profile_data}'
    assert len(profile_data) == Key.PROFILE_ELEMENTS, \
        f'{len(profile_data) = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[Key.PROFILE_ANNOTATION], StrOrTag), \
        f'{type(profile_data[Key.PROFILE_ANNOTATION]).__name__ = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[Key.PROFILE_TYPE], str), \
        f'{type(profile_data[Key.PROFILE_TYPE]).__name__ = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[Key.PROFILE_SOURCE], tuple), \
        f'{type(profile_data[Key.PROFILE_SOURCE]).__name__ = } ¦ {name}¦{profile_data}'
    assert len(profile_data[Key.PROFILE_SOURCE]) == Key.SOURCE_ELEMENTS, \
        f'{len(profile_data[Key.PROFILE_SOURCE]).__name__ = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[Key.PROFILE_SOURCE][Key.SOURCE_FILE], (str, SentinelTag)), \
        f'{type(profile_data[Key.PROFILE_SOURCE][Key.SOURCE_FILE]).__name__ = }' + \
        f' ¦ {name}¦{profile_data}'
    if isinstance(profile_data[Key.PROFILE_SOURCE][Key.SOURCE_FILE], SentinelTag):
        assert profile_data[Key.PROFILE_SOURCE][Key.SOURCE_FILE] is SentinelTag(Tag.NO_SOURCE), \
            f'{type(profile_data[Key.PROFILE_SOURCE][Key.SOURCE_FILE]).__name__ = }' + \
            f' ¦ {name}¦{profile_data}'
        assert profile_data[Key.PROFILE_SOURCE][Key.SOURCE_MODULE] is None, \
            f'{profile_data[Key.PROFILE_SOURCE][Key.SOURCE_FILE]} ' + \
            f'{type(profile_data[Key.PROFILE_SOURCE][Key.SOURCE_MODULE]).__name__ = }' + \
            f' ¦ {name}¦{profile_data}'
    else:
        assert profile_data[Key.PROFILE_SOURCE][Key.SOURCE_MODULE] is not None, \
            f'{profile_data[Key.PROFILE_SOURCE][Key.SOURCE_FILE]} ' + \
            f'{type(profile_data[Key.PROFILE_SOURCE][Key.SOURCE_MODULE]).__name__ = }' + \
            f' ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[Key.PROFILE_TAGS], tuple), \
        f'{type(profile_data[Key.PROFILE_TAGS]).__name__ = } ¦ {name}¦{profile_data}'
    # assert profile_data[Key.PROFILE_TAGS] contains 0 or more str
    assert isinstance(profile_data[Key.PROFILE_DETAIL], tuple), \
        f'{type(profile_data[Key.PROFILE_DETAIL]).__name__ = } ¦ {name}¦{profile_data}'
    assert len(profile_data[Key.PROFILE_DETAIL]) == Key.DETAIL_ELEMENTS, \
        f'{len(profile_data[Key.PROFILE_DETAIL]) = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY], StrOrTag), \
        f'{type(profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY]).__name__ = }' + \
        ' ¦ {name}¦{profile_data}'
    if isinstance(profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY], str):
        assert profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY] in (Is.ROUTINE, Is.MODULE,
                Is.DATADESCRIPTOR, PrfC.A_CLASS, PrfC.PKG_CLS_INST, PrfC.DUNDER), \
            f'str but {profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY] = } ¦ {name}¦{profile_data}'
        if profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY] in (PrfC.A_CLASS, PrfC.PKG_CLS_INST):
            assert profile_data[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT] \
                is SentinelTag(Tag.OTHER_EXPAND), 'expected expand: ' \
                f'{type(profile_data[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT]).__name__}' + \
                f' ¦ {name}¦{profile_data}'
        elif profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY] == Is.MODULE:
            raise ValueError(('"%s" module detected, should filter?: %s', name, str(profile_data)))
        # something else: app error?
    elif profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY] is SentinelTag(Tag.DATA_LEAF):
        assert isinstance(profile_data[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT], (type(None), str,
                int, float)), \
            f'leaf but {type(profile_data[Key.PROFILE_DETAIL][Key.DETAIL_CONTENT]).__name__ = }' + \
            f' ¦ {name}¦{profile_data}'
    else:
        assert profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY] is SentinelTag(Tag.DATA_NODE), \
            f'{type(profile_data[Key.PROFILE_DETAIL][Key.DETAIL_KEY]).__name__ = } ¦{path}¦' + \
            f'{name}¦{profile_data}'
        assert profile_data[Key.PROFILE_TAGS] == (), \
            f'{profile_data[Key.PROFILE_TAGS] = } ¦{path}¦{name}¦{profile_data}'
        if profile_data[Key.PROFILE_TYPE] not in ('list', 'dict'):
            print(f'**** {path} {name = }, {profile_data} ****')

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

def print_logger_hierarchy(logger: logging.Logger, indent: int=0) -> None:
    """
    show the actual and effective logging levels for a hierarchy of loggers

    DEBUG code

    Args:
        logger (Logger): the 'leaf' logger to do the check from
        indent (int): multiplier to indent the hierarch reporting
    """
    print(f"{'    ' * indent}Logger '{logger.name}' - Level: {logger.level}, " +
          f"Effective Level: {logger.getEffectiveLevel()}")
    if logger.parent:
        print_logger_hierarchy(logger.parent, indent + 1)

# Demonstration with sample case
ATTR_SCOPE = 'all'
REPORT_EXACT_MATCH = True
IGNORE_DOCSTRING_DIFFERENCES = True
# Ignore port Annotation when not defined in base
IGNORE_ADDED_ANNOTATION_ALL = False
IGNORE_ADDED_ANNOTATION_PARAM = False
IGNORE_ADDED_ANNOTATION_RETURN = False
IGNORE_ADDED_ANNOTATION_SCOPE = False
# StrictAnnotation
if __name__ == '__main__':
    cmp = ProfilePrototype('logging', 'lib.adafruit_logging')
    # cmp.match_attributes()
    cmp.process_expand_queue()

    # match_attributes('logging', 'lib.adafruit_logging')

# cSpell:words adafruit, dunder, inspectable
# cSpell:words datadescriptor
# cSpell:ignore fstring
# cSpell:allowCompoundWords true
