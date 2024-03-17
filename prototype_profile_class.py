# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""attribute profiling iteration prototyping"""

from typing import Iterable, Tuple, Hashable, Union, Dict, get_type_hints
from collections import namedtuple
import inspect
import logging
from queue import Queue
from prototype_import import import_module
from prototype_support import (
    ApplicationFlagError,
    ObjectContextData,
    ListHandler,
    SentinelTag,
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

class ProfilePrototype:
    """
    Create profiles and compare the api for a pair of modules
    """
    HIGH_VALUES = attribute_name_compare_key('_~')
    """ High-value sentinel, lexicographically greater than any valid attribute name

    For added certainty, could use a lexicographically higher utf-8 character. Like '°' (degrees)

    With the sort order used, private attribute names sort last
    """
    REPORT_NOT_IMPLEMENTED = 'not implemented in port'
    REPORT_EXTENSION = 'extension in port'
    REPORT_ATTRIBUTE_SKIPPED = 'attribute skipped'
    REPORT_MATCHED_ATTRIBUTE = 'matched attribute'

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
        self._reports[self.REPORT_NOT_IMPLEMENTED] = self.create_logger(self.REPORT_NOT_IMPLEMENTED)
        self._reports[self.REPORT_EXTENSION] = self.create_logger(self.REPORT_EXTENSION)
        self._reports[self.REPORT_MATCHED_ATTRIBUTE] = \
            self.create_logger(self.REPORT_MATCHED_ATTRIBUTE)
        self._reports[self.REPORT_ATTRIBUTE_SKIPPED] = \
            self.create_logger(self.REPORT_ATTRIBUTE_SKIPPED)
        # print_logger_hierarchy(self.reports[self.REPORT_NOT_IMPLEMENTED])
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
        # self._configuration_settings['attr_scope'] = getattr(module, 'ATTR_SCOPE', 'all')
        self._configuration_settings['attr_scope'] = ATTR_SCOPE # module level variable


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
        attr_scope = self._configuration_settings['attr_scope']\
            if impl_source == 'base' else 'all'
        attr_names = {
            'all': object_profile.all,
            'published': object_profile.published \
                if object_profile.published else object_profile.public,
            'public': object_profile.public
        }.get(attr_scope, object_profile.all)
        base_typehints = get_type_hints(object_profile.element)
        rpt_target = self._reports[self.REPORT_ATTRIBUTE_SKIPPED]

        for name in sorted(attr_names, key=attribute_name_compare_key):
            result = get_attribute_info(
                object_profile.element, base_typehints.get(name, inspect.Parameter.empty), name)
            assert result[0] == name, 'get_attribute_info should return the requested attribute ' \
                f'name: "{result[0]}" not equal "{name}"'
            if isinstance(result[1], ApplicationFlagError):
                rpt_target.error(f'**** Error accessing {impl_source}."{name}" ' +
                                 f'attribute: {result}')
                continue
            key = result[1][3][1]
            if key is SentinelTag('System:Exclude') or key is SentinelTag('builtin:Exclude'):
                rpt_target.info(f'{impl_source} {result}')
                continue
            yield (attribute_name_compare_key(result[0]),) + result[1:]

    def process_expand_queue(self) -> None:
        """
        Compares attributes profiles between base and port implementations based on the
        configuration settings.
        """
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

            match_count, not_impl_count, extension_count = 0, 0, 0
            while compare_base < self.HIGH_VALUES or compare_port < self.HIGH_VALUES:
                if compare_base == compare_port:
                    match_count += 1
                    self.handle_matched_attribute(compare_base[1], new_context, profile_base,
                                                  profile_port)
                    compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
                    compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))
                elif compare_base < compare_port:
                    not_impl_count += 1
                    self.handle_unmatched_attribute('base', compare_base[1], profile_base)
                    compare_base, profile_base = next(iter_base, (self.HIGH_VALUES, None))
                else: # compare_base > compare_port
                    extension_count += 1
                    self.handle_unmatched_attribute('port', compare_port[1], profile_port)
                    compare_port, profile_port = next(iter_port, (self.HIGH_VALUES, None))
            break  # DEBUG, verify top level reporting after restructure for queue

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
        validate_profile_data(name, profile_base)
        validate_profile_data(name, profile_port)
        rpt_target = self._reports[self.REPORT_MATCHED_ATTRIBUTE]
        # need to watch for the need to expand both attributes
        diff_hdr_sent = False
        if profile_base[0] != profile_port[0]:
            diff_hdr_sent = send_match_differences_header(rpt_target, name, diff_hdr_sent)
            rpt_target.info(f'  Annotation: Base {profile_base[0]}; Port {profile_port[0]}')
        if profile_base[1] != profile_port[1]:
            diff_hdr_sent = send_match_differences_header(rpt_target, name, diff_hdr_sent)
            rpt_target.info(f'  Type: Base {profile_base[1]}; Port {profile_port[1]}')
            # 'type' could match 'function'. A class constructor could do the same
            # as a function: logging._logRecordFactory
            # doing that sort of match is going to need smarter processing. Currently
            # a class is tagged for later expansion, while function signature is
            # handled in the current pass.
            # ?re-tag the function to be expanded? ?logic to only expand the constructor?
            # process the class constructor now, and match to function signature?
            # -- the class is its constructor??
        if profile_base[2] != profile_port[2]:
            diff_hdr_sent = send_match_differences_header(rpt_target, name, diff_hdr_sent)
            rpt_target.info(f'  "is" tags: Base {profile_base[2]}; Port {profile_port[2]}')
        if profile_base[3] != profile_port[3]:
            diff_hdr_sent = send_match_differences_header(rpt_target, name, diff_hdr_sent)
            rpt_target.info(f'  compare context: Base {profile_base[3]}; Port {profile_port[3]}')

        base_category = profile_base[3]
        port_category = profile_port[3]
        if len(base_category) != len(port_category):
            diff_hdr_sent = send_match_differences_header(rpt_target, name, diff_hdr_sent)
            rpt_target.info(f'  context length {len(base_category)} not = {len(port_category)}: ' +
                            f'can not compare further\n    {base_category}\n    {port_category}')
            return
        if len(base_category) != 2:
            diff_hdr_sent = send_match_differences_header(rpt_target, name, diff_hdr_sent)
            rpt_target.info('  Odd(unhandled) context size '
                f'{len(base_category)}:\n    {base_category}\n    {port_category}')
            return
        # len(handling_category) == 2
        if base_category[0] is SentinelTag('Data:Leaf'):
            print('Leaf context')
            return
        if base_category[0] is SentinelTag('Data:Node'):
            self.queue_attribute_expansion(name, context)
            print('Node expand context')
            return
        assert isinstance(base_category[0], str) and isinstance(port_category[0], str), \
            f'{name} handling category 0 is {type(base_category[0])}, {type(port_category[0])} ' \
            'instead of str, str.'
        if base_category[0] != port_category[0]:
            diff_hdr_sent = send_match_differences_header(rpt_target, name, diff_hdr_sent)
            rpt_target.info(f'  Handling category 0 "{base_category[0]}" != "{base_category[0]}"' +
                            f': can not compare further\n    {base_category}\n    {port_category}')
            return
        if base_category[1] is SentinelTag('Other:Expand') and base_category[1] is port_category[1]:
            assert base_category[0] in ('a class',), \
                f'Other expand context "{base_category[0]}" found for "{name}" attribute.'
            self.queue_attribute_expansion(name, context)
            print('Other:Expand context')
            return
        if base_category[1] is SentinelTag('Self:No Expand') \
                and base_category[1] is port_category[1]:
            assert base_category[0] in ('dunder class attribute',), \
                f'Self tag context "{base_category[0]}" found for "{name}" attribute.'
            print('Self:No Expand context')
            return

        self.handle_matched_routine(rpt_target, name, base_category, port_category, diff_hdr_sent)

    def handle_matched_routine(self, destination: logging.Logger, name: str,
            base_category: MethodSignatureDetail, port_category: MethodSignatureDetail,
            header_sent: bool) -> None:
        """
        Handle reporting (miss) matches of signatures for matched function elements

        Args:
            destination (Logger): the report (segment) to append any mismatched information to
            name (str): The name of the matched attribute.
            base_category (tuple): the base implementation function signature information
            port_category (tuple): the port implementation function signature information
                MethodSignatureDetail is Tuple[str, Tuple[Tuple[ParameterDetail, ...], StrOrTag]]
            header_sent (bool): True if an attribute match header already sent to the report
        """
        assert isinstance(base_category[1], tuple), \
            f'{name} handling category 1 is {type(base_category[0])} instead of tuple.' + \
            f'\n{base_category}\n{port_category}'
        assert base_category[0] == 'routine', f'unhandled "{base_category[0]}" context 0.' + \
            f'\n{base_category}\n{port_category}'
        assert isinstance(base_category[1], tuple) and isinstance(port_category[1], tuple), \
            f'"routine" category[1], {type(base_category[1]).__name__}, ' + \
            f'{type(port_category[1]).__name__}, not tuple, tuple'
        assert len(base_category[1]) == 2 and len(port_category[1]) == 2, \
            f'len "routine category[1] {len(base_category[1])}, {len(port_category[1])} not 2, 2'
        base_params, base_anno = base_category[1]
        port_params, port_anno = port_category[1]
        diff_hdr_sent = header_sent
        sig_hdr_sent = False
        end_detail = ParameterDetail(name='z', kind='KEYWORD_ONLY', annotation='str', default='')
        parm_sentinel = SentinelTag('No parameter annotation')
        base_iter = tuple_generator(base_params)
        port_iter = tuple_generator(port_params)
        base_det: ParameterDetail = next(base_iter, end_detail)
        port_det: ParameterDetail = next(port_iter, end_detail)
        positional_idx = -1
        keyword_idx = -1
        while base_det != end_detail or port_det != end_detail:
            positional_idx += 1
            if 'POSITIONAL' in base_det.kind and 'POSITIONAL' in port_det.kind:
                if base_det.name != port_det.name:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    positional parameter {positional_idx} name: ' +
                        f'base "{base_det.name}"; port "{port_det.name}"')
                if base_det.kind != port_det.kind:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    positional parameter {positional_idx} kind: ' +
                        f'base "{base_det.kind}"; port "{port_det.kind}"')
                if base_det.annotation != port_det.annotation:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    positional parameter {positional_idx} annotation: ' +
                        f'base {pretty_annotation(base_det.annotation, parm_sentinel)}; ' +
                        f'port {pretty_annotation(port_det.annotation, parm_sentinel)}')
                if base_det.default != port_det.default:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    positional parameter {positional_idx} default: ' +
                        f'base "{pretty_default(base_det.default)}"; ' +
                        f'port "{pretty_default(port_det.default)}"')
                base_det = next(base_iter, end_detail)
                port_det = next(port_iter, end_detail)
                continue
            if 'POSITIONAL' in base_det.kind:
                diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                destination.info(
                    f'    positional parameter {positional_idx} in base but not port: {base_det}')
                base_det = next(base_iter, end_detail)
                continue
            if 'POSITIONAL' in port_det.kind:
                diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                destination.info(
                    f'    positional parameter {positional_idx} in port but not base: {port_det}')
                port_det = next(port_iter, end_detail)
                continue
            # handle keyword (non-positional) parameters
            # potentially these could be out of order matches, to the logic here could be made
            # smarter: sort remaining ParameterDetail entries in both sets
            # 'pre' split, so the non-positional entries are handled separately, after positional

            # Currently *assumes* that keyword entries are in the same order for base and port.
            # If they are not, mismatches will be reported.
            keyword_idx += 1
            if base_det != end_detail and port_det != end_detail:
                if base_det.name != port_det.name:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    keyword parameter {keyword_idx} name: ' +
                        f'base "{base_det.name}"; port "{port_det.name}"')
                if base_det.kind != port_det.kind:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    keyword parameter {keyword_idx} kind: ' +
                        f'base "{base_det.kind}"; port "{port_det.kind}"')
                if base_det.annotation != port_det.annotation:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    keyword parameter {keyword_idx} annotation: ' +
                        f'base {pretty_annotation(base_det.annotation, parm_sentinel)}; ' +
                        f'port {pretty_annotation(port_det.annotation, parm_sentinel)}')
                if base_det.default != port_det.default:
                    diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                    sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                    destination.info(f'    keyword parameter {keyword_idx} default: ' +
                        f'base "{pretty_default(base_det.default)}"; ' +
                        f'port "{pretty_default(port_det.default)}"')
                base_det = next(base_iter, end_detail)
                port_det = next(port_iter, end_detail)
                continue
            if base_det != end_detail:
                diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
                sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
                destination.info(
                    f'    keyword parameter {keyword_idx} in base but not port: {base_det}')
                base_det = next(base_iter, end_detail)
                continue
            diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
            sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
            destination.info(
                f'    keyword parameter {keyword_idx} in port but not base: {port_det}')
            port_det = next(port_iter, end_detail)

        sentinel = SentinelTag('No return annotation')
        if base_anno != port_anno:
            diff_hdr_sent = send_match_differences_header(destination, name, diff_hdr_sent)
            sig_hdr_sent = send_match_sig_header(destination, sig_hdr_sent)
            destination.info('   routine return annotation: '
                f'base {pretty_annotation(base_anno, sentinel)}; ' +
                f'port {pretty_annotation(port_anno, sentinel)}')

    def handle_unmatched_attribute(self, base_or_port: str, name: str, profile_base: Tuple) -> None:
        """
        Handles attributes that exist in only one of the base and port implementations

        Args:
            base_or_port (str): the key to the module that implements the attribute
            name (str): The name of the unmatched attribute.
            profile_base (Tuple): The profile information for the implemented attribute.
                Tuple[StrOrTag, str, Tuple[str], Tuple[tuple, StrOrTag]]
        """
        validate_profile_data(name, profile_base)
        if base_or_port == 'base':
            rpt_target = self._reports[self.REPORT_NOT_IMPLEMENTED]
        else:
            rpt_target = self._reports[self.REPORT_EXTENSION]
        if report_profile_data_exceptions(rpt_target, name, profile_base):
            return

        # pylint:disable=logging-fstring-interpolation
        if profile_base[3][0] == 'routine':
            sig = profile_base[3][1]
            if not (isinstance(sig, tuple) and len(sig) == 2 and isinstance(sig[0], tuple)):
                rpt_target.error(f'**** {type(sig).__name__ = } {len(sig) = } ' +
                    f'{type(sig[0]).__name__ = } {type(sig[1]).__name__ = } ****')
                return
            rpt_target.info(f'{name}, {profile_base[0]}, {profile_base[1]}, ' +
                               f'{profile_base[2]}, {len(sig[0])}')
            for field in sig[0]:
                assert isinstance(field, ParameterDetail), f'{type(field) = }¦{sig =}'
                rpt_target.info(f'    {field}')
            rpt_target.info(f'    {sig[1]}')
        else:
            rpt_target.info(f'{name}, {profile_base[0]}, {profile_base[1]}, {profile_base[2]},' +
                               f'\n    {profile_base[3]}')

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
        print('\nNot Implemented in "" port implementation.')
        print('Attribute, Base Annotation, Type, "is" Tags, Count, Details¦Fields')
        rpt_content: ListHandler = self.get_logger(self.REPORT_NOT_IMPLEMENTED).handlers[0]
        for rec in rpt_content.log_records:
            print(rec.msg)
        # # for rec in rpt_content.log_records:
        # #     print(message)

        print('\nExtensions in the "" port implementation.')
        print('Attribute, Base Annotation, Type, "is" Tags, Count, Details¦Fields')
        rpt_content: ListHandler = self.get_logger(self.REPORT_EXTENSION).handlers[0]
        for rec in rpt_content.log_records:
            print(rec.msg)

        print('\nSkipped attributes for "" (base) '
              'and "" (port)')
        rpt_content: ListHandler = self.get_logger(self.REPORT_ATTRIBUTE_SKIPPED).handlers[0]
        for rec in rpt_content.log_records:
            print(rec.msg)

def send_match_differences_header(destination: logging.Logger, name: str, sent: bool) -> bool:
    """
    Send a (report detail block) header line, if it has not yet been sent

    Args:
        destination (Logger): the report (segment) to append any exception information to
        name (str) the name of the attribute being reported
        sent (bool) a flag that is true only if a header line has already been sent

    Returns True
    """
    if not sent:
        destination.info(f'{name} Differences:')
    return True

def send_match_sig_header(destination: logging.Logger, sent: bool) -> bool:
    """
    Send a (method signature block) header line, if it has not yet been sent

    Args:
        destination (Logger): the report (segment) to append method signature match information to
        sent (bool) a flag that is true only if a signature header has already been sent

    Returns True
    """
    if not sent:
        destination.info('  Method Parameters:')
    return True

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
    return '«none»' if default is SentinelTag('No Default') \
        else 'None' if default is None else \
        f':{type(default).__name__} {default:s}'

def tuple_generator(src: tuple):
    """
    Create a generator to allow stepping through a tuple using next()

    Args:
        src (tuple): the tuple to create the generator for
    """
    yield from src

def validate_profile_data(name: str, profile_data: Tuple) -> None:
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
    assert len(profile_data) == 4, \
        f'{len(profile_data) = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[0], StrOrTag), \
        f'{type(profile_data[0]).__name__ = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[1], str), \
        f'{type(profile_data[1]).__name__ = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[2], tuple), \
        f'{type(profile_data[2]).__name__ = } ¦ {name}¦{profile_data}'
    # assert profile_data[2] contains 0 or more str
    assert isinstance(profile_data[3], tuple), \
        f'{type(profile_data[3]).__name__ = } ¦ {name}¦{profile_data}'
    assert len(profile_data[3]) == 2, f'{len(profile_data[3]) = } ¦ {name}¦{profile_data}'
    assert isinstance(profile_data[3][0], StrOrTag), \
        f'{type(profile_data[3][0]).__name__ = } ¦ {name}¦{profile_data}'
    if isinstance(profile_data[3][0], str):
        assert profile_data[3][0] in ('routine', 'a class', 'something else to be handled',
                'module', 'package.class.instance', 'dunder class attribute'), \
            f'str but {profile_data[3][0] = } ¦ {name}¦{profile_data}'
        if profile_data[3][0] in ('a class', 'package.class.instance'):
            assert profile_data[3][1] is SentinelTag('Other:Expand'), \
                f'expected expand: {type(profile_data[3][1]).__name__} ¦ {name}¦{profile_data}'
        elif profile_data[3][0] == 'module':
            raise ValueError(('"%s" module detected, should filter?: %s', name, str(profile_data)))
        # something else: app error?
    elif profile_data[3][0] is SentinelTag('Data:Leaf'):
        assert isinstance(profile_data[3][1], (type(None), str, int, float)), \
            f'leaf but {type(profile_data[3][1]).__name__ = } ¦ {name}¦{profile_data}'
    else:
        print(f'**** {name = }, {profile_data} ****')
        assert profile_data[3][0] is SentinelTag('Data:Node'), \
            f'{type(profile_data[3][0]).__name__ = } ¦ {name}¦{profile_data}'

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
    if details_count != 4:
        destination.error(f'**** {details_count =} ¦ {name}¦{profile_data} ****')
        return True
    if not isinstance(profile_data[3], tuple):
        destination.error(
            f'**** {type(profile_data[3]).__name__ =} ¦ {name}¦{profile_data} ****')
        return True
    if len(profile_data[3]) != 2:
        destination.error(f'**** {len(profile_data[3]) =} ¦ {name}¦{profile_data} ****')
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
if __name__ == '__main__':
    cmp = ProfilePrototype('logging', 'lib.adafruit_logging')
    # cmp.match_attributes()
    cmp.process_expand_queue()

    # match_attributes('logging', 'lib.adafruit_logging')

# cSpell:words adafruit, dunder, inspectable, typehints
# cSpell:ignore fstring
