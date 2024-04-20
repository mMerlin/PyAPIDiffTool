# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""Code introspection tools"""

import types
import enum
from typing import (Callable, Tuple, Union, Hashable, Mapping, Sequence,
    get_type_hints,
    FrozenSet, Dict, Any,
)
from collections import namedtuple
from dataclasses import dataclass
import inspect
import decimal
import fractions
import logging
from generic_tools import SentinelTag, LoggerMixin, StrOrTag

ParameterDetail = namedtuple('ParameterDetail', ['name', 'kind', 'annotation', 'default'])
"""Details collected about a function or method parameter"""

MethodSignature = Tuple[Tuple[ParameterDetail], StrOrTag, StrOrTag]
LeafDataType = Union[types.NoneType, str, int, float]

RoutineDetail = Tuple[str, MethodSignature]
LeafDetail = Tuple[str, LeafDataType]
AttributeDetail = Tuple[str, Union[Tuple, LeafDataType, SentinelTag]]
AttributeProfile = Tuple[StrOrTag,
                         str,
                         Tuple[StrOrTag, types.ModuleType],
                         Tuple[str, ...],
                         AttributeDetail]
"""
    parent context typehint annotation
    type
    (source file path, source module)
    ("is" keywords)
    (profile details)
"""

GLOBAL_IS_FUNCTIONS: Tuple[Tuple[str, Callable[[Any], bool]]] = tuple(
    (name[2:], func)
    for name, func in sorted(inspect.__dict__.items())
    if name.startswith('is') and callable(func)
)
"""Collect the inspect.is«something» methods one time for use in the module.

Sorted so that tags created iterating over this will be in sorted order as well."""

@dataclass(frozen=True)
class AttributeProfileKey:
    """
    Constants indexing and specifying the fields in an AttributeProfile tuple data structure.
    """
    # pylint:disable=too-many-instance-attributes
    # Root element indices and count
    annotation: int = 0
    """parent contact typehint annotation"""
    data_type: int = 1
    """python data type of the attribute"""
    source: int = 2
    """attribute profile source file and module"""
    tags: int = 3
    """'IS' keywords for matches to inspect.is«category» methods"""
    details: int = 4
    """detail information for the attribute"""
    root_elements: int = 5
    """the number of elements in an AttributeProfile root tuple"""

    # source tuple element indices and count
    file: int = 0
    """source file defining attribute"""
    module: int = 1
    """module name defining attribute"""
    source_elements: int = 2
    """the number of elements in a source tuple"""

    # details tuple element indices and count
    context: int = 0
    """context key for the detail information"""
    detail: int = 1
    """attribute detail content"""
    detail_elements: int = 2
    """the number of elements in a details tuple"""

    # signature tuple element indices and count
    sig_parameters: int = 0
    """tuple containing signature information for method parameters"""
    sig_return: int = 1
    """method return annotation"""
    sig_doc: int = 2
    """method docstring"""
    sig_elements: int = 3
    """the number of elements in a signature tuple"""

    match_positional: str = 'POSITIONAL'

@dataclass(frozen=True)
class Tag:
    """Constants for SentinelTag instances, to avoid possible typos in strings used to
    create or compare them.
    """
    # pylint:disable=invalid-name,too-many-instance-attributes
    NO_PARAMETER_ANNOTATION: str = 'No parameter annotation'
    NO_RETURN_ANNOTATION: str = 'No return annotation'
    NO_ATTRIBUTE_ANNOTATION: str = 'no attribute annotation'
    NO_DATA_ANNOTATION: str = 'no annotation for data'
    SYS_EXCLUDE: str = 'System:Exclude'
    BUILTIN_EXCLUDE: str = 'builtin:Exclude'
    GET_SOURCE_FAILURE: str = 'got type, not expected object'
    NO_DEFAULT: str = 'No Default'

    NOT_AN_ATTRIBUTE: str = 'Not an attribute'
    NO_DOCSTRING: str = 'No docstring'
    NO_SOURCE: str = 'No source file'
    ERROR_DATA_TYPE: str = 'Error:Unhandled Data Type'
    WARNING_NON_INSPECTABLE: str = 'Warning:Non Inspectable Callable'
    WARNING_NO_ATTRIBUTE: str = 'Warning:Cannot get attribute'
    ERROR_ACCESS_FAILURE: str = 'Error:Failure accessing attribute'

@dataclass(frozen=True)
class ProfileConstant:
    """
    Constants and unique keywords used to categorize profile information details.
    """
    # pylint:disable=invalid-name,too-many-instance-attributes
    GENERIC_MODE: str = 'generic'
    MODULE_MODE: str = 'module'
    CLASS_MODE: str = 'class'
    SEQUENCE_MODE: str = 'sequence'  # list, tuple, set, …
    """list, tuple, set, maybe more, but not 'simple' types like str and bytes"""
    KEY_VALUE_MODE: str = 'key_value'  # dict, mappingproxy

    instance_prefix_fmt = "<class '{}."
    """Match for detection of a class instance"""
    DUNDER: str = 'dunder class attribute'
    A_CLASS: str = 'class'
    namedtuple: str = 'namedtuple'
    """A namedtuple. Only it's fields will be included in profiling information"""
    DATA_LEAF: str = 'Data:Leaf'
    """A data (value) attribute that has been fully expanded (profiled)"""
    DATA_NODE: str = 'Data:Node'
    """A data (value) attribute that contains subelements that need to be expanded for full
    profiling"""
    signature: str = 'Function:Signature'
    """Signature information for a function or method"""
    expandable: str = 'Other:Expand'
    """An attribute that can be further (recursively) expanded"""
    cutoff: str = 'Self:No Expand'
    """An attribute that could be expanded further, but will not be for the profiling context
    It would become infinite recursion, and is not needed for profiling.
    Higher level code needs to also implement maximum depth checking if needed."""
    # SOMETHING_ELSE: str = 'something else to be handled'
    prune: str = 'external.module'
    """An attribute that could be expanded further, but will not be for the profiling context
    It is, or references, a module outside of the current profiling scope"""
    unhandled_value: str = 'Data:Unhandled'
    """A value type attribute that contains something that the code could not profile"""

    PKG_CLS_INST: str = 'package.class.instance'

@dataclass(frozen=True)
class InspectIs:
    """
    Constants matching the tags for inspect.is… functions.
    """
    # pylint:disable=invalid-name,too-many-instance-attributes
    ABSTRACT: str = 'abstract'
    ASYNCGEN: str = 'asyncgen'
    ASYNCGENFUNCTION: str = 'asyncgenfunction'
    AWAITABLE: str = 'awaitable'
    BUILTIN: str = 'builtin'
    CLASS: str = 'class'
    CODE: str = 'code'
    COROUTINE: str = 'coroutine'
    COROUTINEFUNCTION: str = 'coroutinefunction'
    DATADESCRIPTOR: str = 'datadescriptor'
    FRAME: str = 'frame'
    FUNCTION: str = 'function'
    GENERATOR: str = 'generator'
    GENERATORFUNCTION: str = 'generatorfunction'
    GETSETDESCRIPTOR: str = 'getsetdescriptor'
    KEYWORD: str = 'keyword'
    MEMBERDESCRIPTOR: str = 'memberdescriptor'
    METHOD: str = 'method'
    METHODDESCRIPTOR: str = 'methoddescriptor'
    METHODWRAPPER: str = 'methodwrapper'
    MODULE: str = 'module'
    ROUTINE: str = 'routine'
    TRACEBACK: str = 'traceback'

@dataclass(frozen=True)
class TagSets:
    """Constants holding patterns of "IS" tags."""
    known_tag_sets: FrozenSet[FrozenSet[str]] =frozenset({
        frozenset({InspectIs.BUILTIN, InspectIs.ROUTINE}),
        frozenset({InspectIs.FUNCTION, InspectIs.ROUTINE}),
        frozenset({InspectIs.METHOD, InspectIs.ROUTINE}),
        frozenset({InspectIs.METHODDESCRIPTOR, InspectIs.ROUTINE}),
        frozenset({InspectIs.METHODWRAPPER, InspectIs.ROUTINE}),
        frozenset({InspectIs.DATADESCRIPTOR, InspectIs.GETSETDESCRIPTOR}),
    })
    """combinations of tags that are handled by the introspection tools."""
    async_tags: FrozenSet = frozenset({
        InspectIs.ASYNCGEN, InspectIs.ASYNCGENFUNCTION, InspectIs.AWAITABLE,
        InspectIs.COROUTINE, InspectIs.COROUTINEFUNCTION})
    """async tags, which are not currently handled."""
    not_researched: FrozenSet = frozenset({
        InspectIs.ABSTRACT, InspectIs.CODE, InspectIs.FRAME, InspectIs.GENERATOR,
        InspectIs.GENERATORFUNCTION, InspectIs.KEYWORD,
        InspectIs.MEMBERDESCRIPTOR, InspectIs.TRACEBACK})
    """tag cases that need research before handling. Revisit when encountered."""

@dataclass(frozen=True)
class TypeSets:  # pylint:disable=too-many-instance-attributes
    """Constant holding groups of data types that (in some context) need to be processed together"""
    with_hints: Tuple[type] = (type, types.MethodType, types.FunctionType, types.ModuleType)
    with_source: Tuple[type] = (types.ModuleType, type, types.MethodType, types.FunctionType,
                            types.TracebackType, types.FrameType, types.CodeType)
    module: Tuple[type] = (types.ModuleType,)
    nestable: Tuple[type] = (list, tuple, set)
    dictionary: Tuple[type] = (dict, types.MappingProxyType)
    function: Tuple[type] = (types.FunctionType,)
    simple: Tuple[type] = (type(None), bool, int, float, complex, enum.Enum, decimal.Decimal,
                    fractions.Fraction, str, bytes, bytearray)
    # nested_types = (list, tuple, set)
    complex: Tuple[type] = (list, tuple, dict, set, Mapping, Sequence, types.MappingProxyType)

@dataclass
class ObjectContextData:  # pylint:disable=too-many-instance-attributes
    """
    Data class to hold object context (attribute name) information.
    """
    path: Tuple[str]
    """path to object, normally starting at the root module"""
    element: object
    """the actual object"""
    source: str = None
    """the source file for the object (definition)"""
    mode: str = ProfileConstant.GENERIC_MODE
    """hint for how to profile attributes for the current context"""
    module: types.ModuleType = None
    """the module that element is (or is contained in)"""
    typehints: dict = None
    """get_type_hints(element) if isinstance(element, (type, types.MethodType, types.FunctionType,
           types.ModuleType)) else {}"""
    # attribute names
    all: Tuple[str] = None
    """tuple(dir(obj))"""
    published: Tuple[str] = None
    """
    tuple(getattr(element, '__all__', []))
    tuple(getattr(element, '_fields, []))
    tuple(element.keys()))
    """
    public: Tuple[str] = None
    """tuple(attr for attr in all if public_attr_name(attr))"""
    skipped: int = 0

class IntrospectionRootError(Exception):
    """Base class for introspection tools exceptions."""
class IntrospectionTagUnhandled(IntrospectionRootError):
    """Individual or combinations of "IS" tags that are not currently being handled."""
class IntrospectionSourceError(IntrospectionRootError):
    """Unrecognized, unhandled combinations of attribute source file and module information"""
class IntrospectionSourceUnhandled(IntrospectionSourceError):
    """Unrecognized, unhandled combinations of attribute source file and module information"""
class IntrospectionContextUnhandled(IntrospectionRootError):
    """Detected element context that is not currently supported"""
class IntrospectionSequenceUnhandled(IntrospectionRootError):
    """Encountered a Sequence type element that could not be processed"""
class SentinelKeyError(IntrospectionRootError):
    """Attempt to use invalid element as SentinelTag key"""
class IntrospectionCallableError(IntrospectionRootError):
    """Error introspecting a Callable element"""
class IntrospectionExternExcludeError(IntrospectionRootError):
    """Processing wants to exclude as external, but found in __all__"""
class IntrospectionNotNamedtuple(IntrospectionRootError):
    """Expected to be processing namedtuple, but found something else"""
class IntrospectionKeyValueError(IntrospectionRootError):
    """Key-Value processing constraint not met"""
class IntrospectionAttributeUnhandled(IntrospectionRootError):
    """Current processing logic could not collect all details for the attribute"""

def populate_object_context(context: ObjectContextData) -> None:
    """
    Populate the fields for an existing ObjectContextData instance with context data
    for an element in either 'base' or 'port' implementation.

    Args:
        context (ObjectContextData): existing instance to fill in with context information
            about the element. The element field needs to be already populated. The path
            field can be, but it is not used or updated here.

    Output:
        updated context fields

    Raises:
        IntrospectionContextUnhandled for contexts the code does not know how to process.
    """
    ele = context.element
    context.source = get_object_source_file(ele)
    context.typehints = get_type_hints(ele) if isinstance(ele, TypeSets.with_hints) else {}
    context.all = tuple(dir(ele))
    context.published = tuple(getattr(ele, '__all__', []))
    context.public = tuple(attr for attr in context.all if is_public_attr_name(attr))
    if isinstance(ele, TypeSets.module):
        context.module = ele
        context.mode = ProfileConstant.MODULE_MODE
    else:
        context.module = inspect.getmodule(ele)
        if isinstance(ele, Sequence):
            if not isinstance(ele, TypeSets.nestable):
                raise IntrospectionContextUnhandled(
                    f'Only a subset of Sequence types expected: {type(ele)} not handled')
            context.mode = ProfileConstant.SEQUENCE_MODE
            context.published = tuple(range(len(ele)))
        elif isinstance(ele, TypeSets.dictionary):
            context.mode = ProfileConstant.KEY_VALUE_MODE
            context.published = tuple((i, key) for i, key in enumerate(ele.keys()))
        elif repr(type(ele)).startswith('<class '):
            # Class definition or instance
            context.mode = ProfileConstant.CLASS_MODE
        else:
            if isinstance(ele, type):
                raise IntrospectionContextUnhandled(f'type but not class {repr(ele)}')
        # elif isinstance(ele, type) and issubclass(ele, tuple) and hasattr(ele, '_fields'):
        #     context.mode = 'namedtuple'
        #     context.published = getattr(ele, '_fields')
        #     # handled as a Data:Leaf at the parent level

def get_object_source_file(element: object) -> Union[str, SentinelTag]:
    """
    Get the source file that an element is defined in, handling complexities of Python's
    introspection capabilities.

    Args:
        element (object): The element to get the source file for.

    Returns:
        The source file path or a SentinelTag indicating specific reasons if the source
        file couldn't be retrieved.

    Raises:
        IntrospectionSourceError: For unexpected issues during source file retrieval,
            providing details of the issue.

    Note:
        This function handles built-in types and elements defined in non-standard contexts
        by returning appropriate SentinelTags.
    """
    if isinstance(element, TypeSets.with_source):
        try:
            return inspect.getsourcefile(element)
        except TypeError as exc:
            sentinel = _handle_specific_type_error(exc)
            if sentinel is not None:
                return sentinel
            raise IntrospectionSourceError(
                f'Failed to retrieve source file for a {type(element)} element') from exc
    return SentinelTag(Tag.NO_SOURCE)

def _handle_specific_type_error(exc: TypeError) -> Union[SentinelTag, None]:
    """
    Distinguish between expected and unexpected TypeErrors when retrieving source files.

    Args:
        exc (TypeError): The exception that was caught.

    Returns:
        SentinelTag if the error is recognized and handled, None otherwise to signal unexpected
        issues.
    """
    error_message = exc.args[0] if exc.args else ''
    if error_message.endswith(' is a built-in module') or \
            error_message.endswith(' is a built-in class'):
        return SentinelTag(Tag.BUILTIN_EXCLUDE)
    if error_message == 'module, class, method, function, traceback, frame, ' \
                        'or code object was expected, got type':
        # This occurs (at least) for special attributes like __call_getitem__. Calling
        # code can use the unique tag, plus other context information to determine if
        # using the source file of the parent attribute is a reasonable fall back.
        # Assuming the attribute *IS* something it should be valid to get source for,
        # it usually is, but there are some edge cases where it will not be.
        return SentinelTag(Tag.GET_SOURCE_FAILURE)
    return None

def get_attribute_source(attribute: Any) -> Tuple[StrOrTag, types.ModuleType]:
    """
    Get information about the source context for the attribute.

    expected (and returned) combinations:
        - SentinelTag(Tag.NO_SOURCE) and (None or types.ModuleType)
        - (SentinelTag(Tag.BUILTIN_EXCLUDE) or SentinelTag(Tag.GET_SOURCE_FAILURE))
            and types.ModuleType
        - None and None
        - str and types.ModuleType

    Args:
        attribute (Any): The element to get information about

    Returns the source file and module associated with the attribute
        Tuple[StrOrTag, types.ModuleType]

    Raises
        IntrospectionSourceUnhandled for unexpected and unhandled source file and module
            status values.
    """
    src_file = get_object_source_file(attribute)
    src_module = inspect.getmodule(attribute)
    good_pattern = True
    if src_file is SentinelTag(Tag.NO_SOURCE):
        if src_module is not None and not isinstance(src_module, types.ModuleType):
            LoggerMixin.get_logger().error(  # pylint:disable=logging-fstring-interpolation
                f'BAD introspection source pattern: {src_file = }, {src_module = }')
            raise IntrospectionSourceUnhandled('Bad introspection source pattern: source = '
                                               f'{repr(src_file)}; module = {repr(src_module)}')
    elif src_file is SentinelTag(Tag.BUILTIN_EXCLUDE) or \
            src_file is SentinelTag(Tag.GET_SOURCE_FAILURE):
        if not isinstance(src_module, types.ModuleType):
            good_pattern = False
    elif src_file is None:
        if src_module is not None:
            good_pattern = False
    else:
        if not (isinstance(src_file, str) and isinstance(src_module, types.ModuleType)):
            good_pattern = False
    if not good_pattern:
        error_message = (f'Unexpected introspection source pattern detected: {src_file = }, '
                        f'{src_module = }. Introspection tools code needs to be enhances to '
                        'handle this combination.')
        LoggerMixin.get_logger().warning(error_message)
        raise IntrospectionSourceUnhandled('New (unhandled) introspection source pattern: source = '
                                           f'{repr(src_file)}; module = {repr(src_module)}')
    return src_file, src_module

def attribute_name_compare_key(attribute_name: Union[str, Tuple[int, str]]) -> Tuple[int, str]:
    """
    Generate a sort key for attribute names, prioritizing public, not dunder leading double
    underscore, dunder, and private attribute names in that order.

    If a tuple is provided instead of a str, return it unaltered. It is supposed to already
    contain the proper sorting index as the first element.

    Args:
        attribute_name (Union[str, tuple[int, str]]): The name of the attribute, or a tuple
            with numeric sort key and value.

    Returns:
        Tuple[int, str]: A tuple containing a numerical key for sorting and the attribute name.
    """
    if isinstance(attribute_name, tuple):
        return attribute_name
    if attribute_name.startswith('__') and attribute_name.endswith('__'):
        generated_key = 2  # dunder
    elif attribute_name.startswith('__'):
        generated_key = 1  # double leading underscore, but not dunder
    elif attribute_name.startswith('_'):
        generated_key = 3  # private
    else:
        generated_key = 0  #public
    return generated_key, attribute_name

def _verify_is_tags(tags: Tuple[str]) -> None:
    """
    Do sanity check on the "is" function tags this code currently understands how to process

    Args:
        tags (tuple): A tuple of strings of 1 or more tags

    Raises:
        IntrospectionTagUnhandled when individual or combinations of tags are not being handled.
    """
    for tag in tags:
        if tag in TagSets.async_tags:
            raise IntrospectionTagUnhandled(
                f'{tags = } includes "{tag}", an async tag, which is not handled yet')
        if tag in TagSets.not_researched:
            raise IntrospectionTagUnhandled(
                f'{tags = } includes "{tag}", which needs research to handle')
    if len(tags) > 1 and set(tags) not in TagSets.known_tag_sets:
        raise IntrospectionTagUnhandled(
            f'{tags = } is a set of tags that have not been validated together. '
            'Determine how to categorize the set, and update the code to support it.')

def _wrap_test(routine: Callable, obj: Any) -> bool:
    """
    Trap (and ignore) any TypeError calling the routine with obj

    inspect.isKeyword raises type error if the obj is not hashable. Like a list

    Args:
        routine (Callable): The function to run
        obj (Any): The argument to pass to the function

    Returns:
        the result from calling the function, expected to be a bool value
        False if the called routine raised a TypeError. In the intended context,
            a TypeError means that the object does not have the tested property.
    """
    try:
        return routine(obj)
    except TypeError:
        pass
    return False

def get_tag_set(obj: Any) -> Tuple[str]:
    """
    Find out what (everything that) obj 'is' recognized as by inspect

    :param Any obj: anything to be inspected.
    :return tuple of «is»names that the obj matches
    :rtype Tuple[str, ...]
    """
    return tuple(tag for tag, test in GLOBAL_IS_FUNCTIONS if _wrap_test(test, obj))

def get_value_information(value: Any) -> Tuple[str, Any]:
    """
    Returns information about a value's type and needed processing.

    Args:
        value: The value to analyze.

    Returns:
        A tuple containing a category key for the value, and information about the value itself,
        or a description.
        Category keys used:
            ProfileConstant.DATA_LEAF == 'Data:Leaf'
            ProfileConstant.DATA_NODE == 'Data:Node'
            ProfileConstant.signature == 'Function:Signature'
            ProfileConstant.unhandled_value == 'Data:Unhandled'


    Examples:
        >>> get_value_information(123)
        ('Data:Leaf', 123)
        >>> get_value_information([1,2,3])
        ('Data:Leaf', '[1, 2, 3]')
        >>> get_value_information({'key': 'value'})
        ('Data:Leaf', "{'key': 'value'}")
        >>> get_value_information([{'key': 'value'}])
        ('Data:Node', '«to be expanded»')
        >>> intro.get_value_information(intro.get_value_information)
        ('Function:Signature', ((ParameterDetail(name='value', kind='POSITIONAL_OR_KEYWORD', annotation='Any', default=Sentinel Tag: 'No Default'),), 'Tuple', '\n «docstring»'))  # pylint:disable=line-too-long
        >>> get_value_information(range(1,9))
        introspection_tools.IntrospectionSequenceUnhandled: Unhandled Sequence type: <class 'range'>
        >>> get_value_information(len)
        ('Data:Unhandled', Sentinel Tag: 'Error:Unhandled Data Type')

    Raises:
        IntrospectionSequenceUnhandled when a Sequence type is detected that the processing
            does not handle.
    """
    # Simple types directly return the value(s)
    if isinstance(value, TypeSets.simple):
        return ProfileConstant.DATA_LEAF, value
    if isinstance(value, TypeSets.nestable) and \
            all(isinstance(ele, TypeSets.simple) for ele in value):
        return ProfileConstant.DATA_LEAF, repr(value)
    if isinstance(value, TypeSets.dictionary) and \
            all(isinstance(ele, TypeSets.simple) for ele in value.values()):
        return ProfileConstant.DATA_LEAF, repr(value)
    if not isinstance(value, TypeSets.nestable) and isinstance(value, Sequence):
        raise IntrospectionSequenceUnhandled(f'Unhandled Sequence type: {type(value)}')
    if isinstance(value, TypeSets.complex):
        return ProfileConstant.DATA_NODE, '«to be expanded»'
    if isinstance(value, TypeSets.function):
        return (ProfileConstant.signature, get_signature(value))
    # Catch-all for unhandled types
    return ProfileConstant.unhandled_value, SentinelTag(Tag.ERROR_DATA_TYPE)

def is_public_attr_name(name: str) -> bool:
    """
    Determines if a given attribute name should be considered 'public'.

    Args:
        name (str): The attribute name to check.

    Returns:
        bool: True if the attribute is considered public, False otherwise.
    """
    if name.startswith('__') and name.endswith('__'):
        return False  # dunder
    if name.startswith('__'):
        return True
    return not name.startswith('_')

def get_annotation_info(source: Any, missing_tag: Hashable) -> Union[str, SentinelTag]:
    """
    Retrieves consistent annotation information for parameters, return values, and attributes.

    Source can (is expected to) be from:
        - param.annotation : name, param in inspect.signature.parameters.items()
        - inspect.signature.return_annotation
        - import.get_type_hints().get('attribute_name', inspect.Parameter.empty)
    Specifying that default value for the dict lookup makes all of the source annotation
    data consistent, allowing generic processing.

    Args:
        source: The source raw retrieved typehint annotation.
        missing_tag: A key for a SentinelTag to use when no annotation is found.

    Returns:
        The annotation as a string if found, otherwise a SentinelTag instance with the missing_tag.

    Raises:
        SentinelKeyError if the missing_tag argument is not Hashable.
    """
    if not isinstance(missing_tag, Hashable):
        raise SentinelKeyError(f'SentinelTag key must be Hashable: {type(missing_tag)}')

    return SentinelTag(missing_tag) if source is inspect.Parameter.empty \
        else source if isinstance(source, str) \
        else source.__name__ if hasattr(source, '__name__') \
        else repr(source)

def get_signature(routine: Callable) -> Tuple[Tuple[ParameterDetail], Union[str, SentinelTag]]:
    """
    Collect function signature details.

    Args:
        routine (Callable): The function to get signature information for.

    Returns:
        tuple containing tuples of signature information for each argument, plus any
            return type annotation for the routine.

    The signature information uses unique SentinelTag instances as place holders
    where a field does not have any value specified. This applies to typehint
    annotations and default values.

    raises
        IntrospectionCallableError when routine is not callable
    """
    if not callable(routine):
        # this is an abort the application error. The code is broken and output can not be trusted
        raise IntrospectionCallableError(
            f'The routine should always be callable. Detected "{type(routine).__name__}".')

    try:
        signature = inspect.signature(routine)
    except ValueError:
        # Some callables may not support introspection of their signature
        return (None, SentinelTag(Tag.WARNING_NON_INSPECTABLE))

    signature_fields = []
    for name, param in signature.parameters.items():
        param_typehint = get_annotation_info(param.annotation, Tag.NO_PARAMETER_ANNOTATION)
        default = SentinelTag(Tag.NO_DEFAULT) if param.default is inspect.Parameter.empty \
            else param.default  # this keeps the type of the default intact
        detail = ParameterDetail(name=name, kind=param.kind.name,
                                 annotation=param_typehint, default=default)
        signature_fields.append(detail)

    return_typehint = get_annotation_info(signature.return_annotation, Tag.NO_RETURN_ANNOTATION)
    doc_string = getattr(routine, '__doc__', SentinelTag(Tag.NO_DOCSTRING))
    return tuple(signature_fields), return_typehint, doc_string

def details_without_tags(my_object: Any, attr_name: str, attribute: Any, details: list) -> None:
    """
    Collect details when an attribute does not match any of the inspect "is" functions

    Args:
        my_object (Any): The object whose attribute is being inspected.
        attr_name (str): The name of the attribute.
        attribute (Any): The attribute being inspected.
        details (list): storage for collected attribute information.

    Raises:
        IntrospectionExternExcludeError if process says the attribute should be from an external
            module, but it is found in the __all__ attribute.
    """
    is_obj = hasattr(my_object, '__name__')
    if is_obj and str(type(attribute)).startswith(
            ProfileConstant.instance_prefix_fmt.format(my_object.__name__)):
        details.append((ProfileConstant.PKG_CLS_INST, SentinelTag(ProfileConstant.expandable)))
    elif is_obj and my_object.__name__ not in getattr(attribute, '__module__', my_object.__name__):
        if hasattr(my_object, '__all__') and attr_name in my_object.__all__:
            raise IntrospectionExternExcludeError(
                'Invalid External Exclude case; Exists in __all__: '
                f'{attr_name}¦{getattr(attribute, "__module__")}¦')
        details.append((ProfileConstant.prune, SentinelTag(Tag.SYS_EXCLUDE),
            get_module_info(attribute)))
    else:
        details.append(get_value_information(attribute))

def get_module_info(attribute: types.ModuleType) -> Tuple[str]:
    """
    get extra information for a module attribute

    Args:
        attribute (types.ModuleType): The (maybe) module to get information about
    """
    return InspectIs.MODULE, getattr(attribute, '__package__', '«pkg»'), \
        getattr(attribute, '__path__', '«pth»')

def _namedtuple_fields(attribute: type) -> Tuple[str, Tuple[str]]:
    """
    namedtuple as a tuple of its fields

    Args:
        attribute (type): An attribute that is a namedtuple

    Raises:
        IntrospectionNotNamedtuple if the passed attribute is not a namedtuple
    """
    # pylint:disable=protected-access
    if not (isinstance(attribute, type) and issubclass(attribute, tuple) and
            hasattr(attribute, '_fields') and isinstance(attribute._fields, tuple) and
            all(isinstance(ele, str) for ele in attribute._fields)):
        raise IntrospectionNotNamedtuple(f'Not a namedtuple: {type(attribute)}')
    return ProfileConstant.namedtuple, repr(attribute._fields)

def _key_value_info(context: ObjectContextData, attr_name: str, details: list) -> None:
    """
    Calculate the profile for an element of a dict or mappingproxy object

    Args:
        context (ObjectContextData): The context (with object) whose attribute is being inspected.
        attr_name (str): The name of the attribute.
        details (list): Storage for collected attribute information.

    Outputs:
        updated (mutated) details list containing information collected about the attribute.

    Raises:
        IntrospectionKeyValueError if input constraints are not met
    """
    if context.mode != ProfileConstant.KEY_VALUE_MODE:
        raise IntrospectionKeyValueError(
            f'only handle key_value context attributes: {context.mode = }')
    if not isinstance(context.element, (dict, types.MappingProxyType)):
        raise IntrospectionKeyValueError(
            f'cannot process {type(context.element).__name__} in a key_value context')
    attribute = context.element[attr_name]
    if isinstance(attribute, types.FunctionType):
        details.append(get_annotation_info(  # __dict__ includes methods
            context.typehints.get(attr_name, inspect.Parameter.empty), Tag.NO_ATTRIBUTE_ANNOTATION))
    else:
        details.append(SentinelTag(Tag.NO_DATA_ANNOTATION))
    details.append(type(attribute).__name__)
    details.append((SentinelTag(Tag.NO_SOURCE), None))  # no source info for data
    details.append(())  # no "is" tags for data
    details.append(get_value_information(attribute))

def split_routine_parameters(parameters: Tuple[ParameterDetail]) -> Tuple[
        Tuple[ParameterDetail], Dict[str, ParameterDetail]]:
    """
    separates positional parameters from keyword-only parameters.

    Args:
        parameters (Tuple[ParameterDetail]): All parameter information for a function.

    Returns
        Tuple[Tuple[ParameterDetail], Dict[str, ParameterDetail]]: A tuple containing
            positional parameter details and a dictionary of keyword parameter details.
    """
    positional = []
    keywords = {}
    seen_non_positional = False
    for param in parameters:
        if AttributeProfileKey.match_positional in param.kind and not seen_non_positional:
            positional.append(param)
        else:
            seen_non_positional = True
            keywords[param.name] = param
    return tuple(positional), keywords

def details_for_tagged_attribute(attr_name: str, attr_tags: Tuple[str], attribute: Any,
                                 details: list) -> bool:
    """
    Collect details when an attribute is true for at least one of the inspect "is" functions

    Args:
        attr_name (str): The name of the attribute.
        attr_tags (Tuple[str]) inspect."is"… methods matched by attribute.
        attribute (Any): The attribute being inspected.
        details (list): The buffer used to collect attribute information.

    Returns (bool) True if attribute details were collected, False otherwise

    Outputs:
        updated (mutated) details list containing information collected about the attribute.
    """
    if InspectIs.BUILTIN in attr_tags:
        details.append((InspectIs.BUILTIN, SentinelTag(Tag.BUILTIN_EXCLUDE)))
    elif InspectIs.ROUTINE in attr_tags:
        details.append((InspectIs.ROUTINE, get_signature(attribute)))
    elif InspectIs.MODULE in attr_tags:
        if getattr(attribute, '__package__') in ('', attr_name):
            details.append((InspectIs.MODULE, SentinelTag(Tag.BUILTIN_EXCLUDE),
                            get_module_info(attribute)))
        else:
            details.append((InspectIs.MODULE, SentinelTag(ProfileConstant.expandable)))
    elif InspectIs.CLASS in attr_tags:
        if attr_name == '__class__':
            details.append((ProfileConstant.DUNDER, SentinelTag(ProfileConstant.cutoff)))
        else:
            if isinstance(attribute, type) and issubclass(attribute, tuple) and \
                    hasattr(attribute, '_fields'):
                details.append(_namedtuple_fields(attribute))
            else:
                details.append((ProfileConstant.A_CLASS, SentinelTag(ProfileConstant.expandable)))
    elif InspectIs.DATADESCRIPTOR in attr_tags or InspectIs.GETSETDESCRIPTOR in attr_tags:
        details.append((InspectIs.DATADESCRIPTOR, SentinelTag(ProfileConstant.expandable)))
    else:
        return False  # Did NOT collect details for the tagged attribute
    return True

def get_attribute_object(my_object: Any, attr_name: str, details: list) -> \
        Union[object, SentinelTag]:
    """
    Get object for attribute name. Record details if cannot get an object

    Args:
        my_object (Any): The object whose attribute is being inspected.
        attr_name (str): The name of the attribute.
        details (list): storage for collected attribute information.

    Returns Union[object, SentinelTag]
        the object for the attribute name or
        SentinelTag(Tag.WARNING_NO_ATTRIBUTE) when could not obtain object for the attribute.

    Outputs:
        updated (mutated) details list containing error information when could not get the object.
    """
    attribute: Any = None
    try:
        attribute = getattr(my_object, attr_name)
    except AttributeError:
        logging.info('Attribute "%s" does not exist on the provided object %s.',
                     attr_name, repr(my_object))
        details.append(SentinelTag(Tag.NOT_AN_ATTRIBUTE))
        attribute = SentinelTag(Tag.WARNING_NO_ATTRIBUTE)
    except Exception as e:  # pylint:disable=broad-exception-caught
        logging.error('Unexpected error accessing "%s" of %s: %s', attr_name, repr(my_object), e)
        details.append(SentinelTag(Tag.ERROR_ACCESS_FAILURE))
        attribute = SentinelTag(Tag.WARNING_NO_ATTRIBUTE)
    return attribute

def get_attribute_info(context: ObjectContextData, attr_name: str) -> Tuple[str, AttributeProfile]:
    """
    Calculate the profile for an attribute of an object, handling errors gracefully.

    Args:
        context (ObjectContextData): The context (with object) whose attribute is being inspected.
        attr_name (str): attr_name (str): The name of the attribute.

    Returns:
        Tuple[str, AttributeProfile]: A tuple containing the name of the attribute, plus information
            collected about it, or a tuple containing error information if an error occurred.

    Raises:
        IntrospectionAttributeUnhandled if none of the processing filled in all of the
            attribute details.
    """
    details: list = []  # empty buffer to store collected attribution information details
    have_all_details = False  # more detail collection is still needed
    if context.mode == ProfileConstant.KEY_VALUE_MODE:
        _key_value_info(context, attr_name[1], details)  # name without the sorting key
        have_all_details = True
    elif context.mode not in (ProfileConstant.GENERIC_MODE,
                              ProfileConstant.MODULE_MODE,
                              ProfileConstant.CLASS_MODE):
        raise NotImplementedError(f'Unhandled {context.mode = }')
    if not have_all_details:
        attr_annotation = get_annotation_info(
            context.typehints.get(attr_name, inspect.Parameter.empty), Tag.NO_ATTRIBUTE_ANNOTATION)
        details.append(attr_annotation)
        attribute = get_attribute_object(context.element, attr_name, details)
        if attribute is SentinelTag(Tag.WARNING_NO_ATTRIBUTE):
            have_all_details = True  # all handled, just continue
    if not have_all_details:
        # Collect common information with a bunch of different endings depending on context
        details.append(type(attribute).__name__)
        details.append(get_attribute_source(attribute))
        attr_tags = get_tag_set(attribute)
        details.append(attr_tags)
        if not attr_tags:
            details_without_tags(context.element, attr_name, attribute, details)
            have_all_details = True
    if not have_all_details:
        _verify_is_tags(attr_tags)
        have_all_details = details_for_tagged_attribute(attr_name, attr_tags, attribute, details)
    if not have_all_details:
        raise IntrospectionAttributeUnhandled(f'{attr_tags = } not handled by current logic')
        # details.append((ProfileConstant.SOMETHING_ELSE, '«need a processing category»'))
    return attr_name, tuple(details)

# Usage example:
if __name__ == '__main__':
    ctx=ObjectContextData(path=(logging.__name__,), element=logging)
    populate_object_context(ctx)
    print(get_attribute_info(ctx, ctx.public[-1]))

# pylint:disable=line-too-long
# cSpell:words dunder, typehints, getsourcefile, getset, inspectable subelements
# cSpell:words asyncgen, asyncgenfunction, coroutinefunction, datadescriptor, generatorfunction, getsetdescriptor, memberdescriptor, methoddescriptor, methodwrapper
# cSpell:ignore fstring
# cSpell:allowCompoundWords true
