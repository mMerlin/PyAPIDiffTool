# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""Code introspection tools"""

import types
import enum
from typing import (Callable, Tuple, Union, Hashable, Mapping, Sequence,
    get_type_hints,
    Any,
)
from collections import namedtuple
from dataclasses import dataclass
import inspect
import decimal
import fractions
import logging
from generic_tools import SentinelTag, StrOrTag

ParameterDetail = namedtuple('ParameterDetail', ['name', 'kind', 'annotation', 'default'])
"""Details collected about a function or method parameter"""

AttributeProfile = Tuple[StrOrTag,
                         str,
                         Tuple[StrOrTag, types.ModuleType],
                         Tuple[str, ...],
                         Tuple[tuple, StrOrTag]]
"""
    parent context typehint annotation
    type
    (source file path, source module)
    ("is" keywords)
    (detail, …)
        «hpd need to expand»
"""

@dataclass(frozen=True)
class APKey:
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

@dataclass(frozen=True)
class Tag:
    """Constants for SentinelTag instances, to avoid possible typos in strings used to
    create or compare them.
    """
    # pylint:disable=invalid-name,too-many-instance-attributes
    NO_PARAMETER_ANNOTATION: str = 'No parameter annotation'
    NO_RETURN_ANNOTATION: str = 'No return annotation'
    SYS_EXCLUDE: str = 'System:Exclude'
    BUILTIN_EXCLUDE: str = 'builtin:Exclude'
    GET_SOURCE_FAILURE: str = 'got type, not expected object'
    DATA_LEAF: str = 'Data:Leaf'
    DATA_NODE: str = 'Data:Node'
    OTHER_EXPAND: str = 'Other:Expand'
    SELF_NO_EXPAND: str = 'Self:No Expand'
    NO_DEFAULT: str = 'No Default'

    DATA_UNHANDLED: str = 'Data:Unhandled'
    NOT_AN_ATTRIBUTE: str = 'Not an attribute'
    NO_ATTRIBUTE_ANNOTATION: str = 'no attribute annotation'
    NO_DATA_ANNOTATION: str = 'no annotation for data'
    NO_DOCSTRING: str = 'No docstring'
    NO_SOURCE: str = 'No source file'
    ERROR_DATA_TYPE: str = 'Error:Unhandled Data Type'
    WARNING_NON_INSPECTABLE: str = 'Warning:Non Inspectable Callable'
    WARNING_NO_ATTRIBUTE: str = 'Warning:Cannot get attribute'
    ERROR_ACCESS_FAILURE: str = 'Error:Failure accessing attribute'

    NO_TYPEHINT = SentinelTag('no attribute annotation')

@dataclass(frozen=True)
class ProfileConstant:
    """
    Constants for unique keywords used to categorize profile information details.
    """
    # pylint:disable=invalid-name,too-many-instance-attributes
    DUNDER: str = 'dunder class attribute'
    A_CLASS: str = 'a class'
    NAMEDTUPLE: str = 'namedtuple'
    # SOMETHING_ELSE: str = 'something else to be handled'
    EXTERN_MODULE: str = 'external.module'
    PKG_CLS_INST: str = 'package.class.instance'
    GENERIC_MODE: str = 'generic'
    MODULE_MODE: str = 'module'
    CLASS_MODE: str = 'class'
    SEQUENCE_MODE: str = 'sequence'  # list, tuple, set, …
    KEY_VALUE_MODE: str = 'key_value'  # dict, mappingproxy

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
    """hint for how to profile attributes"""
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
    """
    ele = context.element
    context.source = get_object_source_file(ele)
    context.typehints = get_type_hints(ele) if isinstance(ele,
            (type, types.MethodType, types.FunctionType, types.ModuleType)) \
        else {}
    context.all = tuple(dir(ele))
    context.published = tuple(getattr(ele, '__all__', []))
    context.public = tuple(attr for attr in context.all if is_public_attr_name(attr))
    if isinstance(ele, types.ModuleType):
        context.module = ele
        context.mode = ProfileConstant.MODULE_MODE
    else:
        context.module = inspect.getmodule(ele)
        if isinstance(ele, Sequence):
            assert isinstance(ele, (list, tuple, set)), \
                f'Only a subset of Sequence types expected: not {type(ele)}'
            context.mode = ProfileConstant.SEQUENCE_MODE
            # context.published = tuple(f'index_{i}' for i in range(len(ele) + 1))
            context.published = tuple(range(len(ele)))
        elif isinstance(ele, (dict, types.MappingProxyType)):
            context.mode = ProfileConstant.KEY_VALUE_MODE
            context.published = tuple((i, key) for i, key in enumerate(ele.keys()))
        elif repr(type(ele)).startswith('<class '):
            # Class definition or instance
            context.mode = ProfileConstant.CLASS_MODE
        else:
            assert not isinstance(ele, type), f'type but not class {repr(ele)}'
        # elif isinstance(ele, type) and issubclass(ele, tuple) and hasattr(ele, '_fields'):
        #     context.mode = 'namedtuple'
        #     context.published = getattr(ele, '_fields')
        #     # handled as a Data:Leaf at the parent level

def get_object_source_file(element: object) -> Union[str, SentinelTag]:
    """
    Get the source file that an element (definition?) is in

    Args:
        element (object): The element to get the source file for.
    """
    if isinstance(element, (types.ModuleType, type, types.MethodType, types.FunctionType,
                            types.TracebackType, types.FrameType, types.CodeType)):
        try:
            return inspect.getsourcefile(element)
        except TypeError as exc:
            if len(exc.args) == 1:
                if exc.args[0].endswith("' (built-in)> is a built-in module") \
                        or exc.args[0].endswith("> is a built-in class"):
                        # or exc.args[0] == "<class 'type'> is a built-in class" \
                        # or exc.args[0] == "<class 'mappingproxy'> is a built-in class":
                    # type, mappingproxy, getset_descriptor, ?…
                    return SentinelTag(Tag.BUILTIN_EXCLUDE)
                if exc.args[0] == 'module, class, method, function, traceback, frame, ' \
                        'or code object was expected, got type':
                    # occurs (at least) for special attributes like __call_getitem__. To avoid
                    # crashing, a special tag is returned. Calling code can use that tag, plus
                    # other context information to determine if using the source file of the
                    # parent attribute is a reasonable fall back. Assuming the attribute *IS*
                    # something it should be valid to get source for, it usually is, but there
                    # are some edge cases where it will not be.
                    return SentinelTag(Tag.GET_SOURCE_FAILURE)
            raise
    return SentinelTag(Tag.NO_SOURCE)

def get_attribute_source(attribute: Any) -> Tuple[StrOrTag, types.ModuleType]:
    """
    Get information about the source context for the attribute.

    Args:
        attribute (Any): The element to get information about

    Returns the source file and module associated with the attribute
        Tuple[StrOrTag, types.ModuleType]
    """
    src_file = get_object_source_file(attribute)
    src_module = inspect.getmodule(attribute)
    if src_file is SentinelTag(Tag.NO_SOURCE):
        if src_module is not None:
            assert isinstance(src_module, types.ModuleType), \
                f'BAD source pattern: {src_file = }, {src_module = }'
    elif src_file is SentinelTag(Tag.BUILTIN_EXCLUDE) or \
            src_file is SentinelTag(Tag.GET_SOURCE_FAILURE):
        assert isinstance(src_module, types.ModuleType), \
            f'New source pattern: {src_file = }, {src_module = }'
    elif src_file is None:
        assert src_module is None, \
            f'New source pattern: {src_file = }, {src_module = }'
    else:
        assert isinstance(src_file, str) and isinstance(src_module, types.ModuleType), \
            f'New source pattern: {src_file = }, {src_module = }'
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

def get_is_functions() -> Tuple[Tuple[str, Callable[[Any], bool]]]:
    """
    collect the inspect.is«something» methods

    sorted so that tags created iterating over this will be in sorted order as well

    Returns:
        Tuple[Tuple[str, Callable[[Any], bool]]]: A tuple of tuples containing the names of
            inspect.is… functions (without the leading "is", and a reference to the function.
    """
    return tuple((name[2:], func)
                 for name, func in sorted(inspect.__dict__.items())
                 if name.startswith('is') and callable(func))

GLOBAL_IS_FUNCTIONS = get_is_functions()

def _verify_is_tags(tags: Tuple[str]) -> None:
    """
    Do sanity check on the "is" function tags this code currently understands how to process

    Args:
        tags (tuple): A tuple of strings of 1 or more tags
    """
    # in a class, known_tag_sets would be a class constant
    known_tag_sets = frozenset({
        frozenset({InspectIs.BUILTIN, InspectIs.ROUTINE}),
        frozenset({InspectIs.FUNCTION, InspectIs.ROUTINE}),
        frozenset({InspectIs.METHOD, InspectIs.ROUTINE}),
        frozenset({InspectIs.METHODDESCRIPTOR, InspectIs.ROUTINE}),
        frozenset({InspectIs.METHODWRAPPER, InspectIs.ROUTINE}),
        frozenset({InspectIs.DATADESCRIPTOR, InspectIs.GETSETDESCRIPTOR}),
    })
    for tag in tags:
        if tag in (InspectIs.ASYNCGEN, InspectIs.ASYNCGENFUNCTION, InspectIs.AWAITABLE,
                    InspectIs.COROUTINE, InspectIs.COROUTINEFUNCTION):
            raise ValueError(f'{tags = } includes "{tag}", an async tag, '
                                'which is not handled yet')
        if tag in (InspectIs.ABSTRACT, InspectIs.CODE, InspectIs.FRAME, InspectIs.GENERATOR,
                    InspectIs.GENERATORFUNCTION, InspectIs.KEYWORD,
                    InspectIs.MEMBERDESCRIPTOR, InspectIs.TRACEBACK):
            raise ValueError(f'{tags = } includes "{tag}", which needs research to handle')
    if len(tags) > 1 and set(tags) not in known_tag_sets:
        raise ValueError(f'{tags = } is a set of tags '
                            'that has not been validated together')

def _wrap_test(routine: Callable, obj: Any) -> bool:
    """
    Trap (and ignore) any TypeError calling the routine with obj

    inspect.isKeyword raises type error if the obj is not hashable. Like a list

    Args:
        routine (Callable): The function to run
        obj (Any): The argument to pass to the function

    Returns:
        the result from calling the function, expected to be a bool value
        False if a TypeError is raised
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

def get_value_information(value: Any) -> Tuple[SentinelTag, Any]:
    """
    Returns information about a value's type and its complexity.

    Args:
        value: The value to analyze.

    Returns:
        A tuple containing a SentinelTag indicating the value's complexity (leaf or node),
        and the value itself or a description.
    """
    simple_types = (type(None), bool, int, float, complex, enum.Enum, decimal.Decimal,
                    fractions.Fraction, str, bytes, bytearray)
    nested_types = (list, tuple, set)
    complex_types = (list, tuple, dict, set, Mapping, Sequence, types.MappingProxyType)
        #, Set, FrozenSet

    # Simple types directly return the value(s)
    if isinstance(value, simple_types):
        return SentinelTag(Tag.DATA_LEAF), value
    if isinstance(value, nested_types) and \
            all(isinstance(ele, simple_types) for ele in value):
        return SentinelTag(Tag.DATA_LEAF), repr(value)
    if isinstance(value, (dict, types.MappingProxyType)) and \
            all(isinstance(ele, simple_types) for ele in value.values()):
        return SentinelTag(Tag.DATA_LEAF), repr(value)
    if not isinstance(value, nested_types) and isinstance(value, Sequence):
        raise ValueError(f'Unhandled Sequence type: {type(value)}')
    if isinstance(value, complex_types):
        return SentinelTag(Tag.DATA_NODE), '«to be expanded»'
    if isinstance(value, types.FunctionType):
        return (InspectIs.ROUTINE, get_signature(value))
    # Catch-all for unhandled types
    return SentinelTag(Tag.DATA_UNHANDLED), SentinelTag(Tag.ERROR_DATA_TYPE)

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

    Source can (is expected to be) from:
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
        ValueError if the missing_tag argument is not Hashable.
    """
    if not isinstance(missing_tag, Hashable):
        raise ValueError("missing_tag argument must be Hashable")

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
    """
    if not callable(routine):
        # this is an abort the application error. The code is broken and output can not be trusted
        raise ValueError(
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
    """
    module_class_instance_prefix = f"<class '{my_object.__name__}."
    if str(type(attribute)).startswith(module_class_instance_prefix):
        details.append((ProfileConstant.PKG_CLS_INST, SentinelTag(Tag.OTHER_EXPAND)))
    elif my_object.__name__ not in getattr(attribute, '__module__', my_object.__name__):
        # and not in my_object.__all__
        assert not hasattr(my_object, '__all__') or attr_name not in my_object.__all__, \
            f'{attr_name}¦{getattr(attribute, "__module__")}¦' + \
            f"{(ProfileConstant.EXTERN_MODULE, SentinelTag(Tag.SYS_EXCLUDE))}"
        details.append((ProfileConstant.EXTERN_MODULE, SentinelTag(Tag.SYS_EXCLUDE),
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
    """
    # pylint:disable=protected-access
    if not (isinstance(attribute, type) and issubclass(attribute, tuple) and
            hasattr(attribute, '_fields') and isinstance(attribute._fields, tuple) and
            all(isinstance(ele, str) for ele in attribute._fields)):
        raise ValueError(f'Not a namedtuple: {type(attribute)}')
    return ProfileConstant.NAMEDTUPLE, repr(attribute._fields)

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
        AssertionError if input constraints are not met
    """
    assert context.mode == ProfileConstant.KEY_VALUE_MODE, \
        f'only handle key_value context attributes: {context.mode = }'
    assert isinstance(context.element, (dict, types.MappingProxyType)), \
        f'cannot process {type(context.element).__name__} in a key_value context'
    assert isinstance(details, list), f'details {type(details).__name__} must be a list'
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
            details.append((InspectIs.MODULE, SentinelTag(Tag.OTHER_EXPAND)))
    elif InspectIs.CLASS in attr_tags:
        if attr_name == '__class__':
            details.append((ProfileConstant.DUNDER, SentinelTag(Tag.SELF_NO_EXPAND)))
        else:
            if isinstance(attribute, type) and issubclass(attribute, tuple) and \
                    hasattr(attribute, '_fields'):
                details.append(_namedtuple_fields(attribute))
            else:
                details.append((ProfileConstant.A_CLASS, SentinelTag(Tag.OTHER_EXPAND)))
    elif InspectIs.DATADESCRIPTOR in attr_tags or InspectIs.GETSETDESCRIPTOR in attr_tags:
        details.append((InspectIs.DATADESCRIPTOR, SentinelTag(Tag.OTHER_EXPAND)))
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
        raise ValueError(f'{attr_tags = } not handled by current logic')
        # details.append((ProfileConstant.SOMETHING_ELSE, '«need a processing category»'))
    return attr_name, tuple(details)

# Usage example:
if __name__ == '__main__':
    ctx=ObjectContextData(path=(logging.__name__,), element=logging)
    populate_object_context(ctx)
    print(get_attribute_info(ctx, ctx.public[-1]))

# pylint:disable=line-too-long
# cSpell:words dunder, typehints, getsourcefile, getset, inspectable
# cSpell:words asyncgen, asyncgenfunction, coroutinefunction, datadescriptor, generatorfunction, getsetdescriptor, memberdescriptor, methoddescriptor, methodwrapper
# cSpell:allowCompoundWords true
