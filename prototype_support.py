#profile_support.py

# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""Error classes, utility functions, data classes, and other module compare support definitions"""

# prototype_support.py
import types
import enum
from typing import (Callable, Tuple, Union, Hashable, Mapping, Sequence, NoReturn,
    get_type_hints,
    Any, Set, FrozenSet,
)
from collections import namedtuple
from dataclasses import dataclass, field
import inspect
import decimal
import fractions
import logging

ParameterDetail = namedtuple('ParameterDetail', ['name', 'kind', 'annotation', 'default'])

class ApplicationRootError(BaseException):
    """Application specific Exception type. (to be) Part of Exception handling framework"""

class ApplicationFlagError(ApplicationRootError):
    """
    Indicates that an error case has already been handled, and the caller just needs to continue.
    Used as a signal between functions and their callers.
    """

class ApplicationLogicError(ApplicationRootError):
    """
    Indicates an error in the program's logic, suggesting that the assumptions made by the code
    are violated.
    """

class SentinelTag:
    """
    Creates and manages unique, immutable sentinel objects based on hashable tags.

    Ensures that only one instance exists for each unique hashable tag. Instances are used
    to mark or signal specific conditions or states uniquely and immutably.

    Class Attributes:
        _sentinels: A dictionary that maps hashable tags to their respective SentinelTag instances.
    """

    _sentinels: dict[Hashable, 'SentinelTag'] = {}

    def __new__(cls, tag: Hashable) -> 'SentinelTag':
        """
        Ensure only one instance of SentinelTag for each unique tag exists.

        Args:
            tag: A hashable object used as the unique identifier for the sentinel.

        Returns:
            The unique instance of SentinelTag for the given tag.
        """
        if tag not in cls._sentinels:
            instance = super().__new__(cls)
            cls._sentinels[tag] = instance
            return instance
        return cls._sentinels[tag]

    def __init__(self, tag: Hashable):
        """
        Initialize the SentinelTag instance. This method sets the tag, bypassing __setattr__
        to enforce immutability.

        Args:
            tag: The hashable tag for the sentinel.
        """
        self.__dict__['_tag'] = tag

    @property
    def tag(self) -> Hashable:
        """
        Retrieve the instance's tag.

        Returns:
            The hashable tag associated with this sentinel instance.
        """
        return self._tag  # pylint:disable=no-member

    def __repr__(self) -> str:
        """
        Return the text representation of the SentinelTag instance.

        Returns:
            A string representation indicating it's a sentinel tag followed by the tag value.
        """
        return f"Sentinel Tag: {repr(self._tag)}"  # pylint:disable=no-member

    def __hash__(self) -> int:
        """
        Return the hash of the tag, allowing SentinelTag instances to be used as hashable objects.

        Returns:
            The hash of the _tag attribute.
        """
        return hash(self._tag)  # pylint:disable=no-member

    def __eq__(self, other: object) -> bool:
        """
        Check equality based on the identity of the instances.

        Args:
            other: Another object to compare against.

        Returns:
            True if 'other' is the same instance as 'self'; False otherwise.
        """
        return self is other

    def __setattr__(self, key: str, value: Any) -> NoReturn:
        """
        Prevent modifications to the instance to ensure immutability.

        Args:
            key: The attribute name.
            value: The value to set the attribute to.

        Raises:
            AttributeError: Always raised to prevent modification of any attributes.
        """
        raise AttributeError("SentinelTag instances are immutable.")

    def __delattr__(self, item: str) -> NoReturn:
        """
        Prevent deletion of attributes to ensure immutability.

        Args:
            item: The attribute name to delete.

        Raises:
            AttributeError: Always raised to prevent deletion of any attributes.
        """
        raise AttributeError("SentinelTag instances are immutable.")

StrOrTag = Union[str, SentinelTag]
AttributeProfile = Tuple[StrOrTag, str, Tuple[StrOrTag, types.ModuleType], Tuple[str, ...],
                         Tuple[tuple, StrOrTag]]

@dataclass(frozen=True)
class Tag:
    """
    Constants for SentinelTag instances, to avoid possible typos in strings used to create them
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
    """path to object, starting at module"""
    element: object
    """the actual object"""
    source: str = None
    """the source file for the object (definition)"""
    mode: str = 'generic'
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
    """tuple(getattr(element, '__all__', []))"""
    public: Tuple[str] = None
    """tuple(attr for attr in all if public_attr_name(attr))"""
    skipped: int = 0

# Sample data classes not currently being used. Kept to be used if needed for debugging
@dataclass()
class SampleData1:  # pylint:disable=too-many-instance-attributes
    """sample attributes to test out get_value_information processing"""
    int_attr: int = 42
    bool_attr: bool = False
    float_attr: float = 3.14
    dec_attr: decimal.Decimal = decimal.Decimal('123.456')
    fraction_attr: fractions.Fraction = fractions.Fraction(33, 3)
    str_attr: str = "Hello, world"
    none_str_attr: str = None
    list_attr: list = field(default_factory=lambda: [1, 2, 3])
    dict_attr: dict = field(default_factory=lambda: {'key': 'value'})
    set_attr: Set = field(default_factory=lambda: {1, 2, 3})
    frozenset_attr: FrozenSet = field(default_factory=lambda: frozenset((1, 2, 3)))
    none_attr: None = None
    complex_attr: complex = 1 + 2j

    bytearray_attr: bytearray = field(default_factory=lambda: bytearray([65, 66, 67, 38]))
    # custom_obj: Any = None  # Recursive attribute for demonstration
SampleData1.custom_obj = SampleData1()

@dataclass()
class SampleData2:  # pylint:disable=too-many-instance-attributes
    """sample attributes to test out get_value_information processing"""
    int_attr_x: int = 42
    bool_attr: bool = False
    # float_attr: float = 3.14
    dec_attr: decimal.Decimal = decimal.Decimal('123.456')
    fraction_attr: fractions.Fraction = fractions.Fraction(33, 3)
    str_attr: str = "Hello, world"
    none_str_attr: str = None
    # list_attr: list = field(default_factory=lambda: [1, 2, 3])
    dict_attr: dict = field(default_factory=lambda: {'key': 'value'})
    set_attr: Set = field(default_factory=lambda: {1, 2, 3})
    frozenset_attr: FrozenSet = field(default_factory=lambda: frozenset((1, 2, 3)))
    none_attr: None = None
    complex_attr: complex = 1 + 2j

    bytearray_attr: bytearray = field(default_factory=lambda: bytearray([65, 66, 67, 38]))
    # custom_obj: Any = None  # Recursive attribute for demonstration

class ListHandler(logging.Handler):
    """Save log records to a list"""
    def __init__(self, *args, **kwargs):
        # super(ListHandler, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)
        self.log_records = []

    def emit(self, record) -> None:
        """capture the log record"""
        self.log_records.append(record)
        return True
    # def emit(self, record) -> None:
    #     """capture and format the log record"""
    #     message = record.getMessage()  # This formats the message with any args
    #     self.log_records.append(message)

    def log_also_to_me(self, logger: logging.Logger) -> bool:
        """add the list handler instance to a Logger"""
        for existing_handler in logger._handlers:  # pylint:disable=protected-access
            if existing_handler == self:
                return False  # already there
        logger.addHandler(self)
        return True

    def log_only_to_me(self, logger: logging.Logger) -> None:
        """replace all handlers of a Logger with just me"""
        # pylint:disable=protected-access
        while logger._handlers:
            logger.removeHandler(logger._handlers[0])
        logger.addHandler(self)

    def to_tuple(self) -> Tuple[Tuple[str, str, int, str, tuple]]:
        """
        log record data, without timestamp, as a tuple that can be directly compared
        for unittest verification.

        :return tuples containing name, levelname, levelno, msg, args
        :rtype Tuple[Tuple[str, str, int, str, tuple]]
        """
        if not self.log_records:
            return tuple()
        return tuple((rec.name, rec.levelname, rec.levelno, rec.msg, rec.args)
                     for rec in self.log_records)

def populate_object_context(context: ObjectContextData) -> None:
    """
    Populate the fields for an existing ObjectContextData instance with context data
    for an element in either 'base' or 'port' implementation.

    Args:
        context (ObjectContextData): existing instance to fill in with context information
            about the element. The element field needs to be already populated. The path
            field can be, but it is not used or updated.
        path (tuple): The attribute names leading to the object. The root (first) element
            is the name (path) for the module.
            Tuple[str, ...]
        element (object): The element to get context information for.

    Output:
        updated context
    """
    ele = context.element
    context.source = get_object_source_file(ele)
    context.typehints = get_type_hints(ele) if isinstance(ele,
            (type, types.MethodType, types.FunctionType, types.ModuleType)) \
        else {}
    context.all = tuple(dir(ele))
    context.published = tuple(getattr(ele, '__all__', []))
    context.public = tuple(attr for attr in context.all if public_attr_name(attr))
    if isinstance(ele, types.ModuleType):
        context.module = ele
        # context.mode = 'module'
    else:
        context.module = inspect.getmodule(ele)
        if isinstance(ele, Sequence):
            assert isinstance(ele, (list, tuple, set)), \
                f'Only a subset of Sequence types expected: not {type(ele)}'
            context.mode = 'sequence'
            # context.published = tuple(f'index_{i}' for i in range(len(ele) + 1))
            context.published = tuple(range(len(ele)))
        elif isinstance(ele, (dict, types.MappingProxyType)):
            context.mode = 'key_value'
            context.published = tuple((i, key) for i, key in enumerate(ele.keys()))
        # elif isinstance(ele, type) and issubclass(ele, tuple) and hasattr(ele, '_fields'):
        #     context.mode = 'namedtuple'
        #     context.published = getattr(ele, '_fields')
        #     # handled as a Data:Leaf at the parent level
        # elif isinstance(ele, type):
        #     context.mode = 'class'

def get_object_context_data(path: Tuple[str], element: object) -> ObjectContextData:
    """
    Populates and returns context data for an element in either 'base' or 'port'
    implementation.

    Args:
        path (tuple): The attribute names leading to the object. The root (first) element
            is the name (path) for the module.
            Tuple[str, ...]
        element (object): The element to get context information for.

    Returns
        ObjectContextData instance containing obj attribute name groups for the element
    """
    src = get_object_source_file(element)
    typehints = get_type_hints(element) if isinstance(element,
            (type, types.MethodType, types.FunctionType, types.ModuleType)) \
        else {}
    all_names = tuple(dir(element))
    published_names = tuple(getattr(element, '__all__', []))
    public_names = tuple(attr for attr in all_names if public_attr_name(attr))
    return ObjectContextData(path=path, element=element, source=src, typehints=typehints,
        all=all_names, published=published_names, public=public_names)

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

def get_attribute_source(attribute: Any) -> Tuple[str, types.ModuleType]:
    """
    Get information about the source context for the attribute.

    Args:
        attribute (Any): The element to get information about

    Returns the source file and module associated with the attribute
        Tuple[str, types.ModuleType]
    """
    src_file = get_object_source_file(attribute)
    src_module = inspect.getmodule(attribute)
    if src_file is SentinelTag(Tag.NO_SOURCE):
        if src_module is not None:
            assert isinstance(src_module, types.ModuleType), \
                f'BAD source pattern: {src_file = }, {src_module = }'
            # debug_modules = (
            #     'logging',
            #     'lib.adafruit_logging',
            #     'typing',
            #     '_weakrefset',
            #     'weakref',
            #     '_thread',
            #     'string',
            #     'importlib._bootstrap_external',
            #     'importlib._bootstrap',
            # )
            # if src_module.__name__ not in debug_modules:  # DEBUG
            #     assert src_module.__name__ in debug_modules, \
            #         f'{src_module.__name__ = } with {src_file = }'
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

def attribute_name_compare_key(attribute_name: Union[str, tuple[int, str]]) -> Tuple[int, str]:
    """
    Generate a sort key for attribute names, prioritizing public, dunder, leading double
    underscore, and private attribute names in that order.

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
    if attribute_name.startswith('__') and attribute_name.endswith('__'):  # dunder
        generated_key = 1
    elif attribute_name.startswith('__'):
        generated_key = 2
    elif attribute_name.startswith('_'): # private
        generated_key = 3
    else:
        generated_key = 0  #public
    return generated_key, attribute_name

def get_is_functions() -> Tuple[Tuple[str, Callable[[Any], bool]]]:
    """
    collect the inspect.is«something» methods

    sorted so that tags created using this will be in sorted order as well

    Returns:
        Tuple[Tuple[str, Callable[[Any], bool]]]: A tuple of tuples containing the names of
            inspect.is… functions (without the leading "is", and a reference to the function.
    """
    return tuple((name[2:], func)
                 for name, func in sorted(inspect.__dict__.items())
                 if name.startswith('is') and callable(func))

GLOBAL_IS_FUNCTIONS = get_is_functions()

def verify_is_tags(tags: Tuple[str]) -> None:
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

def wrap_test(routine: Callable, obj: Any) -> bool:
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
    return tuple(tag for tag, test in GLOBAL_IS_FUNCTIONS if wrap_test(test, obj))

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
    return SentinelTag(Tag.DATA_UNHANDLED), ApplicationFlagError('UnhandledDataType')

def public_attr_name(name: str) -> bool:
    """
    Determines if a given attribute name should be considered 'public'.

    Args:
        name (str): The attribute name to check.

    Returns:
        bool: True if the attribute is considered public, False otherwise.
    """
    if name.startswith('__') and name.endswith('__'):
        return False
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
        raise ApplicationLogicError(
            f'The routine should always be callable. Detected "{type(routine).__name__}".')

    try:
        signature = inspect.signature(routine)
    except ValueError:
        # Some callables may not support introspection of their signature
        return (None, ApplicationFlagError('NonInspectableCallable'))

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

def is_defined_within_same_package(attribute, my_object):
    """
    Check if the attribute is an instance of a class that is defined within the same
    package as my_object.

    Args:
        attribute (Any): The attribute whose origin we want to check.
        my_object (Any): The reference object used to determine the package scope.

    Returns:
        bool: True if attribute is defined within the same package as my_object, False otherwise.
    """
    attribute_module = getattr(type(attribute), '__module__', None)
    my_object_module = getattr(type(my_object), '__module__', None)
    return attribute_module == my_object_module

    # print(f'{dir(my_object) = }')
    # print(f'{type(my_object) = } {my_object.__file__ = }')
    # print(f'{my_object.__path__ = }')
    # print(f'{my_object.__package__ = } {my_object.__name__ = }')
    # print(f"<class '{my_object.__package__}.\n")
    # raise ValueError('stop and debug')

def details_without_tags(my_object: Any, attr_name: str, attribute: Any) -> tuple:
    """
    Collect details when an attribute does not match any of the inspect "is" functions

    Args:
        my_object (Any): The object whose attribute is being inspected.
        attr_name (str): The name of the attribute.
        attribute (Any): The attribute being inspected.

    Returns:
        Tuple: A tuple containing attribute profile details
    """
    # module_class_instance_prefix = f"<class '{my_object.__package__ = }."
    module_class_instance_prefix = f"<class '{my_object.__name__}."
    # print(f'"{attr_name}" {type(attribute) = }, prfx: {module_class_instance_prefix}\n' +
    #         f' {str(type(attribute)).startswith(module_class_instance_prefix) = }')
    # if is_defined_within_same_package(attribute, my_object):
    if str(type(attribute)).startswith(module_class_instance_prefix):
        return ProfileConstant.PKG_CLS_INST, SentinelTag(Tag.OTHER_EXPAND)
    if my_object.__name__ not in getattr(attribute, '__module__', my_object.__name__):
        # and not in my_object.__all__
        assert not hasattr(my_object, '__all__') or attr_name not in my_object.__all__, \
            f'{attr_name}¦{getattr(attribute, "__module__")}¦' + \
            f"{(ProfileConstant.EXTERN_MODULE, SentinelTag(Tag.SYS_EXCLUDE))}"
        return ProfileConstant.EXTERN_MODULE, SentinelTag(Tag.SYS_EXCLUDE), \
            get_module_info(attribute)
    return get_value_information(attribute)

def get_module_info(attribute: types.ModuleType) -> Tuple[str]:
    """
    get extra information for a module attribute

    Args:
        attribute (types.ModuleType): The (maybe) module to get information about
    """
    return InspectIs.MODULE, getattr(attribute, '__package__', '«pkg»'), \
        getattr(attribute, '__path__', '«pth»')

def namedtuple_fields(attribute: type) -> Tuple[str, Tuple[str]]:
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

def _key_value_info(context: ObjectContextData, attr_name: str) -> Tuple[str, AttributeProfile]:
    """
    Calculate the profile for an element of a dict or mappingproxy object

    Args:
        context (ObjectContextData): The context (with object) whose attribute is being inspected.
        attr_name (str): The name of the attribute.

    Returns:
        Tuple[str, AttributeProfile]: A tuple containing the name of the attribute, plus information
            collected about it, or a tuple containing error information if an error occurred.
    """
    assert context.mode == 'key_value', \
        f'only handle key_value context attributes: {context.mode = }'
    assert isinstance(context.element, (dict, types.MappingProxyType)), \
        f'cannot process {type(context.element).__name__} in a key_value context'
    assert isinstance(attr_name, tuple) and len(attr_name) == 2, \
        f'attribute name for key_value needs to be (index, key): {attr_name}'
    attribute = context.element[attr_name[1]]
    details = []
    if isinstance(attribute, types.FunctionType):
        details.append(get_annotation_info(  # __dict__ includes methods
            context.typehints.get(attr_name, inspect.Parameter.empty), Tag.NO_ATTRIBUTE_ANNOTATION))
    else:
        details.append(SentinelTag(Tag.NO_DATA_ANNOTATION))
    details.append(type(attribute).__name__)
    details.append((SentinelTag(Tag.NO_SOURCE), None))  # no source info for data
    details.append(())  # no "is" tags for data
    details.append(get_value_information(attribute))
    return attr_name, tuple(details)

# def _get_attribute_basic_info(context: ObjectContextData, attr_name: str) -> Tuple[
#         StrOrTag, str, Tuple[StrOrTag, types.ModuleType], Tuple[str, ...]]:
#     """
#     Collect basic information about an attribute that does not require much in the way of
#     conditional logic.

#     Args:
#         context (ObjectContextData): The context (with object) whose attribute is being inspected.
#         attr_name (str): The name of the attribute.

#     Returns: A tuple containing information collected about an attribute.
#         Tuple[StrOrTag, str, Tuple[StrOrTag, types.ModuleType], Tuple[str, ...]]
#         - The first 4 fields of AttributeProfile
#     """

def get_attribute_info(context: ObjectContextData, attr_name: str) -> Tuple[str, AttributeProfile]:
    """
    Calculate the profile for an attribute of an object, handling errors gracefully.

    Args:
        context (ObjectContextData): The context (with object) whose attribute is being inspected.
        attr_name (str): The name of the attribute.

    Returns:
        Tuple[str, AttributeProfile]: A tuple containing the name of the attribute, plus information
            collected about it, or a tuple containing error information if an error occurred.
    """
    # _get_attribute_basic_info(context, attr_name)
    if context.mode == 'key_value':
        return _key_value_info(context, attr_name)
    if context.mode != 'generic':
        raise ValueError(f'Unhandled {context.mode = }')
    attr_annotation = get_annotation_info(
        context.typehints.get(attr_name, inspect.Parameter.empty), Tag.NO_ATTRIBUTE_ANNOTATION)
    try:
        attribute = getattr(context.element, attr_name)
    except AttributeError:
        logging.info('Attribute "%s" does not exist on the provided object.', attr_name)
        return (attr_name, attr_annotation, SentinelTag(Tag.NOT_AN_ATTRIBUTE))
    except Exception as e:  # pylint:disable=broad-exception-caught
        logging.error('Unexpected error accessing "%s": %s', attr_name, e)
        return (attr_name, attr_annotation, ApplicationFlagError(type(e).__name__))
    # Collect common information with a bunch of different endings depending on context
    details = []
    details.append(attr_annotation)
    attr_tags = get_tag_set(attribute)
    details.append(type(attribute).__name__)
    details.append(get_attribute_source(attribute))
    details.append(attr_tags)
    recognized = False
    if not attr_tags:
        recognized = True
        details.append(details_without_tags(context.element, attr_name, attribute))
    else:
        verify_is_tags(attr_tags)
        if InspectIs.BUILTIN in attr_tags:
            recognized = True
            details.append((InspectIs.BUILTIN, SentinelTag(Tag.BUILTIN_EXCLUDE)))
        elif InspectIs.ROUTINE in attr_tags:
            recognized = True
            details.append((InspectIs.ROUTINE, get_signature(attribute)))
        elif InspectIs.MODULE in attr_tags:
            recognized = True
            if getattr(attribute, '__package__') in ('', attr_name):
                details.append((InspectIs.MODULE, SentinelTag(Tag.BUILTIN_EXCLUDE),
                                get_module_info(attribute)))
            else:
                details.append((InspectIs.MODULE, SentinelTag(Tag.OTHER_EXPAND)))
            # raise ValueError(f'{attr_name = }, module: {details = }')
        elif InspectIs.CLASS in attr_tags:
            recognized = True
            if attr_name == '__class__':
                details.append((ProfileConstant.DUNDER, SentinelTag(Tag.SELF_NO_EXPAND)))
            else:
                if isinstance(attribute, type) and issubclass(attribute, tuple) and \
                        hasattr(attribute, '_fields'):
                    details.append(namedtuple_fields(attribute))
                else:
                    details.append((ProfileConstant.A_CLASS, SentinelTag(Tag.OTHER_EXPAND)))
        elif InspectIs.DATADESCRIPTOR in attr_tags or InspectIs.GETSETDESCRIPTOR in attr_tags:
            recognized = True
            details.append((InspectIs.DATADESCRIPTOR, SentinelTag(Tag.OTHER_EXPAND)))
    if not recognized:
        raise ValueError(f'{attr_tags = } not handled by current logic')
        # details.append((ProfileConstant.SOMETHING_ELSE, '«need a processing category»'))
    return (attr_name, tuple(details))

# pylint:disable=line-too-long
# cSpell:words dunder, inspectable, levelname, typehints, getsourcefile, adafruit
# cSpell:words asyncgen, asyncgenfunction, coroutinefunction, datadescriptor, generatorfunction, getsetdescriptor, memberdescriptor, methoddescriptor, methodwrapper
# cSpell:ignore prfx getset
# cSpell:allowCompoundWords true
