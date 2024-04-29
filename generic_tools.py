# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
Generic tools useful for applications
"""

import argparse
from collections.abc import Mapping
import configparser
from dataclasses import dataclass
import importlib
import inspect
import logging
import os
from pathlib import Path
import platform
import random
import sys
import string
from threading import Lock
from types import ModuleType
from typing import (
    Callable, Hashable, NoReturn, Optional, Iterable, TextIO, Tuple, TypedDict, TypeVar, Union,
    cast,
    Any, Dict, FrozenSet, List, Set,
)
try:
    from logging import _ArgsType  # pylint:disable=no-name-in-module
    # pylance sees type in IDE, but import fails at runtime
except ImportError:
    # Create a custom type alias based on the internal _ArgsType from logging module
    _ArgsType = Mapping[Any, Any]
# _ArgsType = Tuple[Any, ...]
# _ArgsType = Union[Tuple[Any], Tuple[Any, Any], Tuple[Any, Any, Any], Tuple[Any, Any, Any, Any]]

class IniSetting(TypedDict):
    """valid settings entries"""
    doc: str
    default: str
    comment: Optional[str]
class IniSection(TypedDict):
    """valid section entries"""
    description: str
    settings: Dict[str, IniSetting]
IniStructureType = Dict[str, IniSection]
T = TypeVar('T')
ReadOnlySet = Union[Set[T], FrozenSet[T]]
"""A set that is to be used (read) but not modified"""

class LoggerMixin:
    """
    Provides an interface to allow applications to override the logger instance used
    by code in the module

    Usage:
        For any (other) module:
            from generic_tools import LoggerMixin
            module_logger: logging.Logger = LoggerMixin.get_logger()
            module_logger.warning('message content')
        For application:
            import logging
            from generic_tools import LoggerMixin
            app_logger = logging.getLogger("my_application")
            LoggerMixin.set_logger(app_logger)

    For best functionality, an application should create and configure a logger instance
    early in it's lifecycle, then use the mixin to adjust the 'global' logger. Any code run
    in modules that are using the mixin will us a default logger, if it is run before the
    mixin logger is set.
    """
    _logger: Optional[logging.Logger] = None

    @classmethod
    def set_logger(cls, logger: logging.Logger) -> None:
        """
        Sets the logger instance available to all code in the module

        Args:
            logger (Logger): the logger to use (going forward)
        """
        cls._logger = logger

    @classmethod
    def get_logger(cls) -> logging.Logger:
        """gets the configured or default logger instance"""
        if cls._logger is not None:
            return cls._logger
        return logging.getLogger('default')

@dataclass(frozen=True)
class IniStr:
    """
    Constant strings used for storing ini configuration in a structure that can be converted
    into an ini file format.
    """
    description: str = 'description'
    settings: str = 'settings'
    doc: str = 'doc'
    default: str = 'default'
    comment: str = 'comment'  # optional

class ListHandler(logging.Handler):
    """Save log records to a list"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """
        capture the log record

        Args:
            record (LogRecord) the standard logging.LogRecord
        """
        self.log_records.append(record)

    def log_also_to_me(self, logger: logging.Logger) -> bool:
        """
        add the list handler instance to a Logger

        Args:
            logger (logging.Logger) a Logger instance to fully redirect to this ListHandler

        Returns (bool) True if this ListHandler was added to the Logger instance, False if
            it was already there.
        """
        # in adafruit_logging, the attribute is _handlers
        for existing_handler in logger.handlers:  # pylint:disable=protected-access
            if existing_handler is self:
                return False  # already there
        logger.addHandler(self)
        return True

    def log_only_to_me(self, logger: logging.Logger) -> None:
        """
        replace all handlers of a Logger with just me

        Args:
            logger (logging.Logger) a Logger instance to fully redirect to this ListHandler
        """
        # pylint:disable=protected-access
        # in adafruit_logging, the attribute is _handlers
        while logger.handlers:
            logger.removeHandler(logger.handlers[0])
        logger.addHandler(self)

    def to_tuple(self) -> Tuple[Tuple[str, str, int, Union[str, Any],
                                      Optional[_ArgsType]], ...]:  # type: ignore
        """
        log record data, without timestamp, as a tuple that can be directly compared
        for unittest verification.

        Excluded LogRecord fields are not as comparable. They can be different between
        implementations, and even between runs.
        LogRecord itself contains different fields between implementations.
        CircuitPython uses a namedtuple instead of a class, with fields:
            name
            levelname
            levelno
            msg
            created
            args
        cPython uses a class with additional fields
            exc_info
            exc_text
            filename
            funcName
            module
            msecs
            pathname
            process
            processName
            relativeCreated
            stack_info
            thread
            threadName

        :return tuples containing name, levelname, levelno, msg, args
        :rtype Tuple[Tuple[str, str, int, str, tuple]]
        """
        if not self.log_records:
            return tuple()
        return tuple((rec.name, rec.levelname, rec.levelno, rec.msg, rec.args)
                     for rec in self.log_records)

class ReportHandler(logging.Handler):
    """Save log record messages to a list.

    Provide list like read only access to the recorded content.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._report: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        """
        Capture the log formatted record message.

        Args:
            record (logging.LogRecord): The standard logging.LogRecord.
        """
        self._report.append(record.getMessage())

    def __getitem__(self, index):
        """Enable index-based access to the content."""
        return self._report[index]

    def __len__(self):
        """Allow len() to be called on the handler."""
        return len(self._report)

    def __iter__(self):
        """Allow iteration over the content."""
        return iter(self._report)

@dataclass(frozen=True)
class ExampleTags:
    """
    An example set of tags that could be used for SentinelTag creation.

    In any but the simplest usage cases, using a consistent naming convention can be
    useful.

    In more complex cases, multiple …Tag class can help document the usage context, and
    avoid the need for complex tag values be unique and document the context.

    Note that if Context1Tag.TAG1 == Context2Tag.Tag2, then
    SentinelTag(Context1Tag.TAG1) is SentinelTag(Context2Tag.Tag2)
    That is usually not a problem, if usage of Context1Tag and Context2Tag do not overlap.
    If that is a concern, make sure the tag values are unique. That could be done by using
    a tuple instead of a string for the tag, and including a context specific element.
    """
    # pylint:disable=invalid-name
    NO_VALUE_DEFINE: str = 'No value defined'
    """Useful for distinguishing between 'not specified' and None or empty. For example,
    as a default value when None could be an actual value."""
    ERROR_HANDLED: str = 'error handled'
    """Useful for letting a caller know that a problem has been handled, and it is safe to
    just continue to the next item"""
    PREFIX1_NAME: str = 'identifier for name in the context of prefix 1'
    MORE_UNIQUE: tuple = ('maybe not unique', 'context qualifier')

class SentinelTag:
    """
    Creates and manages unique and immutable sentinel objects based on hashable tags.

    Ensures that only one instance exists for each unique hashable tag. Instances are used
    to mark or signal specific conditions or states uniquely and immutably.

    When instances are used cross module, be sure there is a common repository for the tags
    being used. Using literal value for tag creation is not recommended. A frozen dataclass
    of constant values is safer.

    See ExampleTags for an example and related ideas.

    Compare SentinelTag instances using 'is' instead of '=='. __eq__ uses 'is' anyway.

    Class Attributes:
        _sentinels: A dictionary that maps hashable tags to their respective SentinelTag instances.
    """

    _sentinels: dict[Hashable, 'SentinelTag'] = {}
    _lock = Lock()  # Class-level lock for thread-safe instance creation

    def __new__(cls, tag: Hashable) -> 'SentinelTag':
        """
        Ensure only one instance of SentinelTag for each unique tag exists.

        Args:
            tag: A hashable object used as the unique identifier for the sentinel.

        Returns:
            The unique instance of SentinelTag for the given tag.
        """
        with cls._lock:
            if tag not in cls._sentinels:
                instance = super().__new__(cls)
                cls._sentinels[tag] = instance
        return cls._sentinels[tag]

    def __init__(self, tag: Hashable):
        """
        Initialize the SentinelTag instance. This method sets the tag, bypassing __setattr__
        to maintain immutability.

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
        return self._tag  # type: ignore pylint:disable=no-member

    def __repr__(self) -> str:
        """
        Return the text representation of the SentinelTag instance.

        Returns:
            A string representation indicating it's a sentinel tag followed by the tag value.
        """
        return f"Sentinel Tag: {repr(self._tag)}"  # type: ignore pylint:disable=no-member

    def __hash__(self) -> int:
        """
        Return the hash of the tag, allowing SentinelTag instances to be used as hashable objects.

        Returns:
            The hash of the _tag attribute.
        """
        return hash(self._tag)  # type: ignore pylint:disable=no-member

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

class TriStateAction(argparse.Action):
    """Custom action to handle tri-state (None, True, False) using 2 arguments (--arg and its
    negation).  The negation will be --{negation_prefix}arg"""
    def __init__(self, option_strings, dest, negation_marker='no-', **kwargs):
        self.negation_prefix = '--' + negation_marker
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: Optional[List[str]], option_string: Optional[str] = None):
        # Set True or False based on whether the option string starts with the negation prefix.
        setattr(namespace, self.dest,
                option_string is None or not option_string.startswith(self.negation_prefix))

class RunAndExitAction(argparse.Action):
    """Custom action to execute a method and then exit the program.
    Emulates the functionality for --help

    Caller must make sure that any context needed by the external_method is setup before
    argparse is run. For example, any attributes used in it's own 'self' context must be
    properly initialized.

    Args:
        option_strings (List[str]): A list of command-line option strings which
            should be associated with this action.
        dest (str): The name of the attribute to hold the result of this action.
        external_method (Callable[..., Any]): The method to be executed when this
            action is triggered. The method does not need to accept any parameters
            and can return any type.
        **kwargs: Arbitrary keyword arguments.

    Attributes:
        external_method (Callable[..., Any]): Stores the method to execute.
    """
    def __init__(self, option_strings: List[str], dest: str,
                 external_method: Optional[Callable[..., Any]] = None, **kwargs):
        super().__init__(option_strings, dest, **kwargs)
        self.external_method = external_method

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: Optional[List[str]], option_string: Optional[str] = None) -> NoReturn:
        if self.external_method:
            try:
                self.external_method()
            except Exception as e:  # pylint:disable=broad-exception-caught
                parser.error(f'Error executing {self.external_method.__name__}: {e}')
        sys.exit()

def process_keyword_settings(value: str, valid_values: ReadOnlySet[str], *,  # pylint:disable=too-many-arguments
                             remove_prefix: str = 'no-',
                             file_path: Optional[Path] = None,
                             source_entry: Optional[str] = None,
                             raise_exception: bool = False) -> Dict[str, bool]:
    """
    Processes a comma-separated list of keywords, maintaining order and allowing for negations.
    Later entries can reverse the effect of previous ones.

    Example:
        allowed = frozenset('alpha', 'beta', 'delta', 'gamma')
        process_keyword_settings('alpha, nogamma, beta, noalpha', allowed, remove_prefix='no')
        gives
        {'alpha': False, 'gamma': False, 'beta': True}

        'all' is a special, always valid, keyword.
        process_keyword_settings('all', allowed, remove_prefix='no')
        gives
        {'alpha': True, 'beta': True, 'delta': True, 'gamma': True}

    Args:
        value (str): The comma-separated string of keywords from the configuration.
        valid_values (Set[str]): A set of valid keywords without 'all' or their negated versions.
        remove_prefix (str): Prefix indicating negation of a keyword.

    Returns:
        Dict[str, bool]: A dictionary where keys are the valid keywords and values are boolean
                         indicating their enabled (True) or negated (False) status.

    Raises
        ValueError when an invalid keyword list is detected and the raise_exception flag
            is set to True.
    """
    result = {}
    error_detected = False
    if not value:
        return result  # short cut when no keywords: prevents error treating empty string as choice
    if value == 'all':
        return {key: True for key in valid_values}
    for choice in map(str.strip, value.split(',')):
        key = choice[len(remove_prefix):] if choice.startswith(remove_prefix) else choice
        if key in valid_values:
            result[key] = key == choice  # True when choice is a valid keyword, False when negated.
        else:
            error_detected = True
            if file_path and source_entry:
                LoggerMixin.get_logger().warning(
                    'Invalid %s keyword "%s" found in "%s". Valid keywords: %s',
                    source_entry, choice, file_path, ', '.join(valid_values))
            else:
                LoggerMixin.get_logger().warning(
                    '"%s" not in valid keywords: %s', choice, ', '.join(valid_values))
    if error_detected and raise_exception:
        raise ValueError('Invalid keyword set')
    return result

def update_set_keywords_from_dict(target: set[str], keywords: Dict[str, bool]) -> None:
    """
    update keyword parameters in an existing set from a dictionary of keywords with
    boolean values

    keys for dictionary entries with a True value are added to the set. A false value
    is removed.

    Args:
        target (set): the existing keyword set to update
        keywords (Dict[str, bool]): dictionary with keywords to and and remove
    """
    for key, state in keywords.items():
        if state:
            target.add(key)
        else:
            try:
                target.remove(key)
            except KeyError:
                # Ignore if the key to remove doesn't existing in the target set
                pass

def update_set_keywords_from_string(target: set[str], keywords: str, valid: FrozenSet[str],
                                    **kwargs) -> None:
    """
    update keyword parameters in an existing set from a comma-separated list
    of [negated] keywords in a string.

    keywords are added to the set, negated keywords are removed. Processed in the order that
    they are in the string, so latter entries can override earlier, and any keywords will
    override entires already in the target set.

    base: set = {'a', 'b', 'c'}
    allowed: FrozenSet = frozenset({'a', 'b', 'c', 'd', 'e'})
    update_set_keywords(base, 'd,nob,e,nod', allowed)
    base == {'a', 'c', 'e'}

    'all' can also be used, so with
    update_set_keywords(base, 'all', allowed)
    base == {'a', 'b', 'c', 'd', 'e'}

    Args:
        target (set): the existing keyword set to update
        keywords (str): comma-separated list of context keywords (possibly negated)
        valid (Frozenset): the valid context keywords, without 'all' or negated version
        kwargs: pass any arguments through to process_keyword_settings.
    """
    states: Dict[str, bool] = process_keyword_settings(keywords, valid, **kwargs)
    update_set_keywords_from_dict(target, states)

def validate_attribute_names(value: str, *, raise_exception: bool = False) -> Set[str]:
    """
    Creates a set of valid attribute name strings from a comma-separated list of attribute names.

    Invalid attribute names are logged, and conditionally raise an exception

    Args:
        value (str): The comma-separated string of attribute names from the configuration.

    Returns:
        Set[str]: A set of validated attribute names.

    Raises
        ValueError when an invalid attribute name is detected and the raise_exception flag
            is set to True.
    """
    entries = set(map(str.strip, value.split(',')))
    result = {ent for ent in entries if is_attr_name(ent)}
    not_attributes = entries - result
    if not_attributes:
        LoggerMixin.get_logger().warning('%s invalid attribute names ignored: {%s}',
            len(not_attributes), trim_excess(", ".join(not_attributes), 50))
        if raise_exception:
            raise ValueError(f'{len(not_attributes)} invalid attribute names: ' +
                             f'"{trim_excess(", ".join(not_attributes), 50)}"')

    return result

def validate_module_path(value: str) -> str:
    """
    Validates the input string to ensure it is a correctly formatted module path.

    Args:
        value (str): The input string representing a module path.

    Returns:
        str: The validated module path if it is correctly formatted.

    Raises:
        ValueError: If the module path is not correctly formatted.
    """
    if not all(part.isidentifier() for part in value.split(".")):
        raise ValueError("Module path must consist of valid Python identifiers separated by dots.")

    return value

def trim_excess(content: str, max_length: int=100) -> str:
    """
    limit content to specified maximum length

    Args:
        content (str): string to limit to maximum length (in characters)
        max_length (int): The maximum allowed width

    Return
        (str) content trimmed to a maximum of the specified length. If truncated, ellipse character
        appended, still keeping total output to the maximum length.
    """
    return content[:max_length - 1] + '…' if len(content) > max_length else content
    # return content[:max_length - 3] + '...' if len(content) > max_length else content

def add_tri_state_argument(parser: argparse.ArgumentParser, argument_name: str,
                           help_text: str, negation: str = 'no-') -> None:
    """
    Setup a tri-state (True, False, None) argument with customizable negation prefix.
    The negated argument's help text is suppressed to avoid it appearing in the help output.

    Args:
        parser: The argument parser to which the tri-state argument is being added.
        argument_name: The name of the argument (e.g., '--test-argument').
        help_text: The help text for the argument.
        negation: The prefix used for negation (default is 'no-', resulting in
                  '--no-test-argument').
    """
    arg_name = argument_name.lstrip('--')
    dest_name = arg_name.replace('-', '_')
    negated_arg_name = f'--{negation}{arg_name}'
    if help_text:
        help_text += f' (negate with {negated_arg_name})'

    # Add the primary argument with the custom action and help text.
    parser.add_argument(argument_name, dest=dest_name, action=TriStateAction,
                        negation_marker=negation, nargs=0, help=help_text)

    # Add the negated version of the argument without help text to avoid it appearing
    # in the help output.
    parser.add_argument(negated_arg_name, dest=dest_name, action=TriStateAction,
                        negation_marker=negation, nargs=0, help=argparse.SUPPRESS)

def make_all_or_keys_validator(choices: Iterable[str], *, negation: str = 'no-') -> \
        Callable[[str], Dict[str, bool]]:
    """
    Creates a factory function to validate a command-line argument that accepts either 'all',
    or a comma-separated list of keywords, which can individually be negated.

    The function generated by this factory maintains the order of keywords as specified by the
    user, handling repetitions and negations (removals) accordingly.

    Args:
        choices (Iterable[str]): Valid keywords excluding 'all' and their negated versions.
        negation (str): The prefix indicating negation of a keyword. Defaults to 'no-'.

    Returns:
        A validator function that parses the command-line argument value into a dictionary mapping
        from each mentioned keyword to a boolean indicating its negated state (True if not negated,
        False if negated).
    """
    valid_choices = set(choices)

    def all_or_keys_validator(s: str) -> Dict[str, bool]:
        """
        Validates the input string against the allowed choices, maintaining order and handling
        negations.

        Args:
            s (str): The input string from the command line.

        Returns:
            Dict[str, bool]: A dictionary where each key is a valid choice and its value indicates
                             whether it was negated (False if negated, True otherwise).

        Raises
            ValueError for unrecognized or invalid combinations of keywords
        NOTE:
            argparse traps the raised exceptions, and creates it's own generic message, ignoring
            the more detailed information that could be provided here.
        """
        return process_keyword_settings(s, valid_choices, raise_exception=True,
                                        remove_prefix=negation)

    return all_or_keys_validator

def attribute_names_validator(s: str) -> Set[str]:
    """
    Validates the input string against valid attribute names.

    Args:
        s (str): The input string from the command line.

    Returns:
        Set[str]: Unique attribute names.

    Raises
        ValueError if an invalid attribute name is detected.
    NOTE:
        argparse traps the raised exception, and creates it's own generic message, ignoring
        the more detailed information that could be provided here.
    """
    return validate_attribute_names(s, raise_exception=True)

def import_module(module_name: str) -> ModuleType:
    """
    Dynamically import a module based on its textual path.

    Args:
        module_name (str): The textual path of the module to be imported.

    Returns:
        ModuleType: The imported module.

    Raises:
        ModuleNotFoundError: If the specified module name, or a dependency for is, cannot be found.
        ImportError: If the module cannot be loaded for another reason.
        AttributeError: For attribute-related errors, such as incorrect module name types.
        Exception: For any unexpected errors during the import process.
    """
    try:
        module = importlib.import_module(module_name)
        return module
    except ModuleNotFoundError as e:
        if e.name == module_name:
            LoggerMixin.get_logger().error('Module "%s" not found. Please check the module name '
                          'and ensure it is installed.', module_name)
        else:
            LoggerMixin.get_logger().error('Required dependency "%s" was not found while importing '
                          '"%s". Please install it and retry.', e.name, module_name)
        raise
    except ImportError as e:
        LoggerMixin.get_logger().error('Error importing module "%s": %s\n Please correct the '
                      'problem then retry.', module_name, e)
        raise
    except AttributeError as e:
        if e.name == 'startswith':
            LoggerMixin.get_logger().error('The module name "%s" is not a string. Please provide '
                          'a valid string for the module name.', module_name)
        else:
            LoggerMixin.get_logger().error(
                'Attribute error while importing module "%s": %s', module_name, e)
        raise
    except Exception as e:
        LoggerMixin.get_logger().error('Unexpected error (%s) during module "%s" import: %s',
                      type(e).__name__, module_name, e)
        raise

def tuple_2_generator(src: tuple):
    """
    Create a generator to allow stepping through a tuple using next()

    Args:
        src (tuple): the tuple to create the generator for

    Usage:
        iter_name = tuple_2_generator(tuple_variable)
        element = next(iter_name, end_marker_value)  # until end_marker_value detected
    """
    yield from src

def is_attr_name(name: str) -> bool:
    """
    Check if a given name is a valid Python attribute name.

    Args:
        name: the string to check

    Returns True if the name is valid to use as a python attribute name, False otherwise
    """
    return (
        isinstance(name, str) and
        name.isidentifier() and
        not inspect.iskeyword(name)  # type: ignore
    )

def generate_random_alphanumeric(length: int = 10) -> str:
    """Generate a random string of alphanumeric characters."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def get_config_path(app_name: str) -> Path:
    """Determine the configuration path for the application based on the operating system.

    Args:
        app_name (str): The name of the application.

    Returns:
        Path: The path to the configuration directory for the application.
    """
    home = Path.home()

    if platform.system() == 'Windows':
        config_path = Path(os.getenv('APPDATA', '')) / app_name
    elif platform.system() == 'Darwin':
        config_path = home / 'Library' / 'Application Support' / app_name
    else:
        # Default to Linux/Unix path
        config_path = home / '.config' / app_name

    return config_path

def get_config_file(config_file: Path) -> Optional[configparser.ConfigParser]:
    """
    loads a configuration file into a new ConfigParser instance

    Args:
        config_file (Path): the path to the configuration file

    Returns
        ConfigParser instance populated with the configuration file content, or None
        None is return when the specified file does not exist, or cannot be read for
        various reasons.
    """
    config = configparser.ConfigParser()

    if not config_file.is_file():
        # config.read() silently ignores missing files. Explicit test needed to report.
        LoggerMixin.get_logger().warning('Configuration file "%s" not found', config_file)
        return None

    try:
        config.read(config_file)
        return config
    except PermissionError:
        LoggerMixin.get_logger().error(
            'Unable to read "%s" due to insufficient permissions.', config_file)
    except (configparser.ParsingError, configparser.Error) as e:
        LoggerMixin.get_logger().error('Error reading "%s": %s', config_file, e)
    except Exception as e:  # pylint:disable=broad-exception-caught
        LoggerMixin.get_logger().error('Unexpected error reading "%s": %s', config_file, e)

    return None

def insert_prefix(input_string: str, prefix: str = '; ') -> str:
    '''
    add prefix at the start of every line in a multiple line string, except for
    blank lines.

    Args:
        input_str (str) the (possibly) multiple line string
        prefix (str) the prefix to add to the start of every non empty line

    Returns
        (str) input_string with added prefix to all non-empty lines
    '''
    lines = input_string.split('\n')
    new_lines = []

    for line in lines:
        line = line.strip()  # Remove leading/trailing whitespace
        # Skip adding prefix to empty lines and preserve double newlines
        new_lines.append(line if line == '' else prefix + line)

    return '\n'.join(new_lines)

def generate_ini_file(output: TextIO, structure: IniStructureType):
    """
    Generates an INI file structure and writes it to a file or stdout.

    Example usage
        structure_test = {
            "Section1": {
                "description": "This is section 1",
                "settings": {
                    "setting1": {"doc": "Documentation for setting 1", "default": "value1"},
                    "setting2": {
                        "doc": "Documentation for setting 2",
                        "default": "value2",
                        "comment": "optional comment",
                    },
                },
            },
            "Section2": {
                "description": "This is section 2",
                "settings": {
                    "settingA": {"doc": "Documentation for setting A", "default": "valueA"},
                    "settingB": {"doc": "Documentation for setting B", "default": "valueB"},
                },
            },
        }
        IniStr attributes can be used in placed of literal strings for the structure keys
                IniStr.description: "This is section 1",
                IniStr.settings: { …
        generate_ini_file(sys.stdout, structure_test)
        ; This is section 1
        [Section1]
        ; Documentation for setting 1
        ; setting1 = value1

        ; Documentation for setting 2
        ; setting2 = value2 ; optional comment


        ; This is section 2
        [Section2]
        ; Documentation for setting A
        ; settingA = valueA

        ; Documentation for setting B
        ; settingB = valueB

    Args:
        output (TextIO): A file-like object where the INI content will be written.
        structure (Dict): A dictionary defining the INI file structure.
    """
    c_pfx = '; '
    for section, content in structure.items():
        # use insert_prefix to add comment prefix to all comment context, to handle all cases
        # where the comment text includes newline characters.

        # Write section description as a comment
        output.write(f"{insert_prefix(content['description'], c_pfx)}\n")
        output.write(f"[{section}]\n")
        for setting, info in content['settings'].items():
            # Write each setting's documentation and default value (commented out)
            output.write(f"{insert_prefix(info['doc'], c_pfx)}\n")
            optional_comment = insert_prefix(cast(str, info.get('comment', '')), f' {c_pfx}')
            output.write(f"; {setting} = {info['default']}{optional_comment}\n\n")

        # Extra newline for readability between sections
        output.write("\n")

# Alternatively, writing to stderr
# generate_ini_file(sys.stderr, structure)

# cSpell:words levelname iskeyword expanduser pathlib issubset configparser adafruit
# cSpell:ignore msecs nargs appdata noalpha, nogamma
# cSpell:allowCompoundWords true
