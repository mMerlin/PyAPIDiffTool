# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
Generic tools useful for applications
"""

from types import ModuleType
from typing import Hashable, NoReturn, Tuple, Any, List
from dataclasses import dataclass
from threading import Lock
import inspect
import logging
import importlib

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
        return True

    def log_also_to_me(self, logger: logging.Logger) -> bool:
        """
        add the list handler instance to a Logger

        Args:
            logger (logging.Logger) a Logger instance to fully redirect to this ListHandler

        Returns (bool) True if this ListHandler was added to the Logger instance, False if
            it was already there.
        """
        for existing_handler in logger._handlers:  # pylint:disable=protected-access
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
        while logger._handlers:
            logger.removeHandler(logger._handlers[0])
        logger.addHandler(self)

    def to_tuple(self) -> Tuple[Tuple[str, str, int, str, tuple]]:
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

@dataclass(frozen=True)
class ExampleTags:
    """
    An example set of tags that could be used for SentinelTag creation.

    In any but the simplest usage cases, using a consistent naming convention can be
    useful.

    In more complex cases, multiple …Tag class can help document the usage context, and
    avoid the need for complex tag values be unique and document the context.
    """
    # pylint:disable=invalid-name
    NO_VALUE_DEFINE: str = 'No value defined'
    """Useful for distinguishing between 'not specified' and None or empty. For example,
    as a default value when None could be an actual value."""
    ERROR_HANDLED: str = 'error handled'
    """Useful for letting a caller know that a problem has been handled, and it is safe to
    just continue to the next item"""
    PREFIX1_NAME: str = 'identifier for name in the context of prefix 1'

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
            logging.error('Module "%s" not found. Please check the module name '
                          'and ensure it is installed.', module_name)
        else:
            logging.error('Required dependency "%s" was not found while importing "%s". '
                          'Please install it and retry.', e.name, module_name)
        raise
    except ImportError as e:
        logging.error('Error importing module "%s": %s\n Please correct the '
                      'problem then retry.', module_name, e)
        raise
    except AttributeError as e:
        if e.name == 'startswith':
            logging.error('The module name "%s" is not a string. Please provide '
                          'a valid string for the module name.', module_name)
        else:
            logging.error('Attribute error while importing module "%s": %s', module_name, e)
        raise
    except Exception as e:
        logging.error('Unexpected error (%s) during module "%s" import: %s',
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
        len(name) > 0 and
        (not name[0].isdigit()) and
        all(char.isalnum() or char == '_' for char in name) and
        not inspect.iskeyword(name)
    )

# cSpell:words levelname iskeyword
# cSpell:ignore msecs
# cSpell:allowCompoundWords true
